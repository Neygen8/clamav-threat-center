#!/usr/bin/env python3
"""Private VirusTotal download watcher with queueing, policy, and quarantine."""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import plistlib
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from contextlib import contextmanager
from queue import Queue
from datetime import datetime, timezone
from pathlib import Path

API = "https://www.virustotal.com/api/v3"
MAX_PUBLIC_UPLOAD = 32 * 1024 * 1024
MAX_RESULTS_LOG_BYTES = 5 * 1024 * 1024
MAX_RESULTS_LOG_LINES = 2_000
MAX_DEFERRED_RETRY_AGE_SECONDS = 24 * 60 * 60
MAX_DEFERRED_RETRY_DELAY_SECONDS = 15 * 60
LEGACY_APP_DIR = Path.home() / ".local/share/vt-download-watcher"
CONFIG_FILE = Path.home() / ".config/vt-download-watcher/config.json"
ENV_FILE = Path.home() / ".config/vt-download-watcher/.env"
CLAMAV_DIR = Path.home() / "Library/Application Support/ClamAV-Automation"
LOG_DIR = Path.home() / "Library/Logs/ClamAV-Automation"
QUARANTINE_DIR = CLAMAV_DIR / "Quarantine"
COORDINATION_DIR = CLAMAV_DIR / "coordination"
QUARANTINE_LOCK_FILE = COORDINATION_DIR / "quarantine.lock"
STATUS_FILE = CLAMAV_DIR / "virustotal-status.json"
RESULTS_FILE = LOG_DIR / "virustotal-results.jsonl"
PENDING_FILE = CLAMAV_DIR / "virustotal-pending-analyses.json"
PENDING_LOCK_FILE = COORDINATION_DIR / "virustotal-pending.lock"
DEFERRED_RETRIES_FILE = CLAMAV_DIR / "virustotal-deferred-retries.json"
DEFERRED_RETRIES_LOCK_FILE = COORDINATION_DIR / "virustotal-deferred-retries.lock"
QUARANTINE_VT_STATE_FILE = CLAMAV_DIR / "virustotal-quarantine-state.json"
QUARANTINE_VT_STATE_LOCK_FILE = COORDINATION_DIR / "virustotal-quarantine-state.lock"
UPLOAD_LEDGER_FILE = CLAMAV_DIR / "virustotal-upload-ledger.json"
UPLOAD_LEDGER_LOCK_FILE = COORDINATION_DIR / "virustotal-upload-ledger.lock"
IGNORED_SUFFIXES = {".crdownload", ".download", ".part", ".tmp"}
RISKY_SUFFIXES = {".app", ".command", ".dmg", ".exe", ".iso", ".jar", ".js", ".msi", ".pkg", ".py", ".scr", ".sh", ".vbs", ".zip", ".7z", ".rar"}
CONFIG_POLICY_VERSION = 2
DEFAULT_CONFIG = {
    "config_policy_version": CONFIG_POLICY_VERSION,
    "auto_upload_unknown": False,
    "auto_upload_quarantine": False,
    "upload_unknown_risky_only": True,
    "notify_clean": False,
    "max_uploads_per_day": 250,
    "minimum_request_gap_seconds": 15,
    "automatic_quarantine_min_malicious": 2,
    "automatic_quarantine_min_total": 3,
    "whitelist_hashes": [],
    "whitelist_names": [],
    "whitelist_suffixes": [],
}
RATE_LOCK_FILE = LEGACY_APP_DIR / "api-rate.lock"


def now() -> str: return datetime.now(timezone.utc).isoformat()


def private_directory(path: Path) -> None:
    """Create a user-owned private directory and reject link substitution."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise PermissionError(f"Güvensiz özel dizin: {path}")
    os.chmod(path, 0o700)


def atomic_json(path: Path, value: dict) -> None:
    private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(value, output, ensure_ascii=False, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def result_record(record: dict) -> dict:
    """Normalize old and new watcher events for the unified Swift dashboard."""
    timestamp = str(record.get("timestamp") or record.get("time") or now())
    path = str(record.get("path") or record.get("file") or "")
    stats = record.get("analysis_stats") if isinstance(record.get("analysis_stats"), dict) else {}
    malicious = int(record.get("malicious", stats.get("malicious", 0)) or 0)
    suspicious = int(record.get("suspicious", stats.get("suspicious", 0)) or 0)
    harmless = int(record.get("harmless", stats.get("harmless", 0)) or 0)
    undetected = int(record.get("undetected", stats.get("undetected", 0)) or 0)
    raw_status = str(record.get("status") or "")
    has_engine_results = bool(record.get("engine_results"))
    explicit_clean = raw_status in {"known-clean", "uploaded-clean", "clean"}
    if raw_status in {"tarama-başarısız", "izleyici-hatası", "error"} or raw_status.startswith("karantina-hatası"):
        status = "error"
    elif malicious > 0:
        status = "known-malicious"
    elif suspicious > 0:
        status = "known-warning"
    elif raw_status.startswith("bilinmiyor") or raw_status == "unknown":
        status = "unknown"
    elif raw_status in {"kuyrukta", "tarayıcı-kuyruğunda", "queued"}:
        status = "queued"
    elif raw_status in {"taranıyor", "scanning"}:
        status = "scanning"
    elif raw_status == "tarama-yeniden-denenecek":
        status = "retrying"
    elif stats and not has_engine_results and not explicit_clean:
        # Older versions could persist a zeroed analysis shell before VT had
        # produced any engine verdicts. It is unfinished work, never proof that
        # a file is clean.
        status = "retrying"
    elif has_engine_results or explicit_clean:
        status = "known-clean"
    else:
        status = raw_status or "unknown"
    normalized = {
        "id": str(record.get("id") or uuid.uuid4()),
        "timestamp": timestamp,
        "path": path,
        "sha256": str(record.get("sha256") or ""),
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "uploaded": bool(record.get("uploaded", False)),
        "sourceDomains": list(record.get("sourceDomains") or record.get("download_source_domains") or record.get("download_source") or []),
    }
    quarantined = record.get("quarantinedTo") or record.get("quarantined_to")
    report_url = record.get("reportURL") or record.get("url")
    error = record.get("error") or record.get("errorMessage")
    if quarantined:
        normalized["quarantinedTo"] = str(quarantined)
    if report_url:
        normalized["reportURL"] = str(report_url)
    if error:
        normalized["errorMessage"] = str(error)
    if "attempt" in record:
        normalized["attempt"] = int(record["attempt"])
    if "retryAt" in record:
        normalized["retryAt"] = str(record["retryAt"])
    if "firstQueuedAt" in record:
        normalized["firstQueuedAt"] = str(record["firstQueuedAt"])
    if "hashOnly" in record:
        normalized["hashOnly"] = bool(record["hashOnly"])
    if "forceUpload" in record:
        normalized["forceUpload"] = bool(record["forceUpload"])
    if "expectedSha256" in record:
        normalized["expectedSha256"] = str(record["expectedSha256"])
    if "browserRecord" in record or "browser_record" in record:
        normalized["browserRecord"] = str(record.get("browserRecord") or record.get("browser_record"))
    if "source" in record:
        normalized["source"] = str(record["source"])
    if "quarantineID" in record:
        normalized["quarantineID"] = str(record["quarantineID"])
    if "alreadyQuarantined" in record:
        normalized["alreadyQuarantined"] = bool(record["alreadyQuarantined"])
    return normalized


class StatusWriter:
    def __init__(self, watched_paths: list[str], api_key_configured: bool, settings: dict):
        self._lock = threading.Lock()
        self._state = {
            "running": False,
            "startedAt": now(),
            "heartbeatAt": now(),
            "watchedPaths": watched_paths,
            "checkedCount": 0,
            "uploadedCount": 0,
            "threatCount": 0,
            "quarantinedCount": 0,
            "queueDepth": 0,
            "autoUploadUnknown": bool(settings.get("auto_upload_unknown", False)),
            "autoUploadQuarantine": bool(settings.get("auto_upload_quarantine", False)),
            "apiKeyConfigured": api_key_configured,
            "lastPath": None,
            "lastResult": None,
            "lastError": None,
        }

    def update(self, **values) -> None:
        with self._lock:
            self._state.update(values)
            self._state["heartbeatAt"] = now()
            atomic_json(STATUS_FILE, self._state)

    def record(self, result: dict) -> None:
        with self._lock:
            self._state["checkedCount"] += 1
            if result.get("uploaded"):
                self._state["uploadedCount"] += 1
            if int(result.get("malicious", 0)) + int(result.get("suspicious", 0)) > 0:
                self._state["threatCount"] += 1
            if result.get("quarantinedTo"):
                self._state["quarantinedCount"] += 1
            self._state["lastPath"] = result.get("path")
            self._state["lastResult"] = result.get("status")
            self._state["lastError"] = result.get("errorMessage") if result.get("status") == "error" else None
            self._state["heartbeatAt"] = now()
            atomic_json(STATUS_FILE, self._state)


def config() -> dict:
    private_directory(CONFIG_FILE.parent)
    stored = read_private_json(CONFIG_FILE, {})
    if not isinstance(stored, dict):
        stored = {}
    value = DEFAULT_CONFIG | stored
    if stored.get("config_policy_version") != CONFIG_POLICY_VERSION:
        value["auto_upload_quarantine"] = False
        value["config_policy_version"] = CONFIG_POLICY_VERSION
        atomic_json(CONFIG_FILE, value)
    return value


def local_api_key() -> str | None:
    descriptor = -1
    try:
        private_directory(ENV_FILE.parent)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(ENV_FILE, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            return None
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = -1
            for raw in source:
                if raw.strip().startswith("VIRUSTOTAL_API_KEY="):
                    return raw.partition("=")[2].strip().strip('"').strip("'") or None
    except OSError:
        pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()


def is_allowed_virustotal_url(url: str) -> bool:
    try:
        target = urllib.parse.urlsplit(url)
        return (
            target.scheme.lower() == "https"
            and target.hostname == "www.virustotal.com"
            and target.port in (None, 443)
        )
    except ValueError:
        return False


class VirusTotalRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute_url = urllib.parse.urljoin(req.full_url, newurl)
        if not is_allowed_virustotal_url(absolute_url):
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                "VirusTotal alan dışına yönlendirme reddedildi.",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, absolute_url)


def request(url: str, key: str, *, data: bytes | None = None, headers: dict | None = None) -> dict:
    if not is_allowed_virustotal_url(url):
        raise ValueError("Yalnız VirusTotal API adreslerine istek gönderilebilir.")
    # The public API allows four requests/minute. A file lock makes automatic
    # and manual scans share one limiter even though they are separate processes.
    private_directory(RATE_LOCK_FILE.parent)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(RATE_LOCK_FILE, flags, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        os.close(descriptor)
        raise PermissionError("Güvensiz VirusTotal hız sınırı kilidi")
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "r+", encoding="utf-8") as limiter:
        fcntl.flock(limiter.fileno(), fcntl.LOCK_EX)
        limiter.seek(0)
        try: previous = float(limiter.read().strip() or "0")
        except ValueError: previous = 0
        minimum_gap = max(15.0, float(config()["minimum_request_gap_seconds"]))
        remaining = minimum_gap - (time.time() - previous)
        if remaining > 0: time.sleep(remaining)
        req = urllib.request.Request(url, data=data, headers={"x-apikey": key, **(headers or {})})
        try:
            with urllib.request.build_opener(VirusTotalRedirectHandler()).open(req, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = " ".join(error.read(512).decode("utf-8", "replace").split())[:240]
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"VirusTotal HTTP {error.code}{suffix}") from error
        finally:
            limiter.seek(0); limiter.truncate(); limiter.write(str(time.time())); limiter.flush()
            fcntl.flock(limiter.fileno(), fcntl.LOCK_UN)


def file_report(file_hash: str, key: str) -> dict | None:
    try: return request(f"{API}/files/{file_hash}", key)
    except RuntimeError as error:
        if "HTTP 404" in str(error): return None
        raise


def usable_report(report: dict | None) -> bool:
    """A VT file shell with no engine results is not a scan result."""
    if not report or report.get("data", {}).get("type") != "file": return False
    return bool(report["data"].get("attributes", {}).get("last_analysis_results"))


def verified_upload_content(
    path: Path,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_digest: str,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            int(getattr(before, "st_gen", 0)),
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if not stat.S_ISREG(before.st_mode) or before_identity != expected_identity:
            raise SourceChangedError("Dosya yükleme anında değişti.")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            chunks.append(block)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            int(getattr(after, "st_gen", 0)),
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if after_identity != before_identity or digest.hexdigest() != expected_digest:
            raise SourceChangedError("Dosya yükleme için okunurken değişti.")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def upload_content(filename: str, content: bytes, key: str) -> str:
    boundary = "----VTWatcherBoundary"
    safe_name = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode() + content + f"\r\n--{boundary}--\r\n".encode())
    return request(f"{API}/files", key, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})["data"]["id"]


def analysis_report(analysis_id: str, key: str) -> dict:
    # Each API request already observes the public 15-second rate limit. Fifteen
    # polls keep the full wait near five minutes instead of accidentally taking
    # twenty minutes.
    for _ in range(15):
        report = request(f"{API}/analyses/{analysis_id}", key)
        if report["data"]["attributes"]["status"] == "completed": return report
        time.sleep(5)
    raise RuntimeError("VirusTotal analizi 5 dakika içinde tamamlanmadı.")


def log(path: Path, record: dict) -> None:
    private_directory(path.parent)
    normalized = result_record(record)
    payload = (json.dumps(normalized, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise PermissionError(f"Güvensiz VirusTotal günlük dosyası: {path}")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        end = os.lseek(descriptor, 0, os.SEEK_END)
        if end > MAX_RESULTS_LOG_BYTES:
            os.lseek(descriptor, 0, os.SEEK_SET)
            existing = bytearray()
            while len(existing) < end:
                block = os.read(descriptor, min(1024 * 1024, end - len(existing)))
                if not block:
                    break
                existing.extend(block)
            complete_lines = bytes(existing).splitlines()[-MAX_RESULTS_LOG_LINES:]
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if complete_lines:
                retained = b"\n".join(complete_lines) + b"\n"
                offset = 0
                while offset < len(retained):
                    offset += os.write(descriptor, retained[offset:])
            end = os.lseek(descriptor, 0, os.SEEK_END)
        if end > 0:
            os.lseek(descriptor, -1, os.SEEK_END)
            if os.read(descriptor, 1) != b"\n":
                os.write(descriptor, b"\n")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            remaining = remaining[written:]
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def record_and_log(path: Path, record: dict) -> dict:
    normalized = result_record(record)
    log(path, normalized)
    return normalized


def file_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise FileNotFoundError(f"Düzenli dosya değil: {path}")
    return (
        info.st_dev,
        info.st_ino,
        int(getattr(info, "st_gen", 0)),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@contextmanager
def exclusive_lock(directory: Path, lock_file: Path):
    private_directory(directory)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_file, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise PermissionError("Güvensiz karantina kilidi")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def quarantine_lock():
    with exclusive_lock(COORDINATION_DIR, QUARANTINE_LOCK_FILE):
        yield


def read_private_json(path: Path, fallback):
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return fallback
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise PermissionError(f"Güvensiz özel JSON dosyası: {path}")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = -1
            try:
                return json.load(source)
            except json.JSONDecodeError:
                return fallback
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def pending_entry(digest: str) -> dict | None:
    with exclusive_lock(COORDINATION_DIR, PENDING_LOCK_FILE):
        entries = read_private_json(PENDING_FILE, {})
        value = entries.get(digest) if isinstance(entries, dict) else None
        return value if isinstance(value, dict) else None


def claim_upload(
    digest: str,
    path: Path,
    *,
    hash_only: bool,
    source: str = "download",
    quarantine_id: str | None = None,
) -> tuple[str, str | None]:
    """Atomically claim an upload or return a resumable analysis."""
    with exclusive_lock(COORDINATION_DIR, PENDING_LOCK_FILE):
        entries = read_private_json(PENDING_FILE, {})
        if not isinstance(entries, dict):
            entries = {}
        existing = entries.get(digest)
        if isinstance(existing, dict):
            changed = False
            if not existing.get("path"):
                existing["path"] = str(path)
                changed = True
            if "hashOnly" not in existing:
                existing["hashOnly"] = bool(hash_only)
                changed = True
            if "source" not in existing:
                existing["source"] = source
                changed = True
            if quarantine_id and "quarantineID" not in existing:
                existing["quarantineID"] = quarantine_id
                changed = True
            if changed:
                entries[digest] = existing
                atomic_json(PENDING_FILE, entries)
            analysis_id = existing.get("analysisID")
            if analysis_id:
                return "resume", str(analysis_id)
            try:
                created = datetime.fromisoformat(str(existing.get("createdAt")))
                age = (datetime.now(timezone.utc) - created).total_seconds()
            except (TypeError, ValueError):
                age = 601
            if age < 600:
                return "wait", None
        entries[digest] = {
            "state": "uploading",
            "createdAt": now(),
            "path": str(path),
            "hashOnly": bool(hash_only),
            "source": source,
            **({"quarantineID": quarantine_id} if quarantine_id else {}),
        }
        atomic_json(PENDING_FILE, entries)
        return "upload", None


def save_pending_analysis(
    digest: str,
    analysis_id: str,
    path: Path,
    *,
    hash_only: bool,
    source: str = "download",
    quarantine_id: str | None = None,
) -> None:
    with exclusive_lock(COORDINATION_DIR, PENDING_LOCK_FILE):
        entries = read_private_json(PENDING_FILE, {})
        if not isinstance(entries, dict):
            entries = {}
        entries[digest] = {
            "state": "analyzing",
            "analysisID": analysis_id,
            "createdAt": now(),
            "path": str(path),
            "hashOnly": bool(hash_only),
            "source": source,
            **({"quarantineID": quarantine_id} if quarantine_id else {}),
        }
        atomic_json(PENDING_FILE, entries)


def pending_analysis_jobs() -> dict[str, dict]:
    with exclusive_lock(COORDINATION_DIR, PENDING_LOCK_FILE):
        entries = read_private_json(PENDING_FILE, {})
        if not isinstance(entries, dict):
            return {}
        return {
            str(digest): value
            for digest, value in entries.items()
            if isinstance(digest, str)
            and len(digest) == 64
            and isinstance(value, dict)
            and bool(value.get("analysisID"))
            and bool(value.get("path"))
        }


def clear_pending_analysis(digest: str) -> None:
    with exclusive_lock(COORDINATION_DIR, PENDING_LOCK_FILE):
        entries = read_private_json(PENDING_FILE, {})
        if not isinstance(entries, dict) or digest not in entries:
            return
        entries.pop(digest, None)
        atomic_json(PENDING_FILE, entries)


def deferred_retries() -> dict[str, dict]:
    """Return a private snapshot of retries that must survive app/Mac restarts."""
    with exclusive_lock(COORDINATION_DIR, DEFERRED_RETRIES_LOCK_FILE):
        entries = read_private_json(DEFERRED_RETRIES_FILE, {})
        if not isinstance(entries, dict):
            return {}
        return {
            str(path): value
            for path, value in entries.items()
            if isinstance(path, str) and isinstance(value, dict)
        }


def save_deferred_retry(
    path: Path,
    *,
    attempt: int,
    hash_only: bool,
    first_queued_at: str,
    retry_at: str,
    error: str,
    expected_sha256: str | None = None,
    force_upload: bool = False,
    source: str = "download",
    quarantine_id: str | None = None,
) -> None:
    with exclusive_lock(COORDINATION_DIR, DEFERRED_RETRIES_LOCK_FILE):
        entries = read_private_json(DEFERRED_RETRIES_FILE, {})
        if not isinstance(entries, dict):
            entries = {}
        entry = {
            "attempt": max(0, int(attempt)),
            "hashOnly": bool(hash_only),
            "firstQueuedAt": first_queued_at,
            "retryAt": retry_at,
            "lastError": str(error),
            "forceUpload": bool(force_upload),
            "source": source,
        }
        if expected_sha256:
            entry["expectedSha256"] = expected_sha256
        if quarantine_id:
            entry["quarantineID"] = quarantine_id
        entries[str(path)] = entry
        atomic_json(DEFERRED_RETRIES_FILE, entries)


def clear_deferred_retry(path: Path) -> None:
    with exclusive_lock(COORDINATION_DIR, DEFERRED_RETRIES_LOCK_FILE):
        entries = read_private_json(DEFERRED_RETRIES_FILE, {})
        if not isinstance(entries, dict) or str(path) not in entries:
            return
        entries.pop(str(path), None)
        atomic_json(DEFERRED_RETRIES_FILE, entries)


def quarantine_vt_state() -> dict[str, dict]:
    """Return completed quarantine submissions keyed by quarantine UUID."""
    with exclusive_lock(COORDINATION_DIR, QUARANTINE_VT_STATE_LOCK_FILE):
        value = read_private_json(QUARANTINE_VT_STATE_FILE, {})
        if not isinstance(value, dict):
            return {}
        return {
            str(item_id): entry
            for item_id, entry in value.items()
            if isinstance(item_id, str) and isinstance(entry, dict)
        }


def mark_quarantine_vt_complete(quarantine_id: str, digest: str, result: dict) -> None:
    """Persist completion so restarts never submit the same quarantine item twice."""
    with exclusive_lock(COORDINATION_DIR, QUARANTINE_VT_STATE_LOCK_FILE):
        value = read_private_json(QUARANTINE_VT_STATE_FILE, {})
        if not isinstance(value, dict):
            value = {}
        value[quarantine_id] = {
            "sha256": digest.lower(),
            "status": str(result.get("status") or "unknown"),
            "uploaded": bool(result.get("uploaded", False)),
            "completedAt": now(),
        }
        # Quarantine entries can be removed from the dashboard. Keep a bounded
        # audit cache without allowing this state file to grow forever.
        if len(value) > 5_000:
            ordered = sorted(
                value.items(),
                key=lambda item: str(item[1].get("completedAt") or ""),
                reverse=True,
            )[:4_000]
            value = dict(ordered)
        atomic_json(QUARANTINE_VT_STATE_FILE, value)


def ready_quarantine_jobs() -> list[tuple[str, Path, str]]:
    """Return verified, ready quarantine payloads not yet completed by VT."""
    if not QUARANTINE_DIR.is_dir():
        return []
    completed = quarantine_vt_state()
    jobs: list[tuple[str, Path, str]] = []
    with quarantine_lock():
        for metadata_path in sorted(QUARANTINE_DIR.glob("*.json"))[:5_000]:
            try:
                metadata = read_private_json(metadata_path, {})
            except (OSError, PermissionError):
                continue
            if not isinstance(metadata, dict) or metadata.get("state", "ready") != "ready":
                continue
            quarantine_id = str(metadata.get("id") or "")
            stored_name = str(metadata.get("storedFileName") or "")
            expected_digest = str(metadata.get("sha256") or "").lower()
            if (
                not canonical_uuid_token(quarantine_id)
                or metadata_path.stem.lower() != quarantine_id.lower()
                or not stored_name
                or Path(stored_name).name != stored_name
                or stored_name in {".", ".."}
                or not stored_name.lower().startswith(quarantine_id.lower() + "-")
                or len(expected_digest) != 64
                or any(character not in "0123456789abcdef" for character in expected_digest)
            ):
                continue
            previous = completed.get(quarantine_id)
            if isinstance(previous, dict) and str(previous.get("sha256") or "").lower() == expected_digest:
                continue
            payload = QUARANTINE_DIR / stored_name
            try:
                info = os.lstat(payload)
                expected_size = int(metadata.get("fileSize"))
            except (OSError, TypeError, ValueError):
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_size != expected_size
            ):
                continue
            try:
                actual_digest = sha256(payload)
            except OSError:
                continue
            if actual_digest != expected_digest:
                continue
            jobs.append((quarantine_id, payload, expected_digest))
    return jobs


class SourceChangedError(RuntimeError):
    pass


def canonical_uuid_token(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def nested_staging_layout(staging: Path, original: Path) -> Path | None:
    """Return the canonical private container for a nested exFAT claim."""
    if (
        not staging.is_absolute()
        or not original.is_absolute()
        or Path(os.path.normpath(str(staging))) != staging
        or Path(os.path.normpath(str(original))) != original
        or staging.name != "payload"
    ):
        return None
    container = staging.parent
    if container.parent != original.parent:
        return None
    prefix = ".clamav-quarantine-"
    suffix = ".stage-dir"
    name = container.name
    if not name.startswith(prefix) or not name.endswith(suffix):
        return None
    token = name[len(prefix):-len(suffix)]
    return container if canonical_uuid_token(token) else None


def validated_nested_staging_container(staging: Path, original: Path) -> Path | None:
    container = nested_staging_layout(staging, original)
    if container is None:
        return None
    try:
        info = os.lstat(container)
    except OSError:
        return None
    # APFS reports 2 links for the empty directory and 3 after the fixed
    # payload appears; exFAT commonly reports 1 in both states.
    allowed_links = {1, 2, 3} if os.path.lexists(staging) else {1, 2}
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_nlink not in allowed_links
    ):
        return None
    return container


def cleanup_nested_staging_container(staging: Path, original: Path) -> bool:
    """Remove only an empty, canonical, still-private staging container."""
    container = validated_nested_staging_container(staging, original)
    if container is None:
        return False
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(container, flags)
    try:
        info = os.fstat(descriptor)
        path_info = os.lstat(container)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_nlink not in {1, 2}
            or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)
            or os.listdir(descriptor)
        ):
            return False
    finally:
        os.close(descriptor)
    try:
        os.rmdir(container)
        return True
    except OSError:
        return False


def cleanup_nested_staging_container_if_present(staging: Path, original: Path) -> bool:
    container = nested_staging_layout(staging, original)
    if container is None or not os.path.lexists(container):
        return True
    return cleanup_nested_staging_container(staging, original)


def verified_claimed_source(
    path: Path,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_digest: str,
) -> bool:
    """Verify the claimed pathname and opened inode are the scanned source."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        path_before = os.lstat(path)
        stable_before = (
            before.st_dev,
            before.st_ino,
            int(getattr(before, "st_gen", 0)),
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino)
            or stable_before != expected_identity[:5]
        ):
            return False
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        stable_after = (
            after.st_dev,
            after.st_ino,
            int(getattr(after, "st_gen", 0)),
            after.st_size,
            after.st_mtime_ns,
        )
        return (
            stable_after == stable_before
            and (path_after.st_dev, path_after.st_ino) == (after.st_dev, after.st_ino)
            and digest.hexdigest() == expected_digest
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def exclusive_rename_unsupported(error: OSError) -> bool:
    return error.errno in {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}


def claim_source_in_nested_staging(source: Path, staging: Path, original: Path) -> None:
    """Claim source by plain rename only inside a new private same-volume dir."""
    container = nested_staging_layout(staging, original)
    if container is None:
        raise PermissionError("Geçersiz iç içe karantina staging yolu.")
    os.mkdir(container, 0o700)
    moved = False
    descriptor = -1
    try:
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(container, flags)
        info = os.fstat(descriptor)
        path_info = os.lstat(container)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink not in {1, 2}
            or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise PermissionError("Güvensiz iç içe karantina staging dizini.")
        os.fchmod(descriptor, 0o700)
        if os.listdir(descriptor):
            raise FileExistsError("Karantina staging dizini boş değil.")
        try:
            os.stat("payload", dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("Karantina staging hedefi zaten var.")
        os.rename(source, "payload", dst_dir_fd=descriptor)
        moved = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not moved:
            cleanup_nested_staging_container_if_present(staging, original)


def rename_exclusive(source: Path, destination: Path) -> None:
    """Atomically rename without ever replacing an existing destination."""
    renameatx_np = getattr(ctypes.CDLL(None, use_errno=True), "renameatx_np", None)
    if renameatx_np is None:
        raise OSError("Bu macOS sürümünde güvenli atomik yeniden adlandırma kullanılamıyor.")
    renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameatx_np.restype = ctypes.c_int
    at_fdcwd = -2
    rename_excl = 0x00000004
    result = renameatx_np(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_excl,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), str(destination))


def source_matches_after_rename(
    path: Path,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_digest: str,
) -> bool:
    """A rename may change ctime; the inode, generation, size and mtime may not."""
    return verified_claimed_source(path, expected_identity, expected_digest)


def remove_if_same_file(path: Path, expected_device: int, expected_inode: int) -> bool:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_dev != expected_device or info.st_ino != expected_inode:
            return False
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def restore_staged_source(staging: Path, original: Path) -> Path | None:
    """Restore without touching a replacement at the original pathname."""
    if not staging.exists():
        return None
    # The nested fallback is itself a durable private recovery location. Keep
    # it under the preparing metadata so crash recovery can finish quarantine;
    # never risk replacing a new file that appeared at originalPath.
    if validated_nested_staging_container(staging, original) is not None:
        try:
            nested_info = os.lstat(staging)
        except OSError:
            return None
        if (
            stat.S_ISREG(nested_info.st_mode)
            and nested_info.st_uid == os.getuid()
            and nested_info.st_nlink == 1
        ):
            return staging
        return None
    if not original.exists():
        try:
            rename_exclusive(staging, original)
            return original
        except OSError:
            pass
    recovery = original.parent / f"ClamAV-Kurtarma-{uuid.uuid4()}"
    try:
        rename_exclusive(staging, recovery)
        return recovery
    except OSError:
        return None


def verified_cross_volume_copy(
    staging: Path,
    destination: Path,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_digest: str,
) -> tuple[int, int]:
    """Copy a staged inode and verify both ends before its private path is removed."""
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    source_descriptor = os.open(staging, source_flags)
    destination_descriptor = -1
    destination_identity: tuple[int, int] | None = None
    completed = False
    try:
        before = os.fstat(source_descriptor)
        stable_before = (
            before.st_dev,
            before.st_ino,
            int(getattr(before, "st_gen", 0)),
            before.st_size,
            before.st_mtime_ns,
        )
        stable_expected = expected_identity[:5]
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stable_before != stable_expected
        ):
            raise SourceChangedError("Sahiplenilen kaynak dosya beklenen dosya değil.")

        destination_descriptor = os.open(destination, destination_flags, 0o600)
        created = os.fstat(destination_descriptor)
        destination_identity = (created.st_dev, created.st_ino)
        os.fchmod(destination_descriptor, 0o600)
        digest = hashlib.sha256()
        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            remaining = memoryview(block)
            while remaining:
                written = os.write(destination_descriptor, remaining)
                remaining = remaining[written:]
        os.fsync(destination_descriptor)

        after = os.fstat(source_descriptor)
        destination_info = os.fstat(destination_descriptor)
        stable_after = (
            after.st_dev,
            after.st_ino,
            int(getattr(after, "st_gen", 0)),
            after.st_size,
            after.st_mtime_ns,
        )
        if stable_after != stable_before or digest.hexdigest() != expected_digest:
            raise SourceChangedError("Kaynak dosya diskler arası kopyalanırken değişti.")
        if (
            not stat.S_ISREG(destination_info.st_mode)
            or destination_info.st_uid != os.getuid()
            or destination_info.st_nlink != 1
            or destination_info.st_size != expected_identity[3]
        ):
            raise OSError("Karantina kopyasının güvenliği doğrulanamadı.")
        destination_identity = (destination_info.st_dev, destination_info.st_ino)
        completed = True
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        os.close(source_descriptor)
        if not completed and destination_identity is not None:
            remove_if_same_file(destination, *destination_identity)

    if destination_identity is None or sha256(destination) != expected_digest:
        if destination_identity is not None:
            remove_if_same_file(destination, *destination_identity)
        raise SourceChangedError("Karantina kopyasının SHA-256 doğrulaması başarısız oldu.")
    path_info = os.lstat(destination)
    if (
        not stat.S_ISREG(path_info.st_mode)
        or (path_info.st_dev, path_info.st_ino) != destination_identity
    ):
        remove_if_same_file(destination, *destination_identity)
        raise OSError("Karantina kopyasının yolu beklenmedik biçimde değişti.")
    return destination_identity


def quarantine(
    path: Path,
    signature: str,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_digest: str,
) -> Path | None:
    with quarantine_lock():
        recover_incomplete_quarantines_locked()
        try:
            current_identity = file_identity(path)
        except (FileNotFoundError, OSError):
            return None
        if current_identity != expected_identity or sha256(path) != expected_digest:
            raise SourceChangedError("Dosya taramadan sonra değişti; karantinaya taşınmadı.")
        return quarantine_locked(path, signature, expected_identity, expected_digest)


def quarantine_locked(
    path: Path,
    signature: str,
    expected_identity: tuple[int, int, int, int, int, int],
    expected_digest: str,
) -> Path:
    private_directory(QUARANTINE_DIR)
    item_id = uuid.uuid4()
    stored_name = f"{item_id}-{path.name}"
    destination = QUARANTINE_DIR / stored_name
    original_path = str(path)
    # Swift JSONEncoder's default Date representation is seconds since
    # 2001-01-01. Matching it keeps VirusTotal items visible/restorable in the
    # shared ClamAV Threat Center quarantine.
    reference_date = datetime(2001, 1, 1, tzinfo=timezone.utc)
    metadata = {
        "id": str(item_id).upper(),
        "originalPath": original_path,
        "storedFileName": stored_name,
        "signature": signature,
        "quarantinedAt": (datetime.now(timezone.utc) - reference_date).total_seconds(),
        "state": "preparing",
        "sha256": expected_digest,
        "fileSize": expected_identity[3],
    }
    metadata_path = QUARANTINE_DIR / f"{item_id}.json"
    staging = path.parent / f".clamav-quarantine-stage-{uuid.uuid4()}"
    temporary_stored_name = f".{item_id}.payload.tmp"
    temporary_destination = QUARANTINE_DIR / temporary_stored_name
    metadata["stagingPath"] = str(staging)
    metadata["temporaryStoredFileName"] = temporary_stored_name
    staged = False
    destination_identity: tuple[int, int] | None = None
    temporary_identity: tuple[int, int] | None = None
    destination_valid = False

    def finalize_metadata() -> None:
        ready = dict(metadata)
        ready["state"] = "ready"
        ready.pop("stagingPath", None)
        ready.pop("temporaryStoredFileName", None)
        atomic_json(metadata_path, ready)

    try:
        # Publish a non-restorable preparation record first. A process kill or
        # power loss can then be reconciled instead of leaving an invisible
        # staged inode or partial payload.
        atomic_json(metadata_path, metadata)

        # First atomically take ownership of the exact pathname on its original
        # volume. Every later delete targets only this unpredictable staging
        # name, never a replacement that appears at the user's original path.
        try:
            rename_exclusive(path, staging)
        except OSError as error:
            if not exclusive_rename_unsupported(error):
                raise
            staging = path.parent / f".clamav-quarantine-{uuid.uuid4()}.stage-dir" / "payload"
            # Publish the nested recovery location before mkdir/rename. A kill
            # at either boundary leaves enough information to remove an empty
            # container or finish the quarantine copy after restart.
            metadata["stagingPath"] = str(staging)
            atomic_json(metadata_path, metadata)
            claim_source_in_nested_staging(path, staging, path)
        staged = True
        if not source_matches_after_rename(staging, expected_identity, expected_digest):
            raise SourceChangedError("Karantina için sahiplenilen dosya taranan dosyayla eşleşmiyor.")

        quarantine_device = os.lstat(QUARANTINE_DIR).st_dev
        if quarantine_device == expected_identity[0]:
            rename_exclusive(staging, destination)
            staged = False
            destination_info = os.lstat(destination)
            destination_identity = (destination_info.st_dev, destination_info.st_ino)
            os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
            if not source_matches_after_rename(destination, expected_identity, expected_digest):
                raise SourceChangedError("Karantinaya taşınan dosyanın içeriği doğrulanamadı.")
            destination_valid = True
            if nested_staging_layout(staging, path) is not None:
                if not cleanup_nested_staging_container_if_present(staging, path):
                    raise OSError("Boş karantina staging dizini güvenle temizlenemedi.")
            finalize_metadata()
            return destination

        temporary_identity = verified_cross_volume_copy(
            staging,
            temporary_destination,
            expected_identity,
            expected_digest,
        )
        rename_exclusive(temporary_destination, destination)
        destination_identity = temporary_identity
        destination_info = os.lstat(destination)
        if (
            (destination_info.st_dev, destination_info.st_ino) != destination_identity
            or sha256(destination) != expected_digest
        ):
            raise SourceChangedError("Karantina kopyasının son yolu doğrulanamadı.")
        destination_valid = True
        if not source_matches_after_rename(staging, expected_identity, expected_digest):
            raise SourceChangedError("Kaynak dosya karantina kopyası doğrulandıktan sonra değişti.")
        staging_info = os.lstat(staging)
        if not remove_if_same_file(staging, staging_info.st_dev, staging_info.st_ino):
            raise OSError("Sahiplenilen staging dosyası güvenle kaldırılamadı.")
        staged = False
        if nested_staging_layout(staging, path) is not None:
            if not cleanup_nested_staging_container_if_present(staging, path):
                raise OSError("Boş karantina staging dizini güvenle temizlenemedi.")
        finalize_metadata()
        return destination
    except Exception:
        recovered_to: Path | None = None
        if staged and staging.exists():
            recovered_to = restore_staged_source(staging, path)
        elif destination_identity is not None and destination.exists() and not destination_valid:
            # Same-volume rename: the original inode is now at destination.
            if not path.exists():
                try:
                    rename_exclusive(destination, path)
                    recovered_to = path
                except OSError:
                    recovered_to = None

        if recovered_to == path:
            if destination_identity is not None:
                remove_if_same_file(destination, *destination_identity)
            if temporary_identity is not None:
                remove_if_same_file(temporary_destination, *temporary_identity)
            try:
                metadata_path.unlink()
            except FileNotFoundError:
                pass
        elif recovered_to is not None:
            metadata["stagingPath"] = str(recovered_to)
            atomic_json(metadata_path, metadata)
        elif destination_valid and destination.exists() and not staging.exists():
            # The exact source staging inode is already gone and a verified
            # final payload remains. Completing metadata is safer than trying a
            # second cross-volume move during error recovery.
            if (
                nested_staging_layout(staging, path) is None
                or cleanup_nested_staging_container_if_present(staging, path)
            ):
                finalize_metadata()
        elif not staging.exists() and not destination.exists() and path.exists():
            staging_cleanup_ok = True
            if nested_staging_layout(staging, path) is not None:
                staging_cleanup_ok = cleanup_nested_staging_container_if_present(staging, path)
            if staging_cleanup_ok:
                try:
                    metadata_path.unlink()
                except FileNotFoundError:
                    pass
        raise


def recover_incomplete_quarantines_locked() -> None:
    """Reconcile crash-interrupted shared quarantine transactions."""
    private_directory(QUARANTINE_DIR)

    def safe_child(name: object) -> Path | None:
        value = str(name or "")
        if not value or Path(value).name != value:
            return None
        return QUARANTINE_DIR / value

    def safe_staging_child(value: object, original: Path | None) -> Path | None:
        """Accept the two flat names and the shared canonical nested fallback."""
        raw = str(value or "")
        if not raw or original is None:
            return None
        candidate = Path(raw)
        if (
            not candidate.is_absolute()
            or not original.is_absolute()
            or Path(os.path.normpath(str(candidate))) != candidate
            or Path(os.path.normpath(str(original))) != original
            or candidate == original
        ):
            return None

        if nested_staging_layout(candidate, original) is not None:
            return candidate
        if candidate.parent != original.parent:
            return None

        name = candidate.name
        token = ""
        python_prefix = ".clamav-quarantine-stage-"
        realtime_prefix = ".clamav-quarantine-"
        realtime_suffix = ".stage"
        if name.startswith(python_prefix):
            token = name[len(python_prefix):]
        elif name.startswith(realtime_prefix) and name.endswith(realtime_suffix):
            token = name[len(realtime_prefix):-len(realtime_suffix)]
        else:
            return None
        try:
            parsed = uuid.UUID(token)
        except (ValueError, AttributeError):
            return None
        if str(parsed) != token.lower():
            return None
        return candidate

    def matches(path: Path | None, digest: str, size: int) -> bool:
        if path is None:
            return False
        try:
            info = os.lstat(path)
            return (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and info.st_nlink == 1
                and info.st_size == size
                and sha256(path) == digest
            )
        except OSError:
            return False

    def remove_safe_artifact(path: Path | None) -> bool:
        if path is None:
            return True
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return True
        if (
            path.parent != QUARANTINE_DIR
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            return False
        return remove_if_same_file(path, info.st_dev, info.st_ino)

    for metadata_path in QUARANTINE_DIR.glob("*.json"):
        if metadata_path.name.startswith("."):
            continue
        metadata = read_private_json(metadata_path, {})
        if not isinstance(metadata, dict) or metadata.get("state") != "preparing":
            continue
        digest = str(metadata.get("sha256") or "").lower()
        try:
            size = int(metadata.get("fileSize"))
        except (TypeError, ValueError):
            continue
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            continue

        destination = safe_child(metadata.get("storedFileName"))
        temporary = safe_child(metadata.get("temporaryStoredFileName"))
        original_value = str(metadata.get("originalPath") or "")
        original = Path(original_value) if original_value else None
        staging = safe_staging_child(metadata.get("stagingPath"), original)
        nested_container = (
            nested_staging_layout(staging, original)
            if staging is not None and original is not None
            else None
        )
        if nested_container is not None and os.path.lexists(nested_container):
            if validated_nested_staging_container(staging, original) is None:
                # Never traverse, delete, or retire metadata that points at a
                # substituted/symlinked/wrong-owner container.
                continue
        if staging is not None:
            try:
                staging_info = os.lstat(staging)
            except FileNotFoundError:
                if nested_container is not None and nested_container.exists():
                    # Covers both mkdir-before-rename and
                    # payload-delete-before-rmdir crash windows.
                    if not cleanup_nested_staging_container_if_present(staging, original):
                        continue
            except OSError:
                continue
            else:
                if (
                    not stat.S_ISREG(staging_info.st_mode)
                    or staging_info.st_uid != os.getuid()
                    or staging_info.st_nlink != 1
                ):
                    continue

        # A nested source claim is already safely owned. After a crash, finish
        # its verified copy into the shared quarantine instead of attempting a
        # no-replace rename back onto an exFAT original path.
        if (
            nested_container is not None
            and staging is not None
            and matches(staging, digest, size)
            and not matches(destination, digest, size)
        ):
            if temporary is None:
                continue
            if destination is not None and os.path.lexists(destination):
                if not remove_safe_artifact(destination):
                    continue
            if os.path.lexists(temporary) and not matches(temporary, digest, size):
                if not remove_safe_artifact(temporary):
                    continue
            if not matches(temporary, digest, size):
                try:
                    staging_identity = file_identity(staging)
                    verified_cross_volume_copy(
                        staging,
                        temporary,
                        staging_identity,
                        digest,
                    )
                except (OSError, SourceChangedError):
                    continue

        if not matches(destination, digest, size) and matches(temporary, digest, size):
            if destination is not None and not destination.exists():
                try:
                    rename_exclusive(temporary, destination)
                except OSError:
                    pass

        if (
            nested_container is not None
            and (os.path.lexists(staging) or os.path.lexists(nested_container))
            and not matches(destination, digest, size)
        ):
            # Keep every claimed/copy artifact and its preparing metadata for a
            # later safe retry; never route a nested exFAT claim through the
            # legacy restore/delete branches below.
            continue

        if matches(destination, digest, size):
            if staging is not None and staging.exists():
                if matches(staging, digest, size):
                    staging_info = os.lstat(staging)
                    if not remove_if_same_file(staging, staging_info.st_dev, staging_info.st_ino):
                        continue
                elif original is not None:
                    recovered = restore_staged_source(staging, original)
                    if recovered is None or recovered != original:
                        if recovered is not None:
                            metadata["stagingPath"] = str(recovered)
                            atomic_json(metadata_path, metadata)
                        continue
            if nested_container is not None and original is not None:
                if not cleanup_nested_staging_container_if_present(staging, original):
                    continue
            if not remove_safe_artifact(temporary):
                continue
            ready = dict(metadata)
            ready["state"] = "ready"
            ready.pop("stagingPath", None)
            ready.pop("temporaryStoredFileName", None)
            atomic_json(metadata_path, ready)
            continue

        if staging is not None and staging.exists() and original is not None:
            recovered = restore_staged_source(staging, original)
            if recovered == original:
                if remove_safe_artifact(temporary) and remove_safe_artifact(destination):
                    try:
                        metadata_path.unlink()
                    except FileNotFoundError:
                        pass
            elif recovered is not None:
                remove_safe_artifact(temporary)
                remove_safe_artifact(destination)
                metadata["stagingPath"] = str(recovered)
                atomic_json(metadata_path, metadata)
            continue

        if original is not None and matches(original, digest, size):
            if remove_safe_artifact(temporary) and remove_safe_artifact(destination):
                try:
                    metadata_path.unlink()
                except FileNotFoundError:
                    pass


def uploaded_hashes_from_log(log_path: Path, day: str) -> set[str]:
    uploaded_hashes: set[str] = set()
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(log_path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            os.close(descriptor)
            return uploaded_hashes
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="replace") as source:
            for line in source:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                timestamp = str(row.get("timestamp") or row.get("time") or "")
                if timestamp[:10] == day and row.get("uploaded"):
                    digest = str(row.get("sha256") or "")
                    if len(digest) == 64:
                        uploaded_hashes.add(digest.lower())
    except OSError:
        pass
    return uploaded_hashes


def reserve_upload_budget(log_path: Path, digest: str, limit: int) -> str:
    """Atomically reserve one unique daily upload, independent of log rotation."""
    today = datetime.now(timezone.utc).date().isoformat()
    normalized_digest = digest.lower()
    with exclusive_lock(COORDINATION_DIR, UPLOAD_LEDGER_LOCK_FILE):
        value = read_private_json(UPLOAD_LEDGER_FILE, {})
        if isinstance(value, dict) and value.get("date") == today:
            uploaded_hashes = {
                str(item).lower()
                for item in value.get("hashes", [])
                if isinstance(item, str) and len(item) == 64
            }
        else:
            # One-time seed preserves uploads recorded before this ledger was
            # introduced. Future rotations cannot reduce the retained count.
            uploaded_hashes = uploaded_hashes_from_log(log_path, today)
        if normalized_digest in uploaded_hashes:
            return "existing"
        if len(uploaded_hashes) >= max(0, int(limit)):
            return "full"
        uploaded_hashes.add(normalized_digest)
        atomic_json(UPLOAD_LEDGER_FILE, {
            "date": today,
            "hashes": sorted(uploaded_hashes),
            "updatedAt": now(),
        })
        return "reserved"


def release_upload_reservation(digest: str) -> None:
    """Release only requests that VirusTotal definitively rejected."""
    today = datetime.now(timezone.utc).date().isoformat()
    with exclusive_lock(COORDINATION_DIR, UPLOAD_LEDGER_LOCK_FILE):
        value = read_private_json(UPLOAD_LEDGER_FILE, {})
        if not isinstance(value, dict) or value.get("date") != today:
            return
        uploaded_hashes = {
            str(item).lower()
            for item in value.get("hashes", [])
            if isinstance(item, str) and len(item) == 64
        }
        uploaded_hashes.discard(digest.lower())
        atomic_json(UPLOAD_LEDGER_FILE, {
            "date": today,
            "hashes": sorted(uploaded_hashes),
            "updatedAt": now(),
        })


def parse_utc_timestamp(value: object, fallback: datetime | None = None) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return fallback or datetime.now(timezone.utc)


def unfinished_queue(log_path: Path) -> deque[tuple[Path, int, bool, str, str | None, bool, str, str | None]]:
    """Restore items that were queued when the app or Mac restarted."""
    latest: dict[str, dict] = {}
    try:
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try: row = json.loads(line)
            except json.JSONDecodeError: continue
            name = row.get("path") or row.get("file")
            if name: latest[str(name)] = row
    except OSError:
        return deque()
    def needs_retry(row: dict) -> bool:
        if row.get("status") in {
            "kuyrukta", "tarayıcı-kuyruğunda", "taranıyor",
            "tarama-yeniden-denenecek", "upload-pending",
            "queued", "scanning", "retrying",
        }:
            return True
        # Repair records written by older versions that used an analysis object
        # before VT had produced actual engine results.
        return bool(row.get("analysis_stats")) and not row.get("engine_results")
    restored: deque[tuple[Path, int, bool, str, str | None, bool, str, str | None]] = deque()
    for name, row in latest.items():
        path = Path(name)
        if not needs_retry(row) or not path.is_file() or path.name.startswith("."):
            continue
        timestamp = str(row.get("firstQueuedAt") or row.get("timestamp") or row.get("time") or now())
        restored.append((
            path,
            max(0, int(row.get("attempt", 0) or 0)),
            bool(row.get("hashOnly", False)),
            timestamp,
            str(row.get("expectedSha256") or row.get("sha256") or "") or None,
            bool(row.get("forceUpload", False)),
            str(row.get("source") or "download"),
            str(row.get("quarantineID") or "") or None,
        ))
    return restored


def chromium_history_files() -> list[Path]:
    home = Path.home()
    roots = [
        home / "Library/Application Support/Google/Chrome",
        home / "Library/Application Support/Microsoft Edge",
        home / "Library/Application Support/BraveSoftware/Brave-Browser",
        home / "Library/Application Support/Arc/User Data",
    ]
    return [history for root in roots if root.is_dir() for history in root.glob("*/History") if history.is_file()]


def browser_downloads() -> dict[str, Path]:
    """Completed download paths from browser histories; nothing is executed."""
    found: dict[str, Path] = {}
    for history in chromium_history_files():
        try:
            uri = f"file:{urllib.parse.quote(str(history))}?immutable=1"
            with sqlite3.connect(uri, uri=True) as db:
                for row_id, target, state in db.execute("SELECT id, target_path, state FROM downloads"):
                    if state == 1 and target:
                        found[f"chromium:{history}:{row_id}"] = Path(target)
        except (OSError, sqlite3.Error):
            continue
    firefox = Path.home() / "Library/Application Support/Firefox/Profiles"
    if firefox.is_dir():
        for history in firefox.glob("*/places.sqlite"):
            try:
                uri = f"file:{urllib.parse.quote(str(history))}?immutable=1"
                with sqlite3.connect(uri, uri=True) as db:
                    sql = """SELECT a.id, a.content FROM moz_annos a
                             JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id
                             WHERE n.name = 'downloads/destinationFileURI'"""
                    for row_id, location in db.execute(sql):
                        parsed = urllib.parse.urlparse(location)
                        if parsed.scheme == "file": found[f"firefox:{history}:{row_id}"] = Path(urllib.parse.unquote(parsed.path))
            except (OSError, sqlite3.Error):
                continue
    safari = Path.home() / "Library/Safari/Downloads.plist"
    try:
        for index, item in enumerate(plistlib.loads(safari.read_bytes())):
            location = item.get("DownloadEntryPath")
            if location: found[f"safari:{index}:{location}"] = Path(location)
    except (OSError, ValueError, TypeError):
        pass
    return found


def ignored(path: Path, digest: str, settings: dict) -> str | None:
    if path.name.startswith(".") or path.suffix.lower() in IGNORED_SUFFIXES: return "geçici dosya"
    if digest in settings["whitelist_hashes"] or path.name in settings["whitelist_names"] or path.suffix.lower() in settings["whitelist_suffixes"]: return "beyaz listede"
    return None


def download_source(path: Path) -> list[str]:
    """Return only source hostnames, not private full download URLs."""
    try:
        get_xattr = getattr(os, "getxattr", None)
        if get_xattr is None:
            return []
        raw = get_xattr(path, "com.apple.metadata:kMDItemWhereFroms")
        # The value is a binary plist on modern macOS; decode only when available.
        import plistlib
        value = plistlib.loads(raw)
        if not isinstance(value, list): return []
        hosts = []
        for item in value:
            parsed = urllib.parse.urlparse(str(item))
            if parsed.hostname and parsed.hostname not in hosts: hosts.append(parsed.hostname)
        return hosts
    except (AttributeError, OSError, ValueError):
        return []


def inspect(
    path: Path,
    key: str,
    log_path: Path,
    *,
    force_upload: bool = False,
    hash_only: bool = False,
    expected_sha256: str | None = None,
    source: str = "download",
    quarantine_id: str | None = None,
    allow_quarantine: bool = True,
) -> dict:
    settings = config()
    context = {
        "source": source,
        **({"quarantineID": quarantine_id, "alreadyQuarantined": True} if quarantine_id else {}),
    }
    if not path.is_file():
        return result_record({"path": str(path), "status": "error", "error": "Dosya bulunamadı.", **context})
    # Ignore Finder/browser housekeeping before even calculating a hash.
    if path.name.startswith(".") or path.suffix.lower() in IGNORED_SUFFIXES:
        return result_record({"path": str(path), "status": "atlandı-gizli-veya-geçici", **context})
    initial_identity = file_identity(path)
    digest = sha256(path)
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise SourceChangedError("Dosya, yükleme onayından sonra değişti; VirusTotal'a gönderilmedi.")
    if file_identity(path) != initial_identity:
        raise SourceChangedError("Dosya hash hesaplanırken değişti.")

    def verify_unchanged() -> None:
        if file_identity(path) != initial_identity or sha256(path) != digest:
            raise SourceChangedError("Dosya VirusTotal kontrolü sırasında değişti.")

    skipped = ignored(path, digest, settings)
    if skipped:
        return record_and_log(log_path, {"timestamp": now(), "path": str(path), "sha256": digest, "status": skipped, **context})
    report = file_report(digest, key)
    if not usable_report(report): report = None
    uploaded = False
    if report is not None:
        clear_pending_analysis(digest)
    elif not hash_only:
        pending = pending_entry(digest)
        if pending and pending.get("analysisID"):
            analysis_report(str(pending["analysisID"]), key)
            report = file_report(digest, key)
            if not usable_report(report):
                raise RuntimeError("VirusTotal dosya raporu henüz hazırlanıyor")
            clear_pending_analysis(digest)
            uploaded = True
        elif pending:
            try:
                created = datetime.fromisoformat(str(pending.get("createdAt")))
                pending_age = (datetime.now(timezone.utc) - created).total_seconds()
            except (TypeError, ValueError):
                pending_age = 601
            if pending_age < 600:
                raise RuntimeError("Önceki VirusTotal yüklemesi hâlâ işleniyor; yeniden yüklenmedi.")
    if report is None:
        verify_unchanged()
        if hash_only or (not force_upload and not bool(settings.get("auto_upload_unknown", False))):
            return record_and_log(log_path, {"timestamp": now(), "path": str(path), "sha256": digest, "status": "unknown", **context})
        if path.stat().st_size > MAX_PUBLIC_UPLOAD:
            return record_and_log(log_path, {"timestamp": now(), "path": str(path), "sha256": digest, "status": "unknown", "error": "Dosya 32 MB VirusTotal genel API sınırını aşıyor.", **context})
        if settings["upload_unknown_risky_only"] and path.suffix.lower() not in RISKY_SUFFIXES and not force_upload:
            return record_and_log(log_path, {"timestamp": now(), "path": str(path), "sha256": digest, "status": "unknown", **context})
        content = verified_upload_content(path, initial_identity, digest)
        claim, analysis_id = claim_upload(
            digest,
            path,
            hash_only=hash_only,
            source=source,
            quarantine_id=quarantine_id,
        )
        if claim == "wait":
            raise RuntimeError("Aynı dosyanın VirusTotal yüklemesi başka bir süreçte devam ediyor.")
        if claim == "upload":
            reservation = reserve_upload_budget(
                log_path,
                digest,
                int(settings["max_uploads_per_day"]),
            )
            if reservation == "full":
                clear_pending_analysis(digest)
                return record_and_log(log_path, {
                    "timestamp": now(),
                    "path": str(path),
                    "sha256": digest,
                    "status": "error",
                    "error": "Günlük VirusTotal yükleme sınırına ulaşıldı.",
                    **context,
                })
            if reservation == "existing":
                raise RuntimeError("Bu dosya için önceki yüklemenin sonucu bekleniyor; yeniden yüklenmedi.")
            try:
                analysis_id = upload_content(path.name, content, key)
            except Exception as error:
                message = str(error)
                if any(f"VirusTotal HTTP {code}" in message for code in (400, 401, 403, 404, 405, 413, 422, 429)):
                    release_upload_reservation(digest)
                    clear_pending_analysis(digest)
                raise
            save_pending_analysis(
                digest,
                analysis_id,
                path,
                hash_only=hash_only,
                source=source,
                quarantine_id=quarantine_id,
            )
            log(log_path, {
                "timestamp": now(),
                "path": str(path),
                "sha256": digest,
                "status": "upload-pending",
                "uploaded": True,
                **context,
            })
        if not analysis_id:
            raise RuntimeError("VirusTotal analiz kimliği alınamadı.")
        analysis_report(analysis_id, key)
        report = file_report(digest, key)
        if not usable_report(report):
            raise RuntimeError("VirusTotal analizi tamamlandı; dosya raporu henüz hazırlanıyor")
        clear_pending_analysis(digest)
        uploaded = True
    verify_unchanged()
    attributes = report["data"]["attributes"]; stats = attributes.get("last_analysis_stats", attributes.get("stats", {}))
    malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
    record = {
        "timestamp": now(),
        "path": str(path),
        "sha256": digest,
        "sourceDomains": download_source(path),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "uploaded": uploaded,
        "status": "known-malicious" if malicious > 0 else ("known-warning" if suspicious > 0 else "known-clean"),
        "reportURL": f"https://www.virustotal.com/gui/file/{report['data'].get('id', digest)}",
        **context,
    }
    minimum_malicious = max(1, int(settings.get("automatic_quarantine_min_malicious", 2)))
    minimum_total = max(minimum_malicious, int(settings.get("automatic_quarantine_min_total", 3)))
    should_quarantine = malicious >= minimum_malicious or malicious + suspicious >= minimum_total
    if should_quarantine and allow_quarantine:
        signature = f"VirusTotal.{malicious}-malicious.{suspicious}-suspicious"
        try:
            moved = quarantine(path, signature, initial_identity, digest)
            if moved is not None:
                record["quarantinedTo"] = str(moved)
        except (OSError, SourceChangedError) as error:
            record["status"] = "error"
            record["error"] = f"Tehdit bulundu ancak karantina tamamlanamadı: {error}"
    return record_and_log(log_path, record)


def folder_snapshot(folder: Path) -> dict[Path, tuple[int, int, int, int, int, int]]:
    snapshot: dict[Path, tuple[int, int, int, int, int, int]] = {}
    for path in folder.iterdir():
        try:
            snapshot[path] = file_identity(path)
        except (FileNotFoundError, OSError):
            continue
    return snapshot


def watch(
    folder: Path,
    key: str,
    log_path: Path,
    interval: float,
    status: StatusWriter,
    stop_event: threading.Event,
) -> None:
    # Publish liveness before the potentially expensive initial Downloads and
    # browser-history snapshots. This lets launchd/install health checks verify
    # the service without mistaking normal startup work for a crash.
    status.update(running=True, queueDepth=0, lastResult="starting", lastError=None)

    def heartbeat() -> None:
        while not stop_event.wait(60):
            status.update()

    threading.Thread(target=heartbeat, name="vt-status-heartbeat", daemon=True).start()
    try:
        with quarantine_lock():
            recover_incomplete_quarantines_locked()
    except Exception as error:
        log(log_path, {
            "time": now(),
            "status": "izleyici-hatası",
            "error": f"Tamamlanmamış karantina işlemi uzlaştırılamadı: {error}",
        })
        status.update(lastResult="error", lastError=str(error))
    known = folder_snapshot(folder)
    scanned = known.copy()
    work: Queue[tuple[Path, int, bool, str, str | None, bool, str, str | None] | None] = Queue()
    pending: set[Path] = set()
    deferred: dict[Path, tuple[float, int, bool, str, str | None, bool, str, str | None]] = {}
    pending_lock = threading.Lock()
    seen_signatures = {(p, *signature) for p, signature in known.items()}

    # Persistent deferred retries are authoritative: a network outage must not
    # make a completed download disappear just because the app or Mac restarts.
    current_time = datetime.now(timezone.utc)
    for name, entry in deferred_retries().items():
        path = Path(name)
        first_queued_at = str(entry.get("firstQueuedAt") or now())
        first_time = parse_utc_timestamp(first_queued_at, current_time)
        age = (current_time - first_time).total_seconds()
        if age >= MAX_DEFERRED_RETRY_AGE_SECONDS or not path.is_file():
            clear_deferred_retry(path)
            continue
        attempt = max(0, int(entry.get("attempt", 4) or 4))
        hash_only = bool(entry.get("hashOnly", False))
        expected_sha256 = str(entry.get("expectedSha256") or "") or None
        force_upload = bool(entry.get("forceUpload", False))
        source = str(entry.get("source") or "download")
        quarantine_id = str(entry.get("quarantineID") or "") or None
        retry_time = parse_utc_timestamp(entry.get("retryAt"), current_time).timestamp()
        pending.add(path)
        if retry_time <= time.time():
            work.put((path, attempt, hash_only, first_queued_at, expected_sha256, force_upload, source, quarantine_id))
        else:
            deferred[path] = (retry_time, attempt, hash_only, first_queued_at, expected_sha256, force_upload, source, quarantine_id)

    restored = unfinished_queue(log_path)
    for item in restored:
        if item[0] in pending:
            continue
        work.put(item)
        pending.add(item[0])
    status.update(running=True, queueDepth=len(pending), lastResult=None, lastError=None)
    # Snapshot existing browser history so installing/restarting the app never
    # retroactively scans the user's old downloads.
    browser_seen = set(browser_downloads())
    if restored: print(f"Önceki oturumdan {len(restored)} tarama geri yüklendi.", flush=True)
    print(f"İzleniyor: {folder}", flush=True)

    def enqueue(
        path: Path,
        event_status: str,
        *,
        hash_only: bool = False,
        expected_sha256: str | None = None,
        force_upload: bool = False,
        source: str = "download",
        quarantine_id: str | None = None,
        force: bool = False,
        **details,
    ) -> bool:
        try: signature = (path, *file_identity(path))
        except OSError: return False
        if path.name.startswith(".") or path.suffix.lower() in IGNORED_SUFFIXES: return False
        first_queued_at = now()
        with pending_lock:
            if (signature in seen_signatures and not force) or path in pending: return False
            seen_signatures.add(signature)
            pending.add(path)
            work.put((path, 0, hash_only, first_queued_at, expected_sha256, force_upload, source, quarantine_id))
            queue_depth = len(pending)
        status.update(queueDepth=queue_depth)
        log(log_path, {
            "time": now(),
            "file": str(path),
            "status": event_status,
            "hashOnly": hash_only,
            "firstQueuedAt": first_queued_at,
            "forceUpload": force_upload,
            "source": source,
            **({"expectedSha256": expected_sha256} if expected_sha256 else {}),
            **({"quarantineID": quarantine_id, "alreadyQuarantined": True} if quarantine_id else {}),
            **details,
        })
        return True

    def worker() -> None:
        while True:
            item = work.get()
            if item is None: return
            path, attempts, hash_only, first_queued_at, expected_sha256, force_upload, source, quarantine_id = item
            try:
                log(log_path, {
                    "time": now(),
                    "file": str(path),
                    "status": "taranıyor",
                    "attempt": attempts + 1,
                    "hashOnly": hash_only,
                    "firstQueuedAt": first_queued_at,
                    "forceUpload": force_upload,
                    "source": source,
                    **({"expectedSha256": expected_sha256} if expected_sha256 else {}),
                    **({"quarantineID": quarantine_id, "alreadyQuarantined": True} if quarantine_id else {}),
                })
                result = inspect(
                    path,
                    key,
                    log_path,
                    hash_only=hash_only,
                    expected_sha256=expected_sha256,
                    force_upload=force_upload,
                    source=source,
                    quarantine_id=quarantine_id,
                    allow_quarantine=quarantine_id is None,
                )
                if quarantine_id and expected_sha256:
                    mark_quarantine_vt_complete(quarantine_id, expected_sha256, result)
                clear_deferred_retry(path)
                with pending_lock:
                    deferred.pop(path, None)
                    pending.discard(path)
                    queue_depth = len(pending)
                status.record(result)
                status.update(queueDepth=queue_depth)
            except Exception as error:
                attempt = attempts + 1
                status.update(lastPath=str(path), lastResult="retrying", lastError=str(error))
                first_time = parse_utc_timestamp(first_queued_at)
                retry_age = (datetime.now(timezone.utc) - first_time).total_seconds()
                terminal = (
                    isinstance(error, (FileNotFoundError, PermissionError))
                    or (expected_sha256 is not None and isinstance(error, SourceChangedError))
                    or not path.is_file()
                )
                if not terminal and retry_age < MAX_DEFERRED_RETRY_AGE_SECONDS and attempts < 3:
                    log(log_path, {
                        "time": now(),
                        "file": str(path),
                        "status": "tarama-yeniden-denenecek",
                        "attempt": attempt,
                        "hashOnly": hash_only,
                        "firstQueuedAt": first_queued_at,
                        "forceUpload": force_upload,
                        "source": source,
                        **({"expectedSha256": expected_sha256} if expected_sha256 else {}),
                        **({"quarantineID": quarantine_id, "alreadyQuarantined": True} if quarantine_id else {}),
                        "error": str(error),
                    })
                    work.put((path, attempt, hash_only, first_queued_at, expected_sha256, force_upload, source, quarantine_id))
                elif not terminal and retry_age < MAX_DEFERRED_RETRY_AGE_SECONDS:
                    exponent = min(max(0, attempts - 3), 4)
                    delay = min(MAX_DEFERRED_RETRY_DELAY_SECONDS, 60 * (2 ** exponent))
                    retry_at_value = datetime.fromtimestamp(
                        time.time() + delay,
                        tz=timezone.utc,
                    ).isoformat()
                    save_deferred_retry(
                        path,
                        attempt=attempt,
                        hash_only=hash_only,
                        first_queued_at=first_queued_at,
                        retry_at=retry_at_value,
                        error=str(error),
                        expected_sha256=expected_sha256,
                        force_upload=force_upload,
                        source=source,
                        quarantine_id=quarantine_id,
                    )
                    log(log_path, {
                        "time": now(),
                        "file": str(path),
                        "status": "tarama-yeniden-denenecek",
                        "attempt": attempt,
                        "hashOnly": hash_only,
                        "firstQueuedAt": first_queued_at,
                        "forceUpload": force_upload,
                        "source": source,
                        "retryAt": retry_at_value,
                        **({"expectedSha256": expected_sha256} if expected_sha256 else {}),
                        **({"quarantineID": quarantine_id, "alreadyQuarantined": True} if quarantine_id else {}),
                        "error": str(error),
                    })
                    with pending_lock:
                        deferred[path] = (
                            parse_utc_timestamp(retry_at_value).timestamp(),
                            attempt,
                            hash_only,
                            first_queued_at,
                            expected_sha256,
                            force_upload,
                            source,
                            quarantine_id,
                        )
                else:
                    if expected_sha256:
                        clear_pending_analysis(expected_sha256)
                    clear_deferred_retry(path)
                    log(log_path, {
                        "time": now(),
                        "file": str(path),
                        "status": "tarama-başarısız",
                        "attempt": attempt,
                        "hashOnly": hash_only,
                        "firstQueuedAt": first_queued_at,
                        "forceUpload": force_upload,
                        "source": source,
                        **({"expectedSha256": expected_sha256} if expected_sha256 else {}),
                        **({"quarantineID": quarantine_id, "alreadyQuarantined": True} if quarantine_id else {}),
                        "error": str(error),
                    })
                    with pending_lock:
                        deferred.pop(path, None)
                        pending.discard(path)
                        queue_depth = len(pending)
                    status.update(queueDepth=queue_depth, lastResult="error", lastError=str(error))
            finally: work.task_done()

    threading.Thread(target=worker, name="vt-scan-worker", daemon=True).start()
    last_browser_poll = 0.0
    last_quarantine_poll = 0.0
    while not stop_event.is_set():
        try:
            ready: list[tuple[Path, int, bool, str, str | None, bool, str, str | None]] = []
            with pending_lock:
                monotonic_wall_time = time.time()
                for path, retry in list(deferred.items()):
                    if retry[0] <= monotonic_wall_time:
                        ready.append((path, retry[1], retry[2], retry[3], retry[4], retry[5], retry[6], retry[7]))
                        deferred.pop(path, None)
            for item in ready:
                work.put(item)

            # A manual dashboard upload may have been accepted immediately
            # before its short-lived CLI process or the Mac stopped. The
            # analysis ID is durable; adopt it into the live worker without a
            # second upload or a second user approval.
            for digest, entry in pending_analysis_jobs().items():
                path = Path(str(entry.get("path")))
                if not path.is_file():
                    log(log_path, {
                        "time": now(),
                        "file": str(path),
                        "sha256": digest,
                        "status": "tarama-başarısız",
                        "error": "Yüklenen dosya artık bu konumda bulunmadığı için sonuç uygulanamadı.",
                    })
                    clear_pending_analysis(digest)
                    continue
                enqueue(
                    path,
                    "kuyrukta",
                    hash_only=bool(entry.get("hashOnly", False)),
                    expected_sha256=digest,
                    force_upload=bool(entry.get("source") == "quarantine-auto"),
                    source=str(entry.get("source") or "download"),
                    quarantine_id=str(entry.get("quarantineID") or "") or None,
                    force=True,
                )

            # Quarantined payloads are already isolated. Hash-match their
            # signed metadata first; unknown hashes are then automatically
            # uploaded for a VirusTotal second opinion.
            if bool(config().get("auto_upload_quarantine", False)) and time.monotonic() - last_quarantine_poll >= 60:
                for quarantine_id, path, digest in ready_quarantine_jobs():
                    enqueue(
                        path,
                        "kuyrukta",
                        expected_sha256=digest,
                        force_upload=True,
                        source="quarantine-auto",
                        quarantine_id=quarantine_id,
                    )
                last_quarantine_poll = time.monotonic()

            current = folder_snapshot(folder)
            removed_paths = set(known).difference(current)
            if removed_paths:
                seen_signatures = {
                    signature for signature in seen_signatures
                    if signature[0] not in removed_paths
                }
            for path, signature in current.items():
                if path in known and known[path] == signature and scanned.get(path) != signature:
                    if enqueue(path, "kuyrukta"):
                        scanned[path] = signature
                known[path] = signature
            # Browser history catches files saved outside ~/Downloads. Browser
            # records are used only as a file-location signal, never uploaded.
            if time.monotonic() - last_browser_poll >= 60:
                for download_id, path in browser_downloads().items():
                    if download_id not in browser_seen:
                        browser_seen.add(download_id)
                        if path.is_file():
                            enqueue(path, "tarayıcı-kuyruğunda", hash_only=True, browser_record=download_id)
                last_browser_poll = time.monotonic()
            known = {p: v for p, v in known.items() if p in current}; scanned = {p: v for p, v in scanned.items() if p in current}
            if len(seen_signatures) > 20_000:
                seen_signatures = {(path, *signature) for path, signature in current.items()}
            with pending_lock:
                queue_depth = len(pending)
            status.update(queueDepth=queue_depth)
            stop_event.wait(interval)
        except KeyboardInterrupt: return
        except Exception as error:
            log(log_path, {"time": now(), "status": "izleyici-hatası", "error": str(error)})
            status.update(lastResult="error", lastError=str(error))
            stop_event.wait(interval)


def migrate_log(source: Path, destination: Path) -> int:
    if not source.is_file():
        return 0
    private_directory(destination.parent)
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.migration"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    merged: list[dict] = []
    identities: set[str] = set()
    added = 0

    def rows(path: Path):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            source_descriptor = os.open(path, flags)
        except FileNotFoundError:
            return
        try:
            info = os.fstat(source_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise PermissionError(f"Güvensiz VirusTotal geçmiş dosyası: {path}")
            with os.fdopen(source_descriptor, "r", encoding="utf-8", errors="replace") as input_file:
                source_descriptor = -1
                for line in input_file:
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(value, dict):
                        yield result_record(value)
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)

    def identity(row: dict) -> str:
        comparable = {key: value for key, value in row.items() if key != "id"}
        return json.dumps(comparable, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    try:
        for row in rows(destination):
            marker = identity(row)
            if marker not in identities:
                identities.add(marker)
                merged.append(row)
        existing_count = len(merged)
        for row in rows(source):
            marker = identity(row)
            if marker not in identities:
                identities.add(marker)
                merged.append(row)
        added = len(merged) - existing_count

        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            for row in merged:
                output.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        return added
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, default=Path.home() / "Downloads")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--force-upload", action="store_true")
    parser.add_argument("--hash-only", action="store_true")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--migrate-log", type=Path)
    parser.add_argument("--interval", type=float, default=15)
    parser.add_argument("--log", type=Path, default=RESULTS_FILE)
    args = parser.parse_args()

    log_path = args.log.expanduser()
    if args.migrate_log:
        count = migrate_log(args.migrate_log.expanduser(), log_path)
        print(json.dumps({"migrated": count, "destination": str(log_path)}, ensure_ascii=False))
        return 0
    if args.hash_only and args.force_upload:
        parser.error("--hash-only ve --force-upload birlikte kullanılamaz.")
    if args.expected_sha256 and (
        len(args.expected_sha256) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in args.expected_sha256)
    ):
        parser.error("--expected-sha256 64 karakterlik SHA-256 olmalıdır.")

    settings = config()
    key = os.environ.get("VIRUSTOTAL_API_KEY") or local_api_key()
    if args.file:
        if not key:
            print(json.dumps(result_record({"path": str(args.file.expanduser()), "status": "error", "error": "VirusTotal API anahtarı bulunamadı."}), ensure_ascii=False))
            return 78
        try:
            result = inspect(
                args.file.expanduser(),
                key,
                log_path,
                force_upload=args.force_upload,
                hash_only=args.hash_only,
                expected_sha256=args.expected_sha256,
            )
            print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
            return 0 if result.get("status") != "error" else 1
        except Exception as error:
            result = result_record({"path": str(args.file.expanduser()), "status": "error", "error": str(error)})
            log(log_path, result)
            print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
            return 1

    folder = args.folder.expanduser()
    status = StatusWriter([str(folder)], key is not None, settings)
    if not key:
        status.update(running=False, lastResult="error", lastError="VirusTotal API anahtarı bulunamadı.")
        return 0
    stop_event = threading.Event()

    def stop_handler(_signum, _frame) -> None:
        stop_event.set()

    import signal
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    try:
        watch(folder, key, log_path, max(1.0, args.interval), status, stop_event)
        return 0
    except Exception as error:
        status.update(running=False, lastResult="error", lastError=str(error))
        return 1
    finally:
        status.update(running=False)


if __name__ == "__main__": raise SystemExit(main())
