#!/usr/bin/env python3
"""Run a ClamAV scan while publishing bounded, atomic progress status."""
from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


APP_DIR = Path.home() / "Library/Application Support/ClamAV-Automation"
STATUS_FILE = APP_DIR / "scan-progress.json"
MANIFEST_DIR = APP_DIR / "scan-manifests"
SUMMARY_MARKER = "----------- SCAN SUMMARY -----------"
EXCLUDED_DIRECTORY_NAMES = {
    ".cache", ".git", ".mypy_cache", ".npm", ".pytest_cache", ".ruff_cache",
    ".Spotlight-V100", ".svn", ".TemporaryItems", ".tox", ".Trashes",
    ".venv", "__pycache__", "DerivedData", "node_modules", "venv",
}
EXCLUDED_ABSOLUTE_PATHS = {
    Path("/System"),
    Path("/Volumes"),
    Path("/private/var/folders"),
    Path("/private/var/vm"),
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise PermissionError(f"Unsafe state directory: {path}")
    os.chmod(path, 0o700)


def atomic_json(path: Path, value: dict) -> None:
    ensure_private_directory(path.parent)
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


class Progress:
    def __init__(self, title: str, source: str, paths: list[Path]):
        self.state = {
            "id": str(uuid.uuid4()),
            "running": True,
            "phase": "counting",
            "title": title,
            "source": source,
            "startedAt": now(),
            "heartbeatAt": now(),
            "targetPaths": [str(path) for path in paths],
            "totalFiles": 0,
            "scannedFiles": 0,
            "totalBytes": 0,
            "scannedBytes": 0,
            "infectedFiles": 0,
            "errorCount": 0,
            "excludedCount": 0,
            "currentPath": None,
            "estimatedSecondsRemaining": None,
            "filesPerSecond": 0.0,
            "percent": 0.0,
            "message": "Counting files to scan…",
        }
        self.last_write = 0.0
        self.scan_started = 0.0
        self.write(force=True)

    def write(self, *, force: bool = False) -> None:
        current = time.monotonic()
        if not force and current - self.last_write < 0.75:
            return
        self.state["heartbeatAt"] = now()
        atomic_json(STATUS_FILE, self.state)
        self.last_write = current

    def begin_scan(self, total_files: int, total_bytes: int, count_errors: int, excluded: int) -> None:
        self.scan_started = time.monotonic()
        self.state.update({
            "phase": "scanning",
            "totalFiles": total_files,
            "totalBytes": total_bytes,
            "errorCount": count_errors,
            "excludedCount": excluded,
            "message": "ClamAV is scanning files…",
        })
        self.write(force=True)

    def completed_file(self, path: str, size: int, *, infected: bool, error: bool) -> None:
        self.state["scannedFiles"] += 1
        self.state["scannedBytes"] += max(0, size)
        self.state["currentPath"] = path
        if infected:
            self.state["infectedFiles"] += 1
        if error:
            self.state["errorCount"] += 1
        total = max(0, int(self.state["totalFiles"]))
        scanned = max(0, int(self.state["scannedFiles"]))
        if total > 0:
            self.state["percent"] = min(99.9, scanned * 100.0 / total)
        elapsed = max(0.001, time.monotonic() - self.scan_started)
        rate = scanned / elapsed
        self.state["filesPerSecond"] = rate
        if rate > 0 and total >= scanned:
            self.state["estimatedSecondsRemaining"] = int((total - scanned) / rate)
        self.write()

    def finish(self, return_code: int) -> None:
        total = max(0, int(self.state["totalFiles"]))
        if return_code in (0, 1):
            self.state["scannedFiles"] = max(int(self.state["scannedFiles"]), total)
            self.state["percent"] = 100.0
            self.state["phase"] = "completed"
            self.state["message"] = "Scan completed."
        elif return_code in (130, -signal.SIGINT, -signal.SIGTERM):
            self.state["phase"] = "cancelled"
            self.state["message"] = "Scan stopped."
        else:
            self.state["phase"] = "error"
            self.state["message"] = "Scan failed."
        self.state.update({
            "running": False,
            "finishedAt": now(),
            "estimatedSecondsRemaining": 0 if return_code in (0, 1) else None,
            "resultCode": return_code,
        })
        self.write(force=True)


def excluded_directory(path: Path, *, is_selected_root: bool) -> bool:
    if is_selected_root:
        return False
    if path.name in EXCLUDED_DIRECTORY_NAMES:
        return True
    if path in EXCLUDED_ABSOLUTE_PATHS:
        return True
    return len(path.parts) >= 2 and tuple(path.parts[-2:]) == ("Library", "Caches")


def build_manifest(paths: list[Path], progress: Progress, manifest: Path) -> tuple[int, int, int, int]:
    total_files = 0
    total_bytes = 0
    errors = 0
    excluded = 0
    last_update = time.monotonic()
    seen_directories: set[tuple[int, int]] = set()

    def add_file(path: Path, output) -> None:
        nonlocal total_files, total_bytes, errors, excluded
        try:
            info = os.lstat(path)
        except OSError:
            errors += 1
            return
        if stat.S_ISREG(info.st_mode):
            if "\n" in str(path) or "\r" in str(path):
                excluded += 1
                return
            output.write(str(path))
            output.write("\n")
            total_files += 1
            total_bytes += max(0, info.st_size)

    descriptor = os.open(
        manifest,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        for target in paths:
            try:
                info = os.lstat(target)
            except OSError:
                errors += 1
                continue
            if stat.S_ISREG(info.st_mode):
                add_file(target, output)
                continue
            if not stat.S_ISDIR(info.st_mode):
                continue

            def walk_error(_error: OSError) -> None:
                nonlocal errors
                errors += 1

            for root, directories, files in os.walk(target, topdown=True, followlinks=False, onerror=walk_error):
                root_path = Path(root)
                try:
                    root_info = os.lstat(root_path)
                    identity = (root_info.st_dev, root_info.st_ino)
                except OSError:
                    directories[:] = []
                    errors += 1
                    continue
                if identity in seen_directories:
                    directories[:] = []
                    excluded += 1
                    continue
                seen_directories.add(identity)

                retained: list[str] = []
                for name in directories:
                    child = root_path / name
                    if excluded_directory(child, is_selected_root=child in paths):
                        excluded += 1
                        continue
                    try:
                        child_info = os.lstat(child)
                    except OSError:
                        errors += 1
                        continue
                    child_identity = (child_info.st_dev, child_info.st_ino)
                    if child_identity in seen_directories:
                        excluded += 1
                        continue
                    retained.append(name)
                directories[:] = retained

                for name in files:
                    add_file(root_path / name, output)
                if time.monotonic() - last_update >= 0.75:
                    output.flush()
                    progress.state.update({
                        "totalFiles": total_files,
                        "totalBytes": total_bytes,
                        "errorCount": errors,
                        "excludedCount": excluded,
                        "currentPath": str(root_path),
                        "message": f"{total_files:,} files found; counting continues…",
                    })
                    progress.write(force=True)
                    last_update = time.monotonic()
        output.flush()
        os.fsync(output.fileno())
    return total_files, total_bytes, errors, excluded


def completed_path(line: str) -> tuple[str, bool, bool] | None:
    infected = line.endswith(" FOUND")
    error = line.endswith(" ERROR")
    if line.endswith(": OK"):
        return line[:-len(": OK")], False, False
    if not (infected or error):
        return None
    body = line[:-len(" FOUND")] if infected else line[:-len(" ERROR")]
    separator = body.rfind(": ")
    if separator < 0:
        return None
    return body[:separator], infected, error


def file_size(path: str) -> int:
    try:
        info = os.lstat(path)
        return info.st_size if stat.S_ISREG(info.st_mode) else 0
    except OSError:
        return 0


def scanner_command(args: argparse.Namespace, manifest: Path) -> list[str]:
    if args.engine == "clamd":
        return [
            args.scanner,
            f"--config-file={args.clamd_config}",
            "--multiscan",
            f"--file-list={manifest}",
        ]
    return [
        args.scanner,
        f"--file-list={manifest}",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("clamd", "clamscan"), required=True)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--clamd-config", default="")
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    paths = [Path(value).expanduser().absolute() for value in args.paths]
    progress = Progress(args.title, args.source, paths)
    process: subprocess.Popen[str] | None = None
    ensure_private_directory(MANIFEST_DIR)
    manifest = MANIFEST_DIR / f"{progress.state['id']}.files"

    def stop(_signum, _frame) -> None:
        if process is not None and process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    args.log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.log.parent, 0o700)
    with args.log.open("w", encoding="utf-8") as log_file:
        os.chmod(args.log, 0o600)
        log_file.write(f"Start: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"Folders: {' '.join(map(str, paths))}\n")
        log_file.write(f"Engine: {'clamd (ready in memory)' if args.engine == 'clamd' else 'clamscan (fallback)'}\n")
        log_file.flush()
        try:
            total_files, total_bytes, count_errors, excluded = build_manifest(paths, progress, manifest)
            progress.begin_scan(total_files, total_bytes, count_errors, excluded)
            if total_files == 0:
                return_code = 0
                process = None
            else:
                process = subprocess.Popen(
                    scanner_command(args, manifest),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
                assert process.stdout is not None
                in_summary = False
                for raw_line in process.stdout:
                    line = raw_line.rstrip("\n")
                    if line == SUMMARY_MARKER:
                        in_summary = True
                    completed = completed_path(line)
                    if completed is not None:
                        path, infected, error = completed
                        progress.completed_file(path, file_size(path), infected=infected, error=error)
                    if in_summary or completed is None or (completed is not None and (completed[1] or completed[2])):
                        log_file.write(raw_line)
                        log_file.flush()
                return_code = process.wait()
        except Exception as error:
            log_file.write(f"Progress monitor error: {error}\n")
            log_file.flush()
            return_code = 2
        log_file.write(f"End: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.flush()
    progress.finish(return_code)
    try:
        manifest.unlink()
    except FileNotFoundError:
        pass
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
