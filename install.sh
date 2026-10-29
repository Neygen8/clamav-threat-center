#!/bin/zsh

set -eu

ROOT_DIR="${0:A:h}"
APP_DIR="${HOME}/Library/Application Support/ClamAV-Automation"
SCRIPT_DIR="${APP_DIR}/scripts"
LOG_DIR="${HOME}/Library/Logs/ClamAV-Automation"
RUNTIME_DIR="${HOME}/Library/Caches/ClamAV-Automation"
QUARANTINE_DIR="${APP_DIR}/Quarantine"
COORDINATION_DIR="${APP_DIR}/coordination"
AGENT_DIR="${HOME}/Library/LaunchAgents"
SERVICE_DIR="${HOME}/Library/Services"
SERVICE_TARGET="${SERVICE_DIR}/ClamAV ile Tara.workflow/Contents"
DOMAIN="gui/$(id -u)"
LEGACY_VT_LABEL="local.neygenx.virustotal-watcher"
LEGACY_VT_AGENT="${AGENT_DIR}/${LEGACY_VT_LABEL}.plist"
LEGACY_VT_APP="${HOME}/Applications/VirusTotal İzleyici.app"
LEGACY_VT_RESULTS="${HOME}/.local/share/vt-download-watcher/results.jsonl"
THREAT_CENTER_APP="${HOME}/Applications/ClamAV Tehdit Merkezi.app"

find_executable() {
  local candidate
  for candidate in "$@"; do
    [[ -x "$candidate" ]] && { print -r -- "$candidate"; return 0; }
  done
  return 1
}

find_python() {
  local candidate
  for candidate in \
    /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 \
    /opt/homebrew/bin/python3 \
    /usr/local/bin/python3; do
    [[ -x "$candidate" ]] || continue
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      print -r -- "$candidate"
      return 0
    fi
  done
  return 1
}

virustotal_status_ready() {
  local python_path="$1" status_path="$2"
  "$python_path" -c '
import datetime, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {"running", "heartbeatAt", "apiKeyConfigured", "watchedPaths", "queueDepth"}
    heartbeat = datetime.datetime.fromisoformat(value["heartbeatAt"])
    age = abs((datetime.datetime.now(datetime.timezone.utc) - heartbeat).total_seconds())
    healthy = value["apiKeyConfigured"] is True and value["running"] is True and age < 30
    intentionally_idle = value["apiKeyConfigured"] is False and value["running"] is False and age < 30
    raise SystemExit(0 if required <= value.keys() and (healthy or intentionally_idle) else 1)
except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
    raise SystemExit(1)
' "$status_path" 2>/dev/null
}

restore_retired_legacy_items() {
  local backup_dir="$1" backup_root backup_agent backup_app restore_failed=0
  [[ -n "$backup_dir" ]] || return 0
  backup_root="${APP_DIR}/Migration Backups"
  [[ "${backup_dir:h}" == "$backup_root" && "${backup_dir:t}" == VirusTotal-İzleyici-* ]] || return 64
  backup_agent="${backup_dir}/${LEGACY_VT_AGENT:t}"
  backup_app="${backup_dir}/${LEGACY_VT_APP:t}"

  if [[ -e "$backup_agent" || -L "$backup_agent" ]]; then
    if [[ -e "$LEGACY_VT_AGENT" || -L "$LEGACY_VT_AGENT" ]]; then
      restore_failed=1
    else
      mkdir -p "$AGENT_DIR"
      /bin/mv -- "$backup_agent" "$LEGACY_VT_AGENT" || restore_failed=1
    fi
  fi
  if [[ -e "$backup_app" || -L "$backup_app" ]]; then
    if [[ -e "$LEGACY_VT_APP" || -L "$LEGACY_VT_APP" ]]; then
      restore_failed=1
    else
      mkdir -p "${LEGACY_VT_APP:h}"
      /bin/mv -- "$backup_app" "$LEGACY_VT_APP" || restore_failed=1
    fi
  fi
  if (( ! restore_failed )); then
    /bin/rmdir -- "$backup_dir" 2>/dev/null || true
  fi
  return "$restore_failed"
}

retire_legacy_virustotal() {
  local backup_root backup_dir backup_agent backup_app stamp
  [[ -e "$LEGACY_VT_AGENT" || -L "$LEGACY_VT_AGENT" || -d "$LEGACY_VT_APP" ]] || return 0
  backup_root="${APP_DIR}/Migration Backups"
  stamp="$(date '+%Y%m%d-%H%M%S')"
  mkdir -p "$backup_root" || return 1
  if [[ -L "$backup_root" || ! -d "$backup_root" || "$(stat -f %u "$backup_root")" != "$(id -u)" ]]; then
    return 1
  fi
  backup_dir="$(/usr/bin/mktemp -d "${backup_root}/VirusTotal-İzleyici-${stamp}.XXXXXX")" || return 1
  if ! chmod 700 "$backup_root" "$backup_dir"; then
    /bin/rmdir -- "$backup_dir" 2>/dev/null || true
    return 1
  fi
  retirement_backup_dir="$backup_dir"
  backup_agent="${backup_dir}/${LEGACY_VT_AGENT:t}"
  backup_app="${backup_dir}/${LEGACY_VT_APP:t}"

  if [[ -e "$LEGACY_VT_AGENT" || -L "$LEGACY_VT_AGENT" ]]; then
    if ! /bin/mv -- "$LEGACY_VT_AGENT" "$backup_agent"; then
      restore_retired_legacy_items "$backup_dir" || true
      return 1
    fi
  fi
  if [[ -d "$LEGACY_VT_APP" ]]; then
    if ! /bin/mv -- "$LEGACY_VT_APP" "$backup_app"; then
      restore_retired_legacy_items "$backup_dir" || true
      return 1
    fi
  fi
  print -r -- "Eski ayrı VirusTotal uygulaması durduruldu ve geri alınabilir biçimde saklandı: $backup_dir"
}

install_automation() {
  local clamd_path clamdscan_path python_path database_dir build_dir build_parent clamd_config target name
  local legacy_vt_was_loaded=0 legacy_vt_app_was_running=0 unified_vt_was_loaded=0
  local vt_ready=0 vt_mutated=0 attempt cleanup_done=0 rollback_in_progress=0
  local vt_script_backup vt_agent_backup retirement_backup_dir=""
  clamd_path="$(find_executable /opt/homebrew/sbin/clamd /usr/local/sbin/clamd)" || {
    print -u2 -- 'HATA: clamd bulunamadı. Önce ClamAV kurulmalı.'
    return 127
  }
  clamdscan_path="$(find_executable /opt/homebrew/bin/clamdscan /usr/local/bin/clamdscan)" || {
    print -u2 -- 'HATA: clamdscan bulunamadı. Önce ClamAV kurulmalı.'
    return 127
  }
  python_path="$(find_python)" || {
    print -u2 -- 'HATA: VirusTotal bileşeni için Python 3.10 veya daha yenisi bulunamadı.'
    return 127
  }
  if [[ -d /opt/homebrew/var/lib/clamav ]]; then
    database_dir=/opt/homebrew/var/lib/clamav
  elif [[ -d /usr/local/var/lib/clamav ]]; then
    database_dir=/usr/local/var/lib/clamav
  else
    print -u2 -- 'HATA: ClamAV imza veritabanı bulunamadı. freshclam çalıştırılmalı.'
    return 66
  fi

  build_parent="${TMPDIR:-/tmp}"
  build_parent="${build_parent%/}"
  [[ -n "$build_parent" ]] || build_parent=/tmp
  build_dir="$(mktemp -d "${build_parent}/clamav-realtime.XXXXXX")"
  vt_script_backup="$build_dir/previous-virustotal-download-watcher.py"
  vt_agent_backup="$build_dir/previous-com.local.clamav.virustotal.plist"

  bootstrap_agent_with_retry() {
    local label="$1" plist_path="$2" bootstrap_attempt
    for bootstrap_attempt in {1..10}; do
      if launchctl bootstrap "$DOMAIN" "$plist_path" 2>/dev/null; then
        return 0
      fi
      # launchd can report a transient EIO immediately after bootout even
      # though the job becomes registered. Treat a verified loaded job as
      # success; otherwise allow the domain a short time to settle.
      if launchctl print "$DOMAIN/$label" >/dev/null 2>&1; then
        sleep 0.2
        launchctl print "$DOMAIN/$label" >/dev/null 2>&1 && return 0
      fi
      sleep 0.2
    done
    launchctl bootstrap "$DOMAIN" "$plist_path"
  }

  wait_for_agent_unloaded() {
    local label="$1" unload_attempt
    for unload_attempt in {1..50}; do
      launchctl print "$DOMAIN/$label" >/dev/null 2>&1 || return 0
      sleep 0.1
    done
    return 1
  }

  rollback_virustotal() {
    local rollback_failed=0
    (( rollback_in_progress )) && return 0
    rollback_in_progress=1
    trap '' HUP INT TERM

    if [[ -n "$retirement_backup_dir" ]]; then
      restore_retired_legacy_items "$retirement_backup_dir" || rollback_failed=1
    fi
    launchctl bootout "$DOMAIN/com.local.clamav.virustotal" 2>/dev/null || true
    if [[ -f "$vt_script_backup" ]]; then
      /usr/bin/install -m 700 "$vt_script_backup" "$SCRIPT_DIR/virustotal-download-watcher.py" || rollback_failed=1
    else
      /bin/rm -f "$SCRIPT_DIR/virustotal-download-watcher.py" || rollback_failed=1
    fi
    if [[ -f "$vt_agent_backup" ]]; then
      /usr/bin/install -m 644 "$vt_agent_backup" "$AGENT_DIR/com.local.clamav.virustotal.plist" || rollback_failed=1
    else
      /bin/rm -f "$AGENT_DIR/com.local.clamav.virustotal.plist" || rollback_failed=1
    fi
    if (( unified_vt_was_loaded )) && [[ -f "$AGENT_DIR/com.local.clamav.virustotal.plist" ]]; then
      bootstrap_agent_with_retry \
        com.local.clamav.virustotal \
        "$AGENT_DIR/com.local.clamav.virustotal.plist" >/dev/null 2>&1 || rollback_failed=1
    fi
    if (( legacy_vt_was_loaded )) && [[ -f "$LEGACY_VT_AGENT" ]]; then
      launchctl bootout "$DOMAIN/$LEGACY_VT_LABEL" 2>/dev/null || true
      bootstrap_agent_with_retry \
        "$LEGACY_VT_LABEL" \
        "$LEGACY_VT_AGENT" >/dev/null 2>&1 || rollback_failed=1
    fi
    if (( legacy_vt_app_was_running )) && [[ -d "$LEGACY_VT_APP" ]]; then
      /usr/bin/open -g "$LEGACY_VT_APP" >/dev/null 2>&1 || rollback_failed=1
    fi
    if (( rollback_failed )); then
      print -u2 -- 'UYARI: VirusTotal geri alma işlemi tam tamamlanamadı; bir kez daha denenecek.'
      vt_mutated=1
    else
      vt_mutated=0
    fi
    rollback_in_progress=0
    return "$rollback_failed"
  }

  stop_legacy_virustotal_processes() {
    local discovered children pid still_running
    local -a app_pids child_pids all_pids
    discovered="$("$python_path" -c '
import ctypes, os, subprocess, sys, unicodedata
expected = unicodedata.normalize("NFC", os.path.realpath(sys.argv[1]))
result = subprocess.run(
    ["/usr/bin/pgrep", "-x", "VirusTotalWatcher"],
    text=True, capture_output=True, check=False,
)
libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
libproc.proc_pidpath.restype = ctypes.c_int
for value in result.stdout.split():
    try:
        process_id = int(value)
    except ValueError:
        continue
    buffer = ctypes.create_string_buffer(4096)
    length = libproc.proc_pidpath(process_id, buffer, len(buffer))
    if length <= 0:
        continue
    actual = unicodedata.normalize("NFC", os.path.realpath(os.fsdecode(buffer.value)))
    if actual == expected:
        print(process_id)
' "$LEGACY_VT_APP/Contents/MacOS/VirusTotalWatcher")" || return 1
    [[ -n "$discovered" ]] || return 0
    legacy_vt_app_was_running=1
    app_pids=("${(@f)discovered}")

    for pid in $app_pids; do
      children="$(/usr/bin/pgrep -P "$pid" 2>/dev/null || true)"
      if [[ -n "$children" ]]; then
        child_pids=("${(@f)children}")
      else
        child_pids=()
      fi
      all_pids+=("$pid" $child_pids)
    done
    /bin/kill -TERM $all_pids 2>/dev/null || true

    for attempt in {1..30}; do
      still_running=0
      for pid in $all_pids; do
        if /bin/kill -0 "$pid" 2>/dev/null; then
          still_running=1
          break
        fi
      done
      (( ! still_running )) && return 0
      sleep 0.2
    done
    return 1
  }

  find_threat_center_processes() {
    "$python_path" -c '
import ctypes, os, subprocess, sys, unicodedata
expected = unicodedata.normalize("NFC", os.path.realpath(sys.argv[1]))
result = subprocess.run(
    ["/usr/bin/pgrep", "-f", "ClamAV Tehdit Merkezi"],
    text=True, capture_output=True, check=False,
)
libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
libproc.proc_pidpath.restype = ctypes.c_int
for value in result.stdout.split():
    try:
        process_id = int(value)
    except ValueError:
        continue
    buffer = ctypes.create_string_buffer(4096)
    length = libproc.proc_pidpath(process_id, buffer, len(buffer))
    if length <= 0:
        continue
    actual = unicodedata.normalize("NFC", os.path.realpath(os.fsdecode(buffer.value)))
    if actual == expected:
        print(process_id)
' "$THREAT_CENTER_APP/Contents/MacOS/ClamAV Tehdit Merkezi"
  }

  stop_threat_center_processes() {
    local discovered attempt
    local -a processes
    discovered="$(find_threat_center_processes)" || return 1
    [[ -n "$discovered" ]] || return 0
    processes=("${(@f)discovered}")
    /bin/kill -TERM $processes 2>/dev/null || true

    for attempt in {1..30}; do
      discovered="$(find_threat_center_processes)" || return 1
      [[ -z "$discovered" ]] && return 0
      sleep 0.2
    done

    # This app does not contain editable documents. If normal termination is
    # ignored, force only the still-running processes whose executable path is
    # exactly the installed Threat Center binary; protection jobs are separate.
    processes=("${(@f)discovered}")
    /bin/kill -KILL $processes 2>/dev/null || true
    for attempt in {1..10}; do
      discovered="$(find_threat_center_processes)" || return 1
      [[ -z "$discovered" ]] && return 0
      sleep 0.2
    done
    return 1
  }

  cleanup_install() {
    local exit_code="${1:-$?}"
    (( cleanup_done )) && return "$exit_code"
    cleanup_done=1
    trap '' HUP INT TERM
    if (( vt_mutated )); then
      rollback_virustotal || rollback_virustotal || true
    fi
    if [[ "${build_dir:h}" == "$build_parent" && "${build_dir:t}" == clamav-realtime.* && -d "$build_dir" ]]; then
      /bin/rm -rf -- "$build_dir"
    fi
    return "$exit_code"
  }

  cleanup_install_on_exit() {
    local exit_code=$?
    cleanup_install "$exit_code"
    return "$exit_code"
  }

  cleanup_install_on_signal() {
    local exit_code="$1"
    trap '' HUP INT TERM
    cleanup_install "$exit_code" || true
    trap - EXIT
    exit "$exit_code"
  }

  trap cleanup_install_on_exit EXIT
  trap 'cleanup_install_on_signal 129' HUP
  trap 'cleanup_install_on_signal 130' INT
  trap 'cleanup_install_on_signal 143' TERM

  if [[ -f "$SCRIPT_DIR/virustotal-download-watcher.py" ]]; then
    /bin/cp -p -- "$SCRIPT_DIR/virustotal-download-watcher.py" "$vt_script_backup"
  fi
  if [[ -f "$AGENT_DIR/com.local.clamav.virustotal.plist" ]]; then
    /bin/cp -p -- "$AGENT_DIR/com.local.clamav.virustotal.plist" "$vt_agent_backup"
  fi
  if launchctl print "$DOMAIN/com.local.clamav.virustotal" >/dev/null 2>&1; then
    unified_vt_was_loaded=1
  fi
  /usr/bin/xcrun swiftc -O -framework CoreServices \
    "$ROOT_DIR/realtime/ClamAVRealtimeProtection.swift" \
    -o "$build_dir/clamav-realtime-protection"

  mkdir -p "$SCRIPT_DIR" "$LOG_DIR" "$RUNTIME_DIR" "$QUARANTINE_DIR" "$COORDINATION_DIR" "$AGENT_DIR" "$SERVICE_TARGET"
  chmod 700 "$APP_DIR" "$SCRIPT_DIR" "$LOG_DIR" "$RUNTIME_DIR" "$QUARANTINE_DIR" "$COORDINATION_DIR"
  find "$LOG_DIR" -type f -exec chmod 600 {} + 2>/dev/null || true
  find "$QUARANTINE_DIR" -type f -exec chmod 600 {} + 2>/dev/null || true

  /usr/bin/install -m 755 "$ROOT_DIR/scripts/update-clamav.sh" "$SCRIPT_DIR/update-clamav.sh"
  /usr/bin/install -m 755 "$ROOT_DIR/scripts/scan-clamav.sh" "$SCRIPT_DIR/scan-clamav.sh"
  /usr/bin/install -m 755 "$ROOT_DIR/scripts/scan-selection.sh" "$SCRIPT_DIR/scan-selection.sh"
  /usr/bin/install -m 755 "$ROOT_DIR/scripts/scan-progress.py" "$SCRIPT_DIR/scan-progress.py"
  /usr/bin/install -m 755 "$build_dir/clamav-realtime-protection" "$SCRIPT_DIR/clamav-realtime-protection"
  vt_mutated=1
  /usr/bin/install -m 700 "$ROOT_DIR/virustotal/vt_download_watcher.py" "$SCRIPT_DIR/virustotal-download-watcher.py"
  /usr/bin/install -m 644 "$ROOT_DIR/quick-action/Info.plist" "$SERVICE_TARGET/Info.plist"
  sed -e "s|__SCRIPT_PATH__|$SCRIPT_DIR/scan-selection.sh|g" \
    "$ROOT_DIR/quick-action/document.wflow" > "$SERVICE_TARGET/document.wflow"
  plutil -lint "$SERVICE_TARGET/Info.plist" "$SERVICE_TARGET/document.wflow" >/dev/null

  if [[ ! -f "$APP_DIR/scan-paths" ]]; then
    print -r -- '$HOME/Desktop' > "$APP_DIR/scan-paths"
    print -r -- '$HOME/Downloads' >> "$APP_DIR/scan-paths"
  fi
  if [[ ! -f "$APP_DIR/realtime-paths" ]]; then
    print -r -- '$HOME/Desktop' > "$APP_DIR/realtime-paths"
    print -r -- '$HOME/Downloads' >> "$APP_DIR/realtime-paths"
  fi
  chmod 600 "$APP_DIR/scan-paths" "$APP_DIR/realtime-paths"

  clamd_config="$APP_DIR/clamd.conf"
  sed -e "s|__LOG_DIR__|$LOG_DIR|g" \
      -e "s|__RUNTIME_DIR__|$RUNTIME_DIR|g" \
      -e "s|__DATABASE_DIR__|$database_dir|g" \
      "$ROOT_DIR/config/clamd.conf" > "$clamd_config"
  chmod 600 "$clamd_config"

  for name in update scan; do
    target="$AGENT_DIR/com.local.clamav.${name}.plist"
    sed -e "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" -e "s|__LOG_DIR__|$LOG_DIR|g" \
      "$ROOT_DIR/launchagents/com.local.clamav.${name}.plist" > "$target"
    plutil -lint "$target" >/dev/null
  done

  target="$AGENT_DIR/com.local.clamav.daemon.plist"
  sed -e "s|__CLAMD_PATH__|$clamd_path|g" \
      -e "s|__CONFIG_FILE__|$clamd_config|g" \
      -e "s|__LOG_DIR__|$LOG_DIR|g" \
      "$ROOT_DIR/launchagents/com.local.clamav.daemon.plist" > "$target"
  plutil -lint "$target" >/dev/null

  target="$AGENT_DIR/com.local.clamav.realtime.plist"
  sed -e "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" -e "s|__LOG_DIR__|$LOG_DIR|g" \
    "$ROOT_DIR/launchagents/com.local.clamav.realtime.plist" > "$target"
  plutil -lint "$target" >/dev/null

  target="$AGENT_DIR/com.local.clamav.virustotal.plist"
  sed -e "s|__PYTHON_PATH__|$python_path|g" \
      -e "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" \
      -e "s|__WATCH_DIR__|$HOME/Downloads|g" \
      -e "s|__LOG_DIR__|$LOG_DIR|g" \
      "$ROOT_DIR/launchagents/com.local.clamav.virustotal.plist" > "$target"
  plutil -lint "$target" >/dev/null

  target="$AGENT_DIR/com.local.clamav.ui.plist"
  sed -e "s|__APP_EXECUTABLE__|$THREAT_CENTER_APP/Contents/MacOS/ClamAV Tehdit Merkezi|g" \
    "$ROOT_DIR/launchagents/com.local.clamav.ui.plist" > "$target"
  plutil -lint "$target" >/dev/null

  /System/Library/CoreServices/pbs -flush >/dev/null 2>&1 || true
  /System/Library/CoreServices/pbs -update >/dev/null 2>&1 || true
  "$ROOT_DIR/scripts/build-app.sh"
  if ! stop_threat_center_processes; then
    print -u2 -- 'HATA: Eski Tehdit Merkezi arayüzü güvenli biçimde kapatılamadı; menü çubuğu güncellemesi başlatılmadı.'
    return 70
  fi

  for name in realtime daemon update scan virustotal ui; do
    launchctl bootout "$DOMAIN/com.local.clamav.${name}" 2>/dev/null || true
  done
  for name in realtime daemon update scan virustotal ui; do
    if ! wait_for_agent_unloaded "com.local.clamav.${name}"; then
      rollback_virustotal || true
      print -u2 -- "HATA: com.local.clamav.${name} görevi güvenli biçimde durdurulamadı."
      return 70
    fi
  done
  for name in update scan daemon realtime; do
    if ! bootstrap_agent_with_retry \
      "com.local.clamav.${name}" \
      "$AGENT_DIR/com.local.clamav.${name}.plist"; then
      rollback_virustotal || true
      print -u2 -- "HATA: com.local.clamav.${name} görevi başlatılamadı; önceki VirusTotal koruması geri yüklendi."
      return 70
    fi
  done
  if launchctl print "$DOMAIN/$LEGACY_VT_LABEL" >/dev/null 2>&1; then
    legacy_vt_was_loaded=1
    launchctl bootout "$DOMAIN/$LEGACY_VT_LABEL" 2>/dev/null || true
  fi
  if ! stop_legacy_virustotal_processes; then
    rollback_virustotal || true
    print -u2 -- 'HATA: Eski VirusTotal izleyicisi güvenli biçimde durdurulamadı; geçiş yapılmadı.'
    return 70
  fi
  # Merge every time the legacy history exists. If a previous installation
  # rolled back, the old watcher may have appended new events in the meantime;
  # the migrator de-duplicates normalized records atomically.
  if [[ -f "$LEGACY_VT_RESULTS" ]]; then
    if ! "$python_path" "$SCRIPT_DIR/virustotal-download-watcher.py" \
      --migrate-log "$LEGACY_VT_RESULTS" \
      --log "$LOG_DIR/virustotal-results.jsonl" >/dev/null; then
      rollback_virustotal || true
      print -u2 -- 'HATA: VirusTotal geçmişi aktarılamadı; eski uygulama korundu.'
      return 70
    fi
  fi
  /bin/rm -f "$APP_DIR/virustotal-status.json"
  if ! bootstrap_agent_with_retry \
    com.local.clamav.virustotal \
    "$AGENT_DIR/com.local.clamav.virustotal.plist"; then
    rollback_virustotal || true
    print -u2 -- 'HATA: Yeni VirusTotal arka plan servisi başlatılamadı; eski uygulama korundu.'
    return 70
  fi

  for attempt in {1..25}; do
    if virustotal_status_ready "$python_path" "$APP_DIR/virustotal-status.json"; then
      vt_ready=1
      break
    fi
    sleep 0.2
  done
  if (( ! vt_ready )); then
    rollback_virustotal || true
    print -u2 -- 'HATA: Yeni VirusTotal servisi durum bilgisi üretemedi; eski uygulama korundu.'
    return 70
  fi
  if ! retire_legacy_virustotal; then
    rollback_virustotal || true
    print -u2 -- 'HATA: Eski VirusTotal bileşenleri güvenli biçimde arşivlenemedi; önceki koruma geri yüklendi.'
    return 70
  fi
  vt_mutated=0

  if ! bootstrap_agent_with_retry \
    com.local.clamav.ui \
    "$AGENT_DIR/com.local.clamav.ui.plist"; then
    print -u2 -- 'UYARI: Sağ üst menü çubuğu simgesi otomatik başlatılamadı; koruma servisleri çalışmaya devam ediyor.'
  fi

  if ! "$clamdscan_path" --config-file="$clamd_config" --ping=30:1 >/dev/null 2>&1; then
    print -u2 -- 'UYARI: ClamAV motoru henüz yanıt vermiyor; launchd yeniden deneyecek.'
  fi

  cleanup_install 0
  trap - EXIT HUP INT TERM

  print -r -- 'ClamAV otomasyonu kuruldu.'
  print -r -- 'Canlı koruma: Masaüstü, İndirilenler ve bağlı diskler'
  print -r -- 'VirusTotal: görünmez arka plan servisi olarak ana kontrol paneline bağlandı'
  print -r -- 'Menü çubuğu: sağ üstte hızlı durum ve kontrol simgesi'
  print -r -- 'Tehdit eylemi: otomatik karantina'
  print -r -- 'Güncelleme: her 6 saatte bir'
  print -r -- 'Tarama: her gün 19:00 (Desktop ve Downloads)'
  print -r -- 'Finder: sağ tık > Hızlı Eylemler > ClamAV ile Tara'
  print -r -- 'Uygulama: ~/Applications/ClamAV Tehdit Merkezi.app'
  print -r -- "Günlükler: $LOG_DIR"
}

uninstall_automation() {
  for name in realtime daemon update scan virustotal ui; do
    launchctl bootout "$DOMAIN/com.local.clamav.${name}" 2>/dev/null || true
    /bin/rm -f "$AGENT_DIR/com.local.clamav.${name}.plist"
  done
  /bin/rm -rf -- "${SERVICE_TARGET:h}"
  /System/Library/CoreServices/pbs -flush >/dev/null 2>&1 || true
  /System/Library/CoreServices/pbs -update >/dev/null 2>&1 || true
  print -r -- "Görevler kaldırıldı. Ayarlar ve günlükler korundu: $APP_DIR"
}

case "${1:-install}" in
  install) install_automation ;;
  uninstall) uninstall_automation ;;
  scan-now) exec "$SCRIPT_DIR/scan-clamav.sh" ;;
  update-now) exec "$SCRIPT_DIR/update-clamav.sh" ;;
  status)
    for name in daemon realtime virustotal update scan ui; do
      print -r -- "--- com.local.clamav.${name} ---"
      if service_state="$(launchctl print "$DOMAIN/com.local.clamav.${name}" 2>/dev/null)"; then
        print -r -- "$service_state" | awk '
          /state =/ && !seen_state++ { print }
          /last exit code/ && !seen_exit++ { print }
        '
      else
        print -r -- 'kurulu değil'
      fi
    done
    ;;
  *) print -u2 -- 'Kullanım: ./install.sh [install|uninstall|scan-now|update-now|status]'; exit 64 ;;
esac
