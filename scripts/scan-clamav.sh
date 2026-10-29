#!/bin/zsh

set -u
umask 077

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
APP_DIR="${HOME}/Library/Application Support/ClamAV-Automation"
LOG_DIR="${HOME}/Library/Logs/ClamAV-Automation"
PATHS_FILE="${APP_DIR}/scan-paths"
LOCK_DIR="${APP_DIR}/scan.lock"
CLAMD_CONFIG="${APP_DIR}/clamd.conf"
PROGRESS_RUNNER="${0:A:h}/scan-progress.py"
TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
LOG_FILE="${LOG_DIR}/scan-${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"
find "$LOG_DIR" -type f -name 'scan-*.log' -mtime +30 -delete 2>/dev/null || true

CLAMDSCAN="$(command -v clamdscan 2>/dev/null || true)"
CLAMSCAN="$(command -v clamscan 2>/dev/null || true)"
use_daemon=false
if [[ -n "$CLAMDSCAN" && -f "$CLAMD_CONFIG" ]] && \
   "$CLAMDSCAN" --config-file="$CLAMD_CONFIG" --ping=2:1 >/dev/null 2>&1; then
  use_daemon=true
elif [[ -z "$CLAMSCAN" ]]; then
  print -r -- "$(date '+%F %T') HATA: ClamAV tarama motoru bulunamadı." > "$LOG_FILE"
  exit 127
fi

typeset -a scan_paths
scan_paths=()

if [[ -n "${CLAMAV_SCAN_PATHS:-}" ]]; then
  scan_paths=("${(@s/:/)CLAMAV_SCAN_PATHS}")
elif [[ -f "$PATHS_FILE" ]]; then
  while IFS= read -r configured_path; do
    [[ -z "$configured_path" || "$configured_path" == \#* ]] && continue
    configured_path="${configured_path//\$HOME/$HOME}"
    [[ -e "$configured_path" ]] && scan_paths+=("$configured_path")
  done < "$PATHS_FILE"
fi

if (( ${#scan_paths[@]} == 0 )); then
  print -r -- "$(date '+%F %T') HATA: Taranacak erişilebilir klasör bulunamadı." > "$LOG_FILE"
  exit 2
fi

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  print -r -- "$(date '+%F %T') HATA: Başka bir ClamAV taraması zaten çalışıyor." > "$LOG_FILE"
  exit 75
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT HUP INT TERM

if [[ ! -x "$PROGRESS_RUNNER" ]]; then
  print -r -- "$(date '+%F %T') HATA: Tarama ilerleme bileşeni bulunamadı." > "$LOG_FILE"
  exit 127
fi

if [[ "$use_daemon" == true ]]; then
  nice -n 10 "$PROGRESS_RUNNER" \
    --engine clamd \
    --scanner "$CLAMDSCAN" \
    --clamd-config "$CLAMD_CONFIG" \
    --log "$LOG_FILE" \
    --title "Hızlı tarama" \
    --source scheduled \
    -- "${scan_paths[@]}"
else
  nice -n 10 "$PROGRESS_RUNNER" \
    --engine clamscan \
    --scanner "$CLAMSCAN" \
    --log "$LOG_FILE" \
    --title "Hızlı tarama" \
    --source scheduled \
    -- "${scan_paths[@]}"
fi
result=$?

if (( result == 1 )); then
  /usr/bin/osascript -e 'display notification "Ayrıntılar ClamAV tarama günlüğünde." with title "ClamAV: Tehdit bulundu" sound name "Basso"' >/dev/null 2>&1 || true
elif (( result > 1 )); then
  /usr/bin/osascript -e 'display notification "Tarama tamamlanamadı; günlüğü kontrol edin." with title "ClamAV tarama hatası"' >/dev/null 2>&1 || true
fi

exit "$result"
