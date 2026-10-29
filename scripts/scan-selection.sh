#!/bin/zsh

set -u
umask 077

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
LOG_DIR="${HOME}/Library/Logs/ClamAV-Automation"
APP_DIR="${HOME}/Library/Application Support/ClamAV-Automation"
LOCK_DIR="${APP_DIR}/scan.lock"
CLAMD_CONFIG="${APP_DIR}/clamd.conf"
PROGRESS_RUNNER="${0:A:h}/scan-progress.py"
TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
LOG_FILE="${LOG_DIR}/selection-${TIMESTAMP}.log"

notify_user() {
  /usr/bin/osascript - "$1" "$2" <<'APPLESCRIPT' >/dev/null 2>&1 || true
on run argv
  display notification (item 2 of argv) with title (item 1 of argv)
end run
APPLESCRIPT
}

mkdir -p "$LOG_DIR"
find "$LOG_DIR" -type f -name 'selection-*.log' -mtime +30 -delete 2>/dev/null || true

CLAMDSCAN="$(command -v clamdscan 2>/dev/null || true)"
CLAMSCAN="$(command -v clamscan 2>/dev/null || true)"
use_daemon=false
if [[ -n "$CLAMDSCAN" && -f "$CLAMD_CONFIG" ]] && \
   "$CLAMDSCAN" --config-file="$CLAMD_CONFIG" --ping=2:1 >/dev/null 2>&1; then
  use_daemon=true
elif [[ -z "$CLAMSCAN" ]]; then
  notify_user "ClamAV scan error" "ClamAV scan engine not found."
  exit 127
fi

if (( $# == 0 )); then
  notify_user "ClamAV scan error" "No files or folders selected."
  exit 64
fi

typeset -a selected_paths
selected_paths=()
for selected_path in "$@"; do
  [[ -e "$selected_path" ]] && selected_paths+=("$selected_path")
done

if (( ${#selected_paths[@]} == 0 )); then
  notify_user "ClamAV scan error" "Selected items could not be accessed."
  exit 66
fi

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  notify_user "ClamAV scan waiting" "Another scan is already running."
  exit 75
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT HUP INT TERM

if [[ ! -x "$PROGRESS_RUNNER" ]]; then
  notify_user "ClamAV scan error" "Scan progress component not found."
  exit 127
fi

if [[ "$use_daemon" == true ]]; then
  nice -n 10 "$PROGRESS_RUNNER" \
    --engine clamd \
    --scanner "$CLAMDSCAN" \
    --clamd-config "$CLAMD_CONFIG" \
    --log "$LOG_FILE" \
    --title "Selected items scan" \
    --source selection \
    -- "${selected_paths[@]}"
else
  nice -n 10 "$PROGRESS_RUNNER" \
    --engine clamscan \
    --scanner "$CLAMSCAN" \
    --log "$LOG_FILE" \
    --title "Selected items scan" \
    --source selection \
    -- "${selected_paths[@]}"
fi
result=$?

case "$result" in
  0)
    notify_user "ClamAV: Clean" "${#selected_paths[@]} items contained no threats."
    ;;
  1)
    infected_count="$(awk -F: '/^Infected files:/{gsub(/[[:space:]]/, "", $2); print $2}' "$LOG_FILE" | tail -n 1)"
    [[ -z "$infected_count" ]] && infected_count="one or more"
    notify_user "ClamAV: Threat found" "Threat count: ${infected_count}. Opening scan log."
    /usr/bin/open -R "$LOG_FILE" >/dev/null 2>&1 || true
    ;;
  *)
    notify_user "ClamAV scan error" "Scan failed. Opening log."
    /usr/bin/open -R "$LOG_FILE" >/dev/null 2>&1 || true
    ;;
esac

exit "$result"
