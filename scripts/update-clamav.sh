#!/bin/zsh

set -u
umask 077

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
LOG_DIR="${HOME}/Library/Logs/ClamAV-Automation"
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR" 2>/dev/null || true
find "$LOG_DIR" -type f -name '*.log' -mtime +30 -delete 2>/dev/null || true

FRESHCLAM="$(command -v freshclam 2>/dev/null || true)"
if [[ -z "$FRESHCLAM" ]]; then
  print -r -- "$(date '+%F %T') ERROR: freshclam not found." >> "$LOG_DIR/update-error.log"
  exit 127
fi

"$FRESHCLAM" --quiet
result=$?

CLAMD_CONFIG="${HOME}/Library/Application Support/ClamAV-Automation/clamd.conf"
if (( result == 0 )) && [[ -f "$CLAMD_CONFIG" ]] && command -v clamdscan >/dev/null 2>&1; then
  clamdscan --config-file="$CLAMD_CONFIG" --reload >/dev/null 2>&1 || true
fi

exit "$result"
