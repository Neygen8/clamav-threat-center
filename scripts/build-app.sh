#!/bin/zsh

set -eu

ROOT_DIR="${0:A:h:h}"
APP_PARENT="${HOME}/Applications"
APP_BUNDLE="${APP_PARENT}/ClamAV Tehdit Merkezi.app"
CONTENTS_DIR="${APP_BUNDLE}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
ICON_SOURCE="${ROOT_DIR}/app/Assets/ClamAVThreatCenterIcon.png"

mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
/usr/bin/xcrun swiftc \
  -parse-as-library \
  -target "$(uname -m)-apple-macosx13.0" \
  -O \
  -framework SwiftUI \
  -framework AppKit \
  "$ROOT_DIR/app/ClamAVThreatCenter.swift" \
  -o "$MACOS_DIR/ClamAV Tehdit Merkezi"

/usr/bin/install -m 644 "$ROOT_DIR/app/Info.plist" "$CONTENTS_DIR/Info.plist"
/usr/bin/install -m 644 "$ROOT_DIR/app/PkgInfo" "$CONTENTS_DIR/PkgInfo"
if [[ -f "$ICON_SOURCE" ]]; then
  ICON_WORK_DIR="$(/usr/bin/mktemp -d /tmp/clamav-app-icon.XXXXXX)"
  trap '/bin/rm -rf -- "$ICON_WORK_DIR"' EXIT HUP INT TERM
  ICONSET_DIR="$ICON_WORK_DIR/ClamAVThreatCenter.iconset"
  ICON_MASTER="$ICON_WORK_DIR/icon-master.png"
  mkdir -p "$ICONSET_DIR"
  icon_width="$(/usr/bin/sips -g pixelWidth "$ICON_SOURCE" | /usr/bin/awk '/pixelWidth:/ {print $2}')"
  icon_height="$(/usr/bin/sips -g pixelHeight "$ICON_SOURCE" | /usr/bin/awk '/pixelHeight:/ {print $2}')"
  icon_square="$icon_width"
  (( icon_height < icon_square )) && icon_square="$icon_height"
  /usr/bin/sips -c "$icon_square" "$icon_square" "$ICON_SOURCE" --out "$ICON_MASTER" >/dev/null
  for spec in \
    '16 icon_16x16.png' '32 icon_16x16@2x.png' \
    '32 icon_32x32.png' '64 icon_32x32@2x.png' \
    '128 icon_128x128.png' '256 icon_128x128@2x.png' \
    '256 icon_256x256.png' '512 icon_256x256@2x.png' \
    '512 icon_512x512.png' '1024 icon_512x512@2x.png'; do
    size="${spec%% *}"
    name="${spec#* }"
    /usr/bin/sips -z "$size" "$size" "$ICON_MASTER" --out "$ICONSET_DIR/$name" >/dev/null
  done
  /usr/bin/iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/ClamAVThreatCenter.icns"
  /usr/bin/install -m 644 "$ICON_SOURCE" "$RESOURCES_DIR/ClamAVThreatCenterIcon.png"
fi
/usr/bin/codesign --force --deep --sign - "$APP_BUNDLE" >/dev/null
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f "$APP_BUNDLE" >/dev/null 2>&1 || true

print -r -- "Uygulama kuruldu: $APP_BUNDLE"
