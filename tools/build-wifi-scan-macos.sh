#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$project_dir/target/release"}
bundle="$output_dir/Air Wi-Fi Scan.app"
mkdir -p "$bundle/Contents/MacOS"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.aircrack-rs.wifi-scan</string>
<key>CFBundleName</key><string>Air Wi-Fi Scan</string>
<key>CFBundleDisplayName</key><string>Air Wi-Fi Scan</string>
<key>CFBundleExecutable</key><string>air-wifi-scan-macos</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
<key>NSLocationUsageDescription</key><string>Show Wi-Fi network names and BSSIDs in your local Wi-Fi overview. No location or scan data is uploaded.</string>
<key>NSLocationWhenInUseUsageDescription</key><string>Show Wi-Fi network names and BSSIDs in your local Wi-Fi overview. No location or scan data is uploaded.</string>
</dict></plist>
PLIST
/usr/bin/swiftc "$project_dir/tools/air-wifi-scan-macos.swift" \
  -framework CoreWLAN -framework CoreLocation -framework AppKit \
  -module-cache-path "${TMPDIR:-/tmp}/air-wifi-scan-swift-cache" \
  -o "$bundle/Contents/MacOS/air-wifi-scan-macos"
/usr/bin/codesign --force --sign - "$bundle"
printf 'Built %s\n' "$bundle"
