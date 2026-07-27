#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <apk> [output-dir]" >&2
  exit 2
fi

APK=$1
OUT=${2:-"/Users/mac/Downloads/android-dex-$(date +%Y%m%d-%H%M%S)"}
BIN=${DUMPER_BIN:-"$(pwd)/target/aarch64-linux-android/release/eBPFDexDumper"}
ADB=${ADB:-adb}

[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "Dumper binary not found: $BIN" >&2; exit 1; }
mkdir -p "$OUT"

PKG=$(apkanalyzer manifest application-id "$APK" 2>/dev/null || true)
if [[ -z "$PKG" ]]; then
  echo "Cannot read package id with apkanalyzer" >&2
  exit 1
fi

STATE=$($ADB get-state 2>/dev/null || true)
if [[ "$STATE" != "device" ]]; then
  echo "No usable ADB device. Start a local ARM64 emulator and retry." >&2
  exit 1
fi

API=$($ADB shell getprop ro.build.version.sdk | tr -d '\r')
ABI=$($ADB shell getprop ro.product.cpu.abi | tr -d '\r')
$ADB install -r "$APK" >/dev/null
ACT=$($ADB shell cmd package resolve-activity --brief "$PKG" | tail -1 | tr -d '\r')
[[ "$ACT" == */* ]] || { echo "Launcher activity not found for $PKG" >&2; exit 1; }
$ADB push "$BIN" /data/local/tmp/eBPFDexDumper >/dev/null
$ADB shell chmod 755 /data/local/tmp/eBPFDexDumper

REMOTE=/data/local/tmp/android_dex_run_$(date +%s)
$ADB shell "mkdir -p '$REMOTE'"

run_mode() {
  local mode=$1
  $ADB shell am force-stop "$PKG" >/dev/null
  $ADB shell am start -n "$ACT" >/dev/null
  $ADB shell "/data/local/tmp/eBPFDexDumper dump -n '$PKG' -o '$REMOTE/$mode' --no-clean-oat --probe-mode '$mode'"
}

run_mode full || true
COUNT=$($ADB shell "find '$REMOTE/full' -type f -name 'dex_*.dex' 2>/dev/null | wc -l" | tr -d '\r ')
if [[ "$COUNT" == "0" ]]; then
  run_mode lifecycle || true
  COUNT=$($ADB shell "find '$REMOTE/lifecycle' -type f -name 'dex_*.dex' 2>/dev/null | wc -l" | tr -d '\r ')
fi
if [[ "$COUNT" == "0" ]]; then
  run_mode maps-only || true
  COUNT=$($ADB shell "find '$REMOTE/maps-only' -type f -name 'dex_*.dex' 2>/dev/null | wc -l" | tr -d '\r ')
fi

RESULT=$OUT/result
mkdir -p "$RESULT"
for mode in full lifecycle maps-only; do
  $ADB pull "$REMOTE/$mode" "$RESULT/$mode" >/dev/null 2>&1 || true
done

REPORT=$OUT/report.txt
{
  echo "package=$PKG"
  echo "api=$API"
  echo "abi=$ABI"
  echo "launcher=$ACT"
  echo "requested_mode=full"
  echo "fallback_order=full,lifecycle,maps-only"
  echo "output=$OUT"
  echo "dex_files=$(find "$RESULT" -type f -name 'dex_*.dex' 2>/dev/null | wc -l | tr -d ' ')"
  echo "total_bytes=$(find "$RESULT" -type f -name 'dex_*.dex' -exec stat -f '%z' {} + 2>/dev/null | awk '{s+=$1} END{print s+0}')"
  echo
  find "$RESULT" -type f -name 'dex_*.dex' -print 2>/dev/null | while read -r f; do
    size=$(stat -f '%z' "$f")
    magic=$(od -An -j 0 -N 8 -tc "$f" | tr -d ' \n')
    echo "$size $magic $f"
  done
} > "$REPORT"

echo "package: $PKG"
echo "output: $OUT"
echo "report: $REPORT"
echo "DEX files: $(grep '^dex_files=' "$REPORT" | cut -d= -f2)"
