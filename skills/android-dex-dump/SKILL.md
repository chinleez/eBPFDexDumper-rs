---
name: android-dex-dump
description: Dump and validate runtime DEX files from an authorized local APK on a rooted ARM64 Android emulator/device using eBPFDexDumper-rs. Use for local APK runtime capture, APK-vs-runtime DEX comparison, and optional JADX decompilation.
---

# Android runtime DEX dump

Use only for APKs and devices the user is authorized to test. Operate on a local APK and local ADB target; do not download or target third-party apps without explicit authorization.

For the complete automated path, run from the repository root:

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

The script uses `full` with automatic repair first, retries `lifecycle` and `maps-only` when no DEX is found, pulls every attempt, and writes `report.txt`. It never treats tiny fragments as valid DEX. JADX and native `dumpso/fixso` remain opt-in follow-up steps.

## Workflow

1. Identify the APK with `apkanalyzer manifest application-id` and check `adb devices -l` for a usable ARM64 target. If none is listed, inspect local AVDs; do not silently use a remote device.
2. Ensure `target/aarch64-linux-android/release/eBPFDexDumper` exists; build with `sh build_android.sh` if needed.
3. Install with `adb install -r <apk>`, resolve the launcher with `adb shell cmd package resolve-activity --brief <package>`, and explicitly start it with `adb shell am start -n <component>`.
4. Push the binary and run it as root. The default is `--probe-mode full` with automatic `fix` on exit; do not pass `--no-auto-fix` unless the user requests raw-only output. Use `--no-clean-oat` for non-destructive testing. Fall back to `lifecycle` or `maps-only` only when the target exits early, detects uprobes, or a narrower scan is explicitly needed. Use a unique `/data/local/tmp/<slug>_dump` directory.
5. Let the process load code, then pull `final/` (or raw DEX if auto-fix was interrupted) into `/Users/mac/Downloads/<slug>_live_dump/`.
6. Validate each pulled file: `dex\n` magic, header `file_size`, SHA-1, Adler32, and `apkanalyzer dex packages`. Tiny files (a few hundred bytes) or checksum failures are fragments, not usable DEX.
7. Compare SHA-256 hashes against every `classes*.dex` entry in the APK. Report byte-identical files separately from runtime-only files.
8. For JADX, preserve originals and repair checksum only in copies. Write sources to a new `/Users/mac/Downloads/<slug>_jadx_<date>/` directory and report errors.

## Failure handling

- If no DEX is produced, check `pidof`, `logcat`, and whether the launcher crashed or exited before dumping.
- For native `SIGSEGV`, record signal, fault address, API level, and process lifetime; distinguish target initialization failure from dumper failure.
- For ART differences, retry another locally installed ARM64 AVD and report its API level and detected layout.
- Never overwrite the APK or original dump. Keep `--no-clean-oat` unless the user explicitly requests oat cleanup.

## Reporting

Always include package, API/ABI, probe mode, valid DEX count and total size, output path, APK hash comparison, and crash/fragment evidence. Clearly label APK copies, runtime captures, and checksum-repaired analysis copies.
