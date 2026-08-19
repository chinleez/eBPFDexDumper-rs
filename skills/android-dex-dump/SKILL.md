---
name: android-dex-dump
description: From a Windows, macOS, or Linux PC, dump and validate runtime DEX files from an authorized local APK on a rooted ARM64 Android emulator/device using eBPFDexDumper-rs. Use for local APK runtime capture, APK-vs-runtime DEX comparison, and optional JADX decompilation.
---

# Android runtime DEX dump from PC

Use only for APKs and devices the user is authorized to test. The PC is the host that runs this workflow; the live target remains a rooted ARM64 Android emulator/device. Do not download or target third-party apps without explicit authorization.

## Host support

- Windows 10/11: use PowerShell and Python 3.9+ with `run_dump.ps1`.
- macOS/Linux: use Python 3.9+ with `run_dump.sh` (the shell file is a thin wrapper around the same cross-platform implementation).
- All hosts need Android platform-tools (`adb`), a local ARM64 Android target, and either `apkanalyzer` or Android SDK `aapt`.
- The target still needs root, eBPF support, and the Android ARM64 release binary. Host PC support does not make live ART/eBPF dumping available for Windows, macOS, or ordinary desktop Linux processes.

From the repository root, run the complete automated path with the host-native wrapper:

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

```powershell
.\skills\android-dex-dump\scripts\run_dump.ps1 C:\path\to\app.apk
```

Both wrappers call `run_dump.py`. It uses `full` with automatic repair first, retries `lifecycle` and `maps-only` when no DEX is found, pulls every attempt, and writes `report.txt`; validate magic, header size, and checksums before treating a pulled file as usable DEX. JADX and native `dumpso/fixso` remain opt-in follow-up steps.

## Workflow

1. Identify the APK with `apkanalyzer manifest application-id` (or SDK `aapt dump badging`) and check `adb devices -l` for a usable ARM64 target. If none is listed, inspect local AVDs; do not silently use a remote device.
2. Ensure `target/aarch64-linux-android/release/eBPFDexDumper` exists; on macOS/Linux build with `sh build_android.sh`, or on Windows use `cargo ndk -t arm64-v8a build --release` (with the Android NDK and `cargo-ndk` installed) or build through WSL.
3. Install with `adb install -r <apk>`, resolve the launcher with `adb shell cmd package resolve-activity --brief <package>`, and explicitly start it with `adb shell am start -n <component>`.
4. Push the binary and run it as root. The default is `--probe-mode full` with automatic `fix` on exit; do not pass `--no-auto-fix` unless the user requests raw-only output. Use `--no-clean-oat` for non-destructive testing. Fall back to `lifecycle` or `maps-only` only when the target exits early, detects uprobes, or a narrower scan is explicitly needed. Use a unique `/data/local/tmp/<slug>_dump` directory.
5. Let the process load code, then pull `final/` (or raw DEX if auto-fix was interrupted) into the host's `Downloads/<slug>_live_dump/` directory.
6. Validate each pulled file: `dex\n` magic, header `file_size`, SHA-1, Adler32, and `apkanalyzer dex packages`. Tiny files (a few hundred bytes) or checksum failures are fragments, not usable DEX.
7. Compare SHA-256 hashes against every `classes*.dex` entry in the APK. Report byte-identical files separately from runtime-only files.
8. For JADX, preserve originals and repair checksum only in copies. Write sources to a new host `Downloads/<slug>_jadx_<date>/` directory and report errors.

## Failure handling

- If no DEX is produced, check `pidof`, `logcat`, and whether the launcher crashed or exited before dumping.
- For native `SIGSEGV`, record signal, fault address, API level, and process lifetime; distinguish target initialization failure from dumper failure.
- For ART differences, retry another locally installed ARM64 AVD and report its API level and detected layout.
- Never overwrite the APK or original dump. Keep `--no-clean-oat` unless the user explicitly requests oat cleanup.

## Reporting

Always include package, API/ABI, probe mode, valid DEX count and total size, output path, APK hash comparison, and crash/fragment evidence. Clearly label APK copies, runtime captures, and checksum-repaired analysis copies.
