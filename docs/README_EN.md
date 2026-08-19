# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)

[中文](../README.md) | English

An authorized Android reverse-engineering tool controlled from Windows, macOS, or Linux PCs. It captures real DEX files from ART on rooted ARM64 Android targets, records executed method bytecode, and restores it into dumped files. It also dumps runtime native `.so` images and recovers dynamically registered JNI names. The PC is the host; live capture still requires Android ART, root, and eBPF on the target.

## Quick start

```bash
cargo build                # local debug build
sh build_android.sh        # Android ARM64 release
cargo ndk -t arm64-v8a build --release  # Windows/cross-platform (cargo-ndk + Android NDK)
```

On a PC host, `cargo build` is suitable for offline `fix`, `fixso`, `offsets`, and DEX/ELF analysis. Live `dump`/`dumpso` still require the Android ARM64 release binary to run on the target.

Push `target/aarch64-linux-android/release/eBPFDexDumper` to a rooted device with eBPF support:

```bash
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

The default `full` mode automatically fixes DEX files on exit and produces `final/`. To fix manually:

```bash
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app
```

## Subcommands

- **`dump`** captures DEX via ART lifecycle probes, maps scanning, CodeItem backscan, and native-buffer scanning; records executed method bytecode and can recover JNI names.
- **`fix`** restores recorded method bodies and reports coverage. Length mismatches are skipped by default; `--force-mismatch` writes them anyway.
- **`dumpso`** dumps native `.so` files from `/proc/<pid>/maps` with `process_vm_readv` (no eBPF); `--watch` follows runtime-decrypted or newly loaded libraries.
- **`fixso`** repairs segment offsets and rebuilds the section table from `PT_DYNAMIC`; `--symbols` injects JNI names.
- **`offsets`** inspects `libart.so` hook targets and ART layout for adapting to different ROMs.

## Output

```text
<output>/<package-or-pid>/
├── dex_*.dex               # raw DEX
├── dex_*_code.json         # bytecode records
├── fix/                    # repaired DEX
├── final/                  # preferred for analysis
├── jni_symbols_*.txt       # JNI names (optional)
└── native_elf/             # anonymous ELF (optional)
```

## Common options

- `--probe-mode full|lifecycle|maps-only`: controls probe coverage; `maps-only` attaches no uprobes.
- `--clean-oat` (enabled by default): removes the target app's `oat/` before dumping; use `--no-clean-oat` to keep it.
- `--no-maps-scan` / `--no-native-buffer-scan` / `--native-elf-scan`: toggle scans.
- `--art-layout` / `--register-natives-offset`: manual overrides for incompatible ROMs.
- See `./eBPFDexDumper --help` for all options.

## Limitations

- Designed for common Android 13+ ARM64 ART layouts; vendor ROMs may differ in offsets, BTF, or eBPF behavior. Run `offsets` first when adapting.
- CompactDex (`cdex`) must be converted to standard DEX with an external tool first.
- uprobes can be detected by anti-debugging; no guarantees against all protections.
- `dumpso` skips `/system`, `/apex`, `/vendor`, and similar libraries by default; use `--include-system` or `--lib` when needed.

## Development and testing

```bash
cargo fmt --check
cargo test --locked
sh build_android.sh
```

## Project skill

The repository provides a [PC Android DEX dump skill](../skills/android-dex-dump/SKILL.md) that automates installing, launching, dumping, and validating a local APK from Windows, macOS, or Linux:

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

On Windows PowerShell:

```powershell
.\skills\android-dex-dump\scripts\run_dump.ps1 C:\path\to\app.apk
```

Both wrappers call the same cross-platform `run_dump.py`, which tries `full → lifecycle → maps-only` in order and writes results plus `report.txt` to a new directory under the host's Downloads. The host needs Python 3.9+, ADB, and either `apkanalyzer` or Android SDK `aapt`; use only with APKs and devices you are authorized to test.

## License

`GPL-3.0-or-later`; BPF helper headers are BSD-2-Clause. Use this project only on devices, apps, and data you are authorized to analyze.

Reference implementation: [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper).
