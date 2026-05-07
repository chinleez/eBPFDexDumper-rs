# eBPFDexDumper-rs

[![CI](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml)
[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)
[![License](https://img.shields.io/github/license/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/blob/main/LICENSE)
[![Android](https://img.shields.io/badge/Android-13--17%20ARM64-3DDC84?logo=android&logoColor=white)](https://github.com/chinleez/eBPFDexDumper-rs)
[![GitHub stars](https://img.shields.io/github/stars/chinleez/eBPFDexDumper-rs?style=social)](https://github.com/chinleez/eBPFDexDumper-rs/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/chinleez/eBPFDexDumper-rs?style=social)](https://github.com/chinleez/eBPFDexDumper-rs/network/members)

[中文](../README.md) | English

An eBPF DEX dumper for rooted Android 13-17 ARM64 devices. It captures DEX data from ART with eBPF/uProbe, records executed method bytecode, and can write the recorded bytecode back into dumped DEX files.

## Features

- `dump`: captures DEX through ART entries, DexFile registration/construction, CodeItem backscan, maps scan, and native buffer scan.
- `fix`: writes recorded method bytecode back into DEX files, keeps repaired copies under `fix/`, and gathers usable outputs under `final/`.
- `offsets`: resolves hook targets from `libart.so`; manual ART layout is supported when needed.

## Requirements

- Build: Rust stable, LLVM clang, Android NDK.
- Runtime: Android ARM64, root, eBPF-capable kernel, accessible ART `libart.so`.
- On macOS, LLVM clang is recommended:

```bash
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang
```

## Build

```bash
cargo build
sh build_android.sh
```

Android output:

```text
target/aarch64-linux-android/release/eBPFDexDumper
```

## Usage

```bash
./eBPFDexDumper --help

su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
su -c './eBPFDexDumper dump -u 10123 -o /data/local/tmp/dex_out'
su -c './eBPFDexDumper dump -n com.example.app --probe-mode lifecycle'
su -c './eBPFDexDumper dump -n com.example.app --native-elf-scan'

./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app --force-mismatch
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
```

Useful `dump` options:

- `--pid <PID>`: restrict tracing to one process in addition to UID/package filtering.
- `--no-clean-oat`: do not clean OAT files.
- `--no-auto-fix`: do not auto-fix after dumping.
- `--debug-layout`: print ART layout diagnostics.
- `--no-code-item-fallback` / `--no-maps-scan` / `--no-native-buffer-scan`: disable fallback paths.
- `--native-elf-scan`: experimental scan for anonymous executable ARM64 ELF candidates from native loader behavior.
- `--probe-mode full|lifecycle|maps-only`: reduce the attached probe set when a target performs uprobe checks.
- `--libc <PATH>`: set the bionic libc path.
- `--art-layout <LIST>`: provide ART field offsets manually.

Useful `fix` options:

- `--force-mismatch`: fall back to the legacy "truncate / zero-pad" behaviour when a record's hex-decoded length does not match the DEX header's `insns_size * 2`. Off by default — mismatched records are skipped because padding can corrupt the bytecode stream.

`--art-layout` order:

```text
ShadowFrame.method,ArtMethod.declaring_class,ArtMethod.dex_method_index,ArtMethod.data,Class.dex_cache,DexCache.dex_file,DexFile.begin,DexHeader.file_size,CodeItem.insns_size,CodeItem.insns
```

## Package

```bash
./scripts/package-release.sh
```

Outputs under `dist/`:

- `eBPFDexDumper_android_arm64`
- `eBPFDexDumper_android_arm64.sha256`
- `eBPFDexDumper_android_arm64.tar.gz`

## Notes

### Output layout and auto-fix

`dump` writes everything for one target into a per-target subdirectory under `-o`: `--name` uses the package name (e.g. `com.example.app/`), `--pid`-only falls back to `/proc/<pid>/cmdline` and then `pid_<num>/`, `--uid`-only uses `uid_<num>/`. The subdirectory holds `dex_*.dex` (raw dumps), `dex_*_code.json` (per-method bytecode records), `fix/`, `final/`, plus `native_elf/` when `--native-elf-scan` is enabled.

`dump` runs `fix` on exit by default (use `--no-auto-fix` to disable). The original `dex_*.dex` files always remain. `fix/` stores the repaired DEX for each base; `final/` is the usable result set, preferring the repaired copy and falling back to the original dump when no matching `_code.json` exists or repair fails.

### `fix` behaviour

Strict by default: a record whose hex-decoded length does not match the DEX header's `insns_size * 2` is skipped instead of being truncated / zero-padded into the bytecode stream. Pass `--force-mismatch` to restore the legacy lossy behaviour.

`fix` also produces a method-bytecode coverage report. The console prints one `Coverage: A/B methods (P%), N missed` line per DEX, where the denominator counts every method with `code_off != 0` (abstract / native methods are excluded). When at least one method is missed, the full list is written to `final/<base>_missed.json` with `method_idx`, `code_off`, and a best-effort pretty signature for each missed method, so you can decide whether to extend the trace window and re-run.

### `--clean-oat` (destructive default)

`--clean-oat` is **on by default** and removes the target app's `/data/app/.../oat/` directories before dumping to force ART back into the interpreter. **This is destructive** — pass `--no-clean-oat` to keep them.

### Targeting: ART layout and probe modes

The default ART layout targets common Android 13+ layouts. Use `--art-layout` when a ROM uses different offsets. If a target only decrypts fragmented method bodies briefly in native code and never keeps a continuous valid DEX in memory, packer-specific hooks are still required.

`full` is the default mode and attaches ART plus libc uprobes. `lifecycle` keeps only DexFile lifecycle probes and maps scan. `maps-only` attaches no uprobes and only scans `/proc/<pid>/maps`. Uprobes can still leave detectable breakpoint-style traces in the target mapping, so use the narrower modes for targets with strong anti-uprobe checks.

### Experimental options

`--native-elf-scan` reuses libc `mmap`/`mprotect` events to identify anonymous executable ARM64 ELF candidates and saves them under `native_elf/` in the target output directory. It is an auxiliary diagnostic path for hidden native loaders and does not change the default DEX dump or fix flow.

## License

`GPL-3.0-or-later`. The Linux BPF helper headers carry a BSD-2-Clause license at `headers/LICENSE.BSD-2-Clause`.

Use this project only on devices, apps, and data you are authorized to analyze.

## Reference

This project references part of the implementation logic from [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper).
