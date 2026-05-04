# eBPFDexDumper-rs

[![CI](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml)
[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

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

./eBPFDexDumper fix -d /data/local/tmp/dex_out
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
```

Useful options:

- `--pid <PID>`: restrict tracing to one process in addition to UID/package filtering.
- `--no-clean-oat`: do not clean OAT files.
- `--no-auto-fix`: do not auto-fix after dumping.
- `--debug-layout`: print ART layout diagnostics.
- `--no-code-item-fallback` / `--no-maps-scan` / `--no-native-buffer-scan`: disable fallback paths.
- `--libc <PATH>`: set the bionic libc path.
- `--art-layout <LIST>`: provide ART field offsets manually.

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

`dump` runs `fix` on exit by default. The original `dex_*.dex` files remain in the output directory; `fix/` stores repaired copies when bytecode records can be applied; `final/` is the usable result set, preferring repaired DEX files and falling back to original dumps when no matching `_code.json` exists or repair fails.

The default ART layout targets common Android 13+ layouts. Use `--art-layout` when a ROM uses different offsets. If a target only decrypts fragmented method bodies briefly in native code and never keeps a continuous valid DEX in memory, packer-specific hooks are still required.

## License

`GPL-3.0-or-later`. The Linux BPF helper headers carry a BSD-2-Clause license at `headers/LICENSE.BSD-2-Clause`.

Use this project only on devices, apps, and data you are authorized to analyze.

## Reference

This project references part of the implementation logic from [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper).
