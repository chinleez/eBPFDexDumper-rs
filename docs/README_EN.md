# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

[中文](../README.md) | English

An authorized Android reverse-engineering tool for rooted ARM64 devices. It captures real DEX files from ART, records executed method bytecode, and can restore that bytecode into dumped files. It also dumps runtime native ELF/`.so` images and recovers dynamically registered JNI names.

## Quick start

Build and push `target/aarch64-linux-android/release/eBPFDexDumper` to a rooted device:

```bash
cargo build
sh build_android.sh
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app
```

The default `dump` mode is `full` and runs `fix` on exit. Use `--no-auto-fix` to disable that behavior. Narrower probe modes are useful when a target checks for uprobes:

```bash
su -c './eBPFDexDumper dump -n com.example.app --probe-mode lifecycle'
su -c './eBPFDexDumper dump -n com.example.app --probe-mode maps-only'
```

## Capabilities

- **`dump`** combines ART lifecycle probes, cross-VMA maps scanning, CodeItem backscan, and native-buffer scanning. It can emit per-method bytecode records and JNI symbol files when `RegisterNatives` is found.
- **`fix`** restores recorded method bodies. Strict mode skips records whose length disagrees with the DEX header; `--force-mismatch` restores legacy truncate/zero-pad behavior.
- **`dumpso`** reads `/proc/<pid>/maps` and process memory with `process_vm_readv`; it does not require eBPF. `--watch` follows newly loaded or changing runtime-decrypted libraries.
- **`fixso`** repairs dumped ELF layout and rebuilds section metadata for IDA/Ghidra. `--symbols` injects recovered JNI names into `.symtab`.
- **`offsets`** inspects ART hook targets and helps prepare manual layout overrides.

## Output

```text
<output>/<package-or-pid>/
├── dex_*.dex                 # raw dumps
├── dex_*_code.json           # bytecode records
├── fix/                      # repaired DEX files
├── final/                    # preferred files for analysis
├── jni_symbols_*.txt         # recovered JNI names, if available
└── native_elf/               # optional anonymous ELF captures
```

`final/` prefers repaired files and falls back to raw dumps. `fix` also prints coverage and writes `*_missed.json` when methods were not captured.

## Native workflow

```bash
su -c './eBPFDexDumper dumpso -n com.example.app -o /data/local/tmp/so_out --watch'
./eBPFDexDumper fixso -d /data/local/tmp/so_out \
  -s /data/local/tmp/dex_out/com.example.app/jni_symbols_libfoo.txt
```

`dumpso` skips system libraries by default; use `--include-system`, `--lib <substring>`, or `--no-anon` to adjust scanning. CompactDex (`cdex`) requires an external cdex-to-dex conversion tool before standard DEX tooling can read it.

## Requirements and limitations

- Android ARM64, root, an eBPF-capable kernel, and readable `/apex/com.android.art/lib64/libart.so`.
- `--clean-oat` is enabled by default and removes the target app's `oat/` directory before dumping. This is destructive; use `--no-clean-oat` to preserve it.
- Cross-VMA DEX scanning and system-DEX filtering are built in. Vendor ART layouts, BTF differences, anti-eBPF checks, or fragmented native decryption may still require target-specific adaptation.
- `full` attaches ART/libc uprobes, `lifecycle` keeps lifecycle probes plus maps scanning, and `maps-only` attaches no uprobes.

## Common commands and development

```bash
./eBPFDexDumper --help
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
./scripts/package-release.sh
cargo fmt --check
cargo test --locked
```

See `--help` for all options, including `--art-layout`, `--register-natives-offset`, `--native-elf-scan`, and scan controls.

## License

`GPL-3.0-or-later`. BPF helper headers are licensed under `headers/LICENSE.BSD-2-Clause`. Use this project only on devices, apps, and data you are authorized to analyze.

Reference implementation: [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper).
