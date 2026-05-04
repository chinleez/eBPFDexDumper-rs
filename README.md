# eBPFDexDumper-rs

[![CI](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml)
[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

[English](docs/README_EN.md) | 中文

面向 Android 13-17 ARM64 的 eBPF DEX dump 工具。用于在已 root 设备上通过 eBPF/uProbe 捕获 ART 运行时中的 DEX，记录执行过的方法字节码，并可将字节码回填到已 dump 的 DEX。

## 功能

- `dump`：通过 ART 入口、DexFile 注册/构造、CodeItem 反扫、maps 扫描和 native buffer 扫描捕获 DEX。
- `fix`：把记录到的方法字节码回填到 DEX，修复版保留在 `fix/`，最终可用结果汇总到 `final/`。
- `offsets`：从 `libart.so` 定位 hook 目标，必要时可手动指定 ART layout。

## 环境

- 编译：Rust stable、LLVM clang、Android NDK。
- 运行：Android ARM64、root、内核支持 eBPF、可访问 ART `libart.so`。

## 编译

```bash
cargo build
sh build_android.sh
```

## 使用

```bash
./eBPFDexDumper --help
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
su -c './eBPFDexDumper dump -u 10123 -o /data/local/tmp/dex_out'
./eBPFDexDumper fix -d /data/local/tmp/dex_out
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
```

## 说明

`dump` 默认会在退出时执行 `fix`。输出目录中的原始 `dex_*.dex` 会保留；`fix/` 保存成功回填的方法修复版；`final/` 是最终使用目录，有修复版时优先放修复版，没有对应 `_code.json` 或修复失败时放原始 DEX。

默认 ART layout 按 Android 13+ 常见布局处理；ROM 偏移不一致时使用 `--art-layout`。如果目标只在 native 层短暂解密碎片化方法体，内存中不保留连续合法 DEX，需要按壳适配。

## 许可证

`GPL-3.0-or-later`。仓库内 Linux BPF helper 头文件的 BSD-2-Clause 许可证位于 `headers/LICENSE.BSD-2-Clause`。

请只在你有权分析的设备、应用和数据上使用本项目。

## 参考

本项目参考了 [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) 的部分实现逻辑。
