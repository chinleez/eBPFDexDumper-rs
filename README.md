# eBPFDexDumper-rs

[![CI](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml)
[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)
[![License](https://img.shields.io/github/license/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/blob/main/LICENSE)
[![Android](https://img.shields.io/badge/Android-13--17%20ARM64-3DDC84?logo=android&logoColor=white)](https://github.com/chinleez/eBPFDexDumper-rs)
[![GitHub stars](https://img.shields.io/github/stars/chinleez/eBPFDexDumper-rs?style=social)](https://github.com/chinleez/eBPFDexDumper-rs/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/chinleez/eBPFDexDumper-rs?style=social)](https://github.com/chinleez/eBPFDexDumper-rs/network/members)

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
su -c './eBPFDexDumper dump -n com.example.app --probe-mode lifecycle'
su -c './eBPFDexDumper dump -n com.example.app --native-elf-scan'
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app --force-mismatch
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
```

## 说明

### 输出目录与 auto-fix

`dump` 会在 `-o` 指定的根目录下按目标自动建子目录：`--name` 用包名（如 `com.example.app/`），仅 `--pid` 时用 `/proc/<pid>/cmdline` 推断，回落 `pid_<num>/`，仅 `--uid` 时用 `uid_<num>/`。子目录里会落入 `dex_*.dex`（原始 dump）、`dex_*_code.json`（方法字节码记录）、`fix/`、`final/`，开 `--native-elf-scan` 时还有 `native_elf/`。

`dump` 默认会在退出时执行 `fix`（`--no-auto-fix` 关闭）。原始 `dex_*.dex` 始终保留；`fix/` 存放回填后的 DEX；`final/` 是最终使用目录，对每个 base 优先放 `fix/` 里的修复版，缺 `_code.json` 或修复失败时退回原始 DEX。

### `fix` 行为

默认严格模式：当 record 的字节长度与 DEX 头里 `insns_size * 2` 不一致时跳过该 record，避免补 0/截断破坏指令流；如需保留旧的截断/补零行为，加 `--force-mismatch`。

`fix` 同时会输出方法覆盖率报告：控制台打印 `Coverage: A/B methods (P%), N missed` 一行，统计 DEX 里所有 `code_off != 0` 的方法（abstract/native 不计）；当存在未抓到的方法时，详细清单写入 `final/<base>_missed.json`，每条含 `method_idx`、`code_off` 和（尽量解析到的）方法签名，便于判断是否需要扩大 trace 窗口再跑一次。

### `--clean-oat`（破坏性默认）

`--clean-oat` 默认开启，会在 dump 前删除目标 app `/data/app/.../oat/` 目录以强制 ART 走解释器。**这是有破坏性的默认行为**（删除会保留到下次 oat 重建），要保留 oat 加 `--no-clean-oat`。

### 适配：ART layout 与探针模式

默认 ART layout 按 Android 13+ 常见布局处理；ROM 偏移不一致时使用 `--art-layout`。如果目标只在 native 层短暂解密碎片化方法体，内存中不保留连续合法 DEX，需要按壳适配。

`--probe-mode full|lifecycle|maps-only` 用于按场景收窄探针面：`full` 为默认全量 ART/libc uprobe；`lifecycle` 只保留 DexFile 生命周期探针和 maps 扫描；`maps-only` 不挂 uprobe，只做 `/proc/<pid>/maps` 内存扫描。uprobe 在目标映射上仍可能留下可检测痕迹，强反调试目标可先尝试 `lifecycle` 或 `maps-only`。

### 实验选项

`--native-elf-scan` 会复用 libc `mmap`/`mprotect` 事件识别匿名可执行 ARM64 ELF 候选块，并保存到输出子目录的 `native_elf/`。它只作为隐藏 native loader 行为的辅助排查，不影响默认 DEX dump 和回填流程。

---

完整选项见 `--help`，包括 `-p/--pid`、`-t/--trace`、`--debug-layout`、`--no-code-item-fallback`、`--no-maps-scan`、`--no-native-buffer-scan`、`--libc` 等。

## 许可证

`GPL-3.0-or-later`。仓库内 Linux BPF helper 头文件的 BSD-2-Clause 许可证位于 `headers/LICENSE.BSD-2-Clause`。

请只在你有权分析的设备、应用和数据上使用本项目。

## 参考

本项目参考了 [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) 的部分实现逻辑。
