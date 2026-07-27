# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)

当前版本：`v0.2.3`

[English](docs/README_EN.md) | 中文

在已 root 的 Android ARM64 设备上，从 ART 运行时捕获真实 DEX，并把执行过的方法字节码回填到 dump 文件。工具也支持运行时 native ELF/`.so` dump 和 JNI 动态注册名恢复，适合授权的 Android 逆向与安全研究。

## 快速开始

### 构建

```bash
cargo build                         # 本机调试
sh build_android.sh                 # Android ARM64 release
```

将 `target/aarch64-linux-android/release/eBPFDexDumper` 推到设备后运行。设备需要 root、eBPF 支持，并能读取 `/apex/com.android.art/lib64/libart.so`。

### Dump DEX

```bash
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

默认模式是 `full`，退出时自动执行修复。常用变体：

```bash
su -c './eBPFDexDumper dump -n com.example.app --probe-mode lifecycle'
su -c './eBPFDexDumper dump -n com.example.app --probe-mode maps-only'
su -c './eBPFDexDumper dump -u 10123 -o /data/local/tmp/dex_out'
```

### 查看结果或手动修复

```bash
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app
```

`dump` 保留原始 DEX；修复结果在 `fix/`，最终优先使用修复版的文件在 `final/`。使用 `--no-auto-fix` 可关闭退出时自动修复。

## 能做什么

- **`dump`**：组合 ART 生命周期探针、跨 VMA 内存扫描、CodeItem 反扫和 native buffer 扫描捕获 DEX。可记录执行过的方法字节码；定位到 `RegisterNatives` 时还会写出 JNI 名称。
- **`fix`**：按记录回填方法体并生成覆盖率报告。默认拒绝长度不一致的记录；需要兼容旧的截断/补零行为时使用 `--force-mismatch`。
- **`dumpso`**：通过 `/proc/<pid>/maps` 与 `process_vm_readv` dump native `.so`，不依赖 eBPF；`--watch` 可持续抓取运行时解密或新加载的库。
- **`fixso`**：修复段偏移并从 `PT_DYNAMIC` 重建 section table，使 IDA/Ghidra 更容易加载；`--symbols` 可把 JNI 名注入 `.symtab`。
- **`offsets`**：检查 `libart.so` 中的 hook 目标和 ART 布局，ROM 不兼容时辅助生成手动参数。

## 输出目录

```text
<output>/<package-or-pid>/
├── dex_*.dex                 # 原始 dump
├── dex_*_code.json           # 方法字节码记录
├── fix/                      # fix 生成的 DEX
├── final/                    # 推荐交给分析工具的结果
├── jni_symbols_*.txt         # 动态注册 JNI 名（若捕获到）
└── native_elf/               # --native-elf-scan 的匿名 ELF（可选）
```

`final/` 对每个 DEX 优先放 `fix/` 版本；修复失败或没有记录时回退到原始文件。`fix` 还会输出方法覆盖率和 `*_missed.json` 未捕获清单。

## 推荐工作流

1. 先用默认 `full` 冷启动目标应用，得到业务 DEX。
2. 目标有强反调试迹象时尝试 `lifecycle`；只想扫已映射内存时使用 `maps-only`（不挂 uprobe）。
3. 需要 native 分析时执行：

   ```bash
   su -c './eBPFDexDumper dumpso -n com.example.app -o /data/local/tmp/so_out --watch'
   ./eBPFDexDumper fixso -d /data/local/tmp/so_out \
     -s /data/local/tmp/dex_out/com.example.app/jni_symbols_libfoo.txt
   ```

4. 若 ART 使用 CompactDex（`cdex`），先用外部工具转换为标准 DEX。

## 关键行为与限制

- `--clean-oat` 默认开启：dump 前删除目标应用的 `oat/` 目录，帮助 ART 走解释器，但这是破坏性操作；保留 oat 使用 `--no-clean-oat`。
- 系统 framework/APEX DEX 仅在完整地址范围都属于系统映射时跳过；跨连续 VMA 的业务 DEX 会被合并扫描。
- `dumpso` 默认过滤 `/system`、`/apex`、`/vendor` 等系统库；需要时加 `--include-system`，或用 `--lib <substring>` 限定库名。
- uprobe 可能留下可检测痕迹；工具不能保证绕过所有反调试、厂商 ART 分支或内核限制。

## 兼容性说明

项目针对 Android 13+ ARM64 的常见 ART 布局设计，并包含跨 VMA 扫描、系统 DEX 过滤和 ART 偏移探测。不同厂商 ROM 可能存在 ART 字段偏移、BTF 或内核 eBPF 差异；遇到这类情况可先运行 `offsets`，再指定 `--art-layout` 或相应 BTF 资产。兼容性不应理解为对所有 ROM 的保证。

## 常用选项

完整参数请查看 `./eBPFDexDumper --help`。常用选项包括 `-p/--pid`、`-u/--uid`、`-t/--trace`、`--probe-mode`、`--no-maps-scan`、`--no-native-buffer-scan`、`--native-elf-scan`、`--debug-layout`、`--register-natives-offset` 和 `--libc`。

## 开发与测试

```bash
cargo fmt --check
cargo test --locked
sh build_android.sh
```

## 安全边界与许可证

仅在你有权分析的应用、设备和数据上使用。项目采用 `GPL-3.0-or-later`；仓库内 BPF helper 头文件遵循 `headers/LICENSE.BSD-2-Clause`。部分实现参考 [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper)。
