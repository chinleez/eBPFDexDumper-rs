# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)

[English](docs/README_EN.md) | 中文

在 Windows、macOS 或 Linux PC 上连接已 root 的 Android ARM64 设备，从 ART 运行时抓取真实 DEX，把执行过的方法字节码回填到 dump 文件；也支持 native `.so` dump 和 JNI 动态注册名恢复。PC 仅作为控制端，实时抓取仍依赖 Android ART、root 和 eBPF。仅用于授权的 Android 逆向与安全研究。

## 快速开始

```bash
cargo build                # 本机调试
sh build_android.sh        # Android ARM64 release
cargo ndk -t arm64-v8a build --release  # Windows/跨平台（需 cargo-ndk + Android NDK）
```

PC 主机上的 `cargo build` 可用于离线 `fix`、`fixso`、`offsets` 和 DEX/ELF 分析；实时 `dump`/`dumpso` 需要把 Android ARM64 release binary 放到目标设备执行。

把 `target/aarch64-linux-android/release/eBPFDexDumper` 推到设备（需 root + eBPF）：

```bash
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

默认 `full` 模式，退出时自动修复并生成 `final/`；手动修复：

```bash
./eBPFDexDumper fix -d /data/local/tmp/dex_out/com.example.app
```

## 子命令

- **`dump`**：用 ART 生命周期探针、maps 扫描、CodeItem 反扫和 native buffer 扫描抓 DEX，记录执行过的方法字节码，可恢复 JNI 名。
- **`fix`**：把记录的方法体回填到 DEX，输出覆盖率报告；长度不一致默认跳过，`--force-mismatch` 强制写入。
- **`dumpso`**：通过 `/proc/<pid>/maps` 与 `process_vm_readv` dump native `.so`，不依赖 eBPF；`--watch` 可持续抓取运行时解密或新加载的库。
- **`fixso`**：修复段偏移并从 `PT_DYNAMIC` 重建 section table；`--symbols` 注入 JNI 名。
- **`offsets`**：检查 `libart.so` 的 hook 目标和 ART 布局，用于适配不同 ROM。

## 输出目录

```text
<output>/<package-or-pid>/
├── dex_*.dex               # 原始 DEX
├── dex_*_code.json         # 方法字节码记录
├── fix/                    # 修复后的 DEX
├── final/                  # 推荐用于分析
├── jni_symbols_*.txt       # JNI 名（可选）
└── native_elf/             # 匿名 ELF（可选）
```

## 常用选项

- `--probe-mode full|lifecycle|maps-only`：控制探针强度，`maps-only` 不挂 uprobe。
- `--clean-oat`（默认开启）：dump 前删除目标应用 `oat/`，帮助走解释器；`--no-clean-oat` 保留。
- `--no-maps-scan` / `--no-native-buffer-scan` / `--native-elf-scan`：开关各类扫描。
- `--art-layout` / `--register-natives-offset`：ROM 不兼容时手工指定偏移。
- 完整参数见 `./eBPFDexDumper --help`。

## 限制

- 针对 Android 13+ ARM64 常见 ART 布局设计，不同厂商 ROM 可能有偏移、BTF 或 eBPF 差异，可先跑 `offsets` 适配。
- CompactDex（`cdex`）需先用外部工具转成标准 DEX。
- uprobe 可能被反调试检测，工具不保证绕过所有防护。
- `dumpso` 默认过滤 `/system`、`/apex`、`/vendor` 等系统库，需要时用 `--include-system` 或 `--lib`。

## 开发与测试

```bash
cargo fmt --check
cargo test --locked
sh build_android.sh
```

## 项目 Skill

仓库提供 [PC Android DEX dump Skill](skills/android-dex-dump/SKILL.md)，可从 Windows、macOS 或 Linux PC 一键完成本地 APK 的安装、启动、dump、拉取与校验：

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

Windows PowerShell 使用：

```powershell
.\skills\android-dex-dump\scripts\run_dump.ps1 C:\path\to\app.apk
```

两个入口共用跨平台的 `run_dump.py`，按 `full → lifecycle → maps-only` 依次尝试，结果和 `report.txt` 写入主机 Downloads 下的新目录。主机需要 Python 3.9+、ADB，以及 `apkanalyzer` 或 Android SDK `aapt`；目标设备仍须是已授权、root、支持 eBPF 的 ARM64 Android 设备。

## 安全边界与许可证

仅在你有权分析的应用、设备和数据上使用。项目采用 `GPL-3.0-or-later`；BPF helper 头文件为 BSD-2-Clause。参考实现：[LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper)。
