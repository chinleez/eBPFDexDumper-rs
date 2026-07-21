# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)

[English](docs/README_EN.md) | 中文

面向 Android 13-17 ARM64 的 eBPF DEX dump 工具。用于在已 root 设备上通过 eBPF/uProbe 捕获 ART 运行时中的 DEX，记录执行过的方法字节码，并可将字节码回填到已 dump 的 DEX。

## 功能

- `dump`：通过 ART 入口、DexFile 注册/构造、CodeItem 反扫、maps 扫描和 native buffer 扫描捕获 DEX；若能定位 `RegisterNatives`，同时捕获动态注册的 JNI 方法名，写入 `jni_symbols_*.txt`。
- `fix`：把记录到的方法字节码回填到 DEX，修复版保留在 `fix/`，最终可用结果汇总到 `final/`。
- `dumpso`：从运行进程内存 dump native `.so`（读 `/proc/<pid>/maps` 合并各段后用 `process_vm_readv` 读出，不走 eBPF）。支持匿名 ELF 扫描、`--watch` 抓运行时脱壳、系统库过滤，默认 dump 后自动 `fixso`。
- `fixso`：修复 dump 出的 `.so`，让 IDA/Ghidra 能加载——归正段偏移，并从 `PT_DYNAMIC` 重建完整 section header table（`.dynsym`/重定位/hash/version 等）；`--symbols` 可把恢复的符号（如 JNI 名）注入真实 `.symtab`。
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
su -c './eBPFDexDumper dumpso -n com.example.app -o /data/local/tmp/so_out'
su -c './eBPFDexDumper dumpso -n com.example.app --watch --watch-timeout 120'
./eBPFDexDumper fixso -d /data/local/tmp/so_out
./eBPFDexDumper fixso -d /data/local/tmp/so_out -s /data/local/tmp/dex_out/com.example.app/jni_symbols_libfoo.txt
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

### native `.so` dump 与修复（`dumpso` / `fixso`）

`dumpso` 读 `/proc/<pid>/maps`，把每个库分开映射的段（`r--`/`r-x`/`rw-`）按虚拟地址合并成连续区间，用 `process_vm_readv` 整段读出——这条路径**不依赖 eBPF/uprobe**。默认还会扫描匿名、无路径、首页是 ELF magic 的内存区，以捕获壳自己 map/解密、没走 linker 的库。文件命名 `so_<pid>_<base>_<size>_<name>.so`。

- `--watch`：持续轮询 maps，新模块出现即 dump；采样内容变化时按上限重新 dump，用来抓运行时原地解密的库（`--watch-interval` 默认 1s、`--watch-timeout` 默认 60s，0 表示直到 Ctrl-C）。
- 默认跳过 `/system`、`/apex`、`/vendor`、`/system_ext`、`/product`、`/odm` 下的系统库（这些可直接从设备镜像取），`--include-system` 恢复；`--lib <substr>` 只 dump 路径含该子串的库。
- `--no-anon` 关闭匿名扫描；`dumpso` 默认在 dump 后自动跑 `fixso`（`--no-auto-fix` 关闭）。

`fixso` 修复 dump 出的 `.so`：优先从 `PT_DYNAMIC` 重建完整 section header table（`.dynsym`/`.dynstr`/`.hash`/`.gnu.hash`/各类重定位/version/`.init_array` 等，SoFixer 思路，支持 ELF32/64 与 Android packed relocation），无 `PT_DYNAMIC` 时退回最小修复（归正 `p_offset`、抬 `p_filesz`、清零段表）。修复结果写入 `dir/fix/<stem>_fix.so`。

### JNI 名称恢复（`RegisterNatives`）

动态注册的 native 方法在 `.so` 里没有导出符号，IDA 只显示 `sub_XXXX`。`dump` 时若能在 `libart` 定位 `art::JNI<>::RegisterNatives`（符号表；被 strip 时用函数体内嵌的 AOSP 警告字符串做交叉引用回溯），会 hook 它并遍历 `JNINativeMethod` 数组，把 `{fn_ptr, name, sig}` 写入输出目录的 `jni_symbols_<module>.txt`（及 `jni_symbols_raw.txt`）。

把该文件交给 `fixso --symbols`（`-s`），恢复的名字会作为真实 `.symtab` 符号注入到名字匹配的那个 `.so`，IDA/Ghidra 里即可看到函数名。可用 `--register-natives-offset` 手动指定偏移。完整闭环：`dump`（拿 JNI 名）→ `dumpso`（拿 `.so`）→ `fixso -s`（注入）。

### CompactDex（cdex）

遇到 ART 的 CompactDex（`cdex` magic）会给出明确诊断而不是当作损坏 DEX。本工具只产出标准 DEX，cdex 需要先做 cdex→dex 转换（如 vdexExtractor）才能被标准工具读取。

---

完整选项见 `--help`，包括 `-p/--pid`、`-t/--trace`、`--debug-layout`、`--no-code-item-fallback`、`--no-maps-scan`、`--no-native-buffer-scan`、`--libc` 等。

## 许可证

`GPL-3.0-or-later`。仓库内 Linux BPF helper 头文件的 BSD-2-Clause 许可证位于 `headers/LICENSE.BSD-2-Clause`。

请只在你有权分析的设备、应用和数据上使用本项目。

## 参考

本项目参考了 [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) 的部分实现逻辑。
