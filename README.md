# eBPFDexDumper-rs

`eBPFDexDumper-rs` 是面向 Android ARM64 的 eBPF DEX dump 工具，用于在已 root
设备上通过 eBPF/uProbe 捕获 ART 运行时中的 DEX 信息，重建内存 DEX，并记录执行过
的方法字节码，随后可把记录到的字节码回填到已 dump 的 DEX 文件中。

本仓库是独立 Rust 项目，已经包含编译 eBPF 程序所需的 `bpf.c`、头文件、
ARM64 `vmlinux.h` 和最小 BTF 资源。

## 功能

- 支持 Android ARM64 设备上的 `dump` 命令。
- 通过 eBPF ring buffer 接收 DEX、方法和读取失败事件。
- 分块重建 DEX，并在 eBPF 分块读取失败时自动使用 `process_vm_readv` 兜底。
- ART 对象链失效时，可通过 eBPF 捕获的 `CodeItem*` 触发用户态内存反扫，从目标进程
  内存中重新定位 DEX header 并 dump。
- 启动时会对目标 UID 的进程做一次 `/proc/<pid>/maps` 可读区域扫描，作为不依赖 ART
  私有对象布局的兜底。
- 导出方法字节码 JSON，用于后续 DEX 修复。
- 支持 `fix` 命令，将记录到的方法字节码回填到 DEX，并输出到 `fix/` 目录。
- 支持从 `libart.so` 中自动定位 ART `Execute`、`ExecuteNterpImpl`、
  `ExecuteNterpWithClinitImpl` 和 `VerifyClass` hook 目标。
- ART 运行时对象字段通过 layout 下发给 eBPF，并带有 DEX magic 校验和有限候选扫描兜底。
- 已按 AOSP `android16-release` 核对 arm64 nterp：`ExecuteNterpWithClinitImpl`
  仍跳转到 `ExecuteNterpImpl`，`ArtMethod::data_` 在运行时仍是 `CodeItem*`。
- 支持 GitHub Actions CI 和 Android ARM64 Release 打包。

## 环境要求

编译环境：

- Rust stable 工具链。
- 支持 BPF target 的 LLVM clang。
- Android ARM64 Release 构建需要 Android NDK。

设备运行环境：

- Android ARM64。
- root 权限。
- 内核支持 eBPF。
- 可访问 ART `libart.so`，默认路径通常是
  `/apex/com.android.art/lib64/libart.so`。

macOS 自带的 Apple clang 通常不包含 BPF 后端，建议安装 LLVM：

```bash
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang
```

如果没有设置 `CLANG`，构建脚本会优先尝试 Homebrew LLVM clang，然后再尝试系统
`clang`。

## 编译

本机编译：

```bash
cargo build
```

Android ARM64 Release 编译：

```bash
sh build_android.sh
```

生成的 Android 可执行文件路径：

```text
target/aarch64-linux-android/release/eBPFDexDumper
```

`build_android.sh` 会优先使用 `cargo ndk`。如果没有安装 `cargo ndk`，脚本会回退到
`cargo build --target aarch64-linux-android --release`，并通过 `ANDROID_NDK_HOME` 或
`NDK_HOME` 查找 Android linker。

## 使用

查看帮助：

```bash
./eBPFDexDumper --help
```

按包名 dump：

```bash
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

按 UID dump：

```bash
su -c './eBPFDexDumper dump -u 10123 -o /data/local/tmp/dex_out'
```

禁用 OAT 清理或自动修复：

```bash
su -c './eBPFDexDumper dump -n com.example.app --no-clean-oat --no-auto-fix'
```

修复已有 dump 目录：

```bash
./eBPFDexDumper fix -d /data/local/tmp/dex_out
```

单独定位 ART 偏移：

```bash
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
```

输出 JSON：

```bash
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
```

如需调试厂商 ROM 的 ART 字段布局，可以手动覆盖 layout。参数顺序为：
`ShadowFrame.method,ArtMethod.declaring_class,ArtMethod.dex_method_index,ArtMethod.data,Class.dex_cache,DexCache.dex_file,DexFile.begin,DexHeader.file_size,CodeItem.insns_size,CodeItem.insns`。

```bash
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so \
  --art-layout 0x8,0x0,0x8,0x10,0x10,0x10,0x8,0x20,0xc,0x10
```

`dump` 使用多路径互补策略：

- fast path：从 `ArtMethod -> Class -> DexCache -> DexFile -> begin` 直接定位 DEX。
- CodeItem fallback：ART 对象链解析不到 DEX 时，eBPF 上报 `CodeItem*`，用户态通过
  `process_vm_readv` 向前扫描 DEX header。
- maps scan：启动时扫描目标 UID 进程的可读内存区域，查找合法 DEX header。
- native buffer scan：hook bionic libc 的 `mmap`/`mprotect`/`memcpy`/`memmove`，
  将疑似 native 解密缓冲区交给用户态验证。
- hook coverage：同时尝试 `Execute`、`ExecuteNterpImpl`、`ExecuteNterpWithClinitImpl`
  和 nterp invoke 入口，覆盖解释执行路径。

调试新系统版本或厂商 ROM 时可加 `--debug-layout` 打印诊断事件。需要降低开销时可加
`--no-code-item-fallback`、`--no-maps-scan` 或 `--no-native-buffer-scan`。如果 libc
不在默认路径，可用 `--libc /apex/com.android.runtime/lib64/bionic/libc.so` 指定。

## 加固与自定义加载器覆盖

当前实现覆盖的是 DEX 最终进入 ART 或出现在进程内存中的场景：

- 自定义 `ClassLoader` 只要最终走 ART `DexFile` / nterp / interpreter，通常可由
  `DexFile::DexFile`、ART fast path 或 CodeItem fallback 捕获。
- `InMemoryDexClassLoader`、native 解密后交给 ART 的 loader，通常可由 `DexFile`
  构造路径或 maps scan 捕获。
- 如果加固只在 native 层短暂解密单个 class/method，且内存里不保留连续合法 DEX，
  native buffer scan 会尝试从 `mmap`/`mprotect`/`memcpy`/`memmove` 的候选缓冲区中
  识别完整 DEX；如果壳只生成碎片化方法体，仍需要按壳定点 hook 解密函数。

## 方案说明

默认组合覆盖 ART 入口、DexFile 注册/构造、CodeItem 反扫、maps 扫描和 native buffer 扫描。
ART 字段布局默认按 Android 13+ 常见布局处理，ROM 偏移不一致时可用 `--art-layout` 指定。

## 常见日志

运行时如果看到类似日志：

```text
eBPF read failed at offset ...; using process_vm_readv fallback
Dex file saved to ...
```

这通常不是 dump 失败。它表示 eBPF 分块读取某个 DEX offset 时失败，用户态随后使用
`process_vm_readv` 兜底读取。如果后面出现 `Dex file saved`，说明最终 DEX 已经保存。

如果只看到 `process_vm_readv failed`，才需要继续检查目标进程权限、SELinux、root
环境或目标进程是否已经退出。

## Release 打包

本地生成与 GitHub Release 一致的 Android ARM64 产物：

```bash
./scripts/package-release.sh
```

产物会写入 `dist/`：

- `eBPFDexDumper_android_arm64`
- `eBPFDexDumper_android_arm64.sha256`
- `eBPFDexDumper_android_arm64.tar.gz`

## GitHub Actions

仓库内已经包含两个工作流：

- `.github/workflows/ci.yml`：检查格式、运行测试，并验证 Android ARM64 构建。
- `.github/workflows/release.yml`：在推送 `v*` tag 或手动触发时，构建并上传
  Android ARM64 Release 产物。

发布新版本：

```bash
git tag v0.1.0
git push origin v0.1.0
```

也可以在 GitHub Actions 页面手动运行 Release workflow，并填写 tag。

## 许可证

本项目使用 `GPL-3.0-or-later` 许可证。仓库内打包的 Linux BPF helper 头文件带有
独立的 BSD-2-Clause 许可证文件，位于 `headers/LICENSE.BSD-2-Clause`。

请只在你有权分析的设备、应用和数据上使用本项目。
