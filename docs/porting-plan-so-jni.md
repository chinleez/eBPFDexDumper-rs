# 移植方案：native .so dump + 修复 + JNI 名称恢复

把上游 Go 版 eBPFDexDumper（LLeavesG/eBPFDexDumper）2026-07-19 ~ 07-20 的一批改动移植到本 Rust 重写版。

> 状态：**已全部实施**（模块 D/A/B/C）。以下为原始方案；实施结果见文末"实施记录"。

## 实施记录

| 模块 | 状态 | 落地文件 | 验证 |
|------|------|---------|------|
| D. CompactDex 检测 | ✅ | `dex.rs` / `dump.rs` | 单测 + 全量编译 |
| A. dumpso | ✅ | 新 `so.rs` + `main.rs` | 8 单测（分组/合并/过滤/匿名）|
| B. fixso/重建 | ✅ | 新 `so_fix.rs` + `main.rs` | 合成 ELF64 重建 + goblin 严格解析 + 注入符号读回 |
| C1. RegisterNatives offset | ✅ | `art.rs`（含今天的 string-xref + ARM64 解码 + JNINativeInterface 表优选）| ARM64 ADRP/ADR xref 单测 |
| C2. JNI 捕获 | ✅ | `bpf/header.h` + `bpf/bpf.c`（新 uprobe+ringbuf）+ `dump.rs`（消费+写 jni_symbols_*.txt）+ `main.rs` flag | 全量编译（含 BPF）通过 |

**真机待验项（本机无法验证）**：dumpso 实际读内存 / fixso 对真实 ARM64 .so 的 readelf/nm 对比 / RegisterNatives attach + JNINativeMethod ABI（PARM3/PARM4 + 24 字节布局）+ BPF verifier 对 512 次循环的接受度 / fnPtr→offset 解析。ELF32、GNU_HASH、packed-reloc 分支已按上游移植但暂无专门测试样本。

## 一、上游改动范围

涉及 6 个实质 commit（不含纯 README）：

| commit | 日期 | 主题 |
|--------|------|------|
| `3e81bd820` | 07-19 | 新增 dumpso/fixso 命令，native .so 内存 dump |
| `4e103211c` | 07-19 | fixso 从 PT_DYNAMIC 重建完整 section header table |
| `321d4cff3` | 07-19 | .so dump/fix 增加 ELF32、packed-reloc、watch、system-filter |
| `1218b2e0f` | 07-19 | JNI 名称恢复、注入符号到 .so、CompactDex 检测 |
| `7aa7fbf1a` | 07-19 | 修 JNI/watch/fixso 一批 audit 出的 bug |
| `5b731a6fc` | 07-20 | 在被 strip 的 ART 上用字符串 xref 定位 RegisterNatives |

新增 Go 文件：`so_dumper.go`(293) / `so_rebuild.go`(562) / `fix_so.go`(131)，外加 `bpf.c`+`header.h` 的 JNI hook、`utils.go` 的 offset 查找、`dex_parser.go` 的 cdex 检测。

## 二、四个功能模块

### 模块 A — native .so 内存 dump（`dumpso` 命令）

来源：`3e81bd820` + `321d4cff3` + `7aa7fbf1a`（so_dumper.go）

核心逻辑：
1. 读 `/proc/<pid>/maps`，把同一 library 分开映射的段（r-- / r-x / rw-）按 vaddr 合并回一段连续 span；用 `process_vm_readv` 读出（**不走 eBPF/uprobe**，是纯用户态机制）。
2. 额外扫描匿名、无路径、首页以 ELF magic 开头的内存区 —— 抓 packer 自己 map/解密、没走 linker 的库。
3. `--watch` 模式：持续轮询 maps，新模块一出现就 dump；采样内容变化时**重新 dump**（抓运行时原地解密的库）。`--watch-interval` / `--watch-timeout` 调参。
4. system 库过滤：默认跳过 `/system`、`/apex`、`/vendor`、`/system_ext`、`/product`、`/odm`；`--include-system` 恢复旧行为；匿名映射始终保留。
5. ELF32/ARM32 支持。

**Rust 移植要点：**
- `process_vm_readv` → Rust 下用 `libc::process_vm_readv` 或 `/proc/<pid>/mem` pread。本项目应已有跨进程读内存的封装（dex fallback 路径），优先复用。
- maps 解析 → 简单的 `/proc/<pid>/maps` 行解析（起止地址、权限、路径），可自写或用现有 crate。
- watch 轮询 → Rust 用循环 + `std::thread::sleep`，或复用现有 shutdown/信号机制。
- 这块**与 eBPF 无关**，是最独立、最容易移植的模块。

### 模块 B — .so 修复（`fixso` 命令）

来源：`3e81bd820`(fix_so.go) + `4e103211c`(so_rebuild.go) + `321d4cff3`

两级修复：
1. **基础修复（header-only）**：把每个 PT_LOAD 段的 `p_offset` 改成等于 `p_vaddr`，`p_filesz` 抬到 `p_memsz`，清零 `e_shoff/e_shnum/e_shstrndx`（section header table 从来没进内存镜像）。让 IDA/Ghidra/objdump 能直接按 program header 加载。
2. **完整重建（RebuildSoSections）**：从 `PT_DYNAMIC` 重建完整 section header table（SoFixer 的思路，重写为 ARM64/ELF64）。读 `DT_SYMTAB/STRTAB/GNU_HASH/HASH/RELA/RELR/JMPREL/PLTGOT/VERSYM/VERDEF/VERNEED/INIT_ARRAY/FINI_ARRAY`，重建 `.dynsym/.dynstr/.rela.dyn/.rela.plt/.relr.dyn/.dynamic` 等；按地址排序补未知 size；从 SysV/GNU hash 表推导 dynsym 数量；重映射每个符号的 `st_shndx` 到重建后的 section。无 PT_DYNAMIC 时回退到 header-only。
3. Android packed relocations：解析 `DT_ANDROID_REL/RELA/RELR`（APS2 流 + RELR bitmap），产出 `SHT_ANDROID_REL/RELA/RELR` section。
4. ELF32：用一个 `elfLayout` 抽象参数化 ELF32 vs ELF64（结构体大小、字段偏移、符号字段顺序、REL vs RELA、DT_PLTREL）。
5. `SelfCheckSo` 后置自检：用 elf 解析器读回输出，log 可读 dynsym 数量。

**Rust 移植要点：**
- ELF 读写 → Rust 有成熟的 `object` / `goblin` crate 可读，但**写/重建**部分（section header 重建）多半要手写字节布局，因为这些 crate 主要面向解析。本项目 fix.rs 若已有 ELF 处理，优先看能否扩展。
- `elfLayout` 抽象 → Rust 用 trait 或泛型 + 常量表达 ELF32/64 差异，比 Go 更自然。
- 这是**最大、最复杂**的模块（Go 侧 so_rebuild.go 就 562 行且高密度），是移植工作量的大头。SoFixer 逻辑正确性强依赖细节，建议保留上游的验证方式（拿 libc.so/libz.so 重建后 readelf/nm 对比）。

### 模块 C — JNI 名称恢复

来源：`1218b2e0f` + `7aa7fbf1a` + `5b731a6fc`(今天)

动态注册的 native method 没有导出符号，IDA 只显示 `sub_XXXX`。恢复链路：
1. **BPF 侧**：新 uprobe 挂 libart 的 `RegisterNatives`，遍历 `JNINativeMethod` 数组（{name, signature, fnPtr}），把 `{fnPtr, name, signature}` 发到新的 `jni_events` ringbuf。（header.h 加结构体 + map；发 record 前清零，避免 stale 字节泄露；emit **TGID** 而非低 32 位 TID，保证 Stop 时延迟读 maps 仍能解析已退出线程注册的方法。）
2. **用户态**：附加 probe（offset 来自 `FindRegisterNativesOffset`），收集事件，把每个 fnPtr 通过该进程 maps 解析成"模块内 offset"，在 Stop 时写 `jni_symbols_<module>.txt`。
3. **fixso --symbols**：读 "offset name" 映射，把真实 `.symtab/.strtab` 写进重建后的 .so（class-aware，ELF32/64），IDA 里就能看到名字。这半段与架构无关，接受任意来源的映射。（bug fix：只把 `jni_symbols_<module>.txt` 注入名字匹配的那个 .so，别把一个库的 offset 写进所有库。）
4. **`FindRegisterNativesOffset` 三级查找**：
   - 手动 offset（CLI `--register-natives-offset`）优先；
   - 符号表/dynsym（未 strip；偏好 `art::JNI<false>` 即 `Lb0E`，运行时默认派发的实例，而非 CheckJNI 的 `<true>`）；
   - **字符串 xref（今天的改动）**：strip 的现代 ART 不再导出 RegisterNatives，但函数体内嵌 AOSP 警告串 `"This is slow, consider changing your RegisterNatives calls."`（次选 `"JNI RegisterNativeMethods: attempt to register 0 native methods for "`）。找串地址 → 扫可执行段找 ARM64 `ADR`/`ADRP+ADD` 引用 → 回溯函数入口 → 多候选时优先"出现在 JNINativeInterface 式指针表里的"那个（相邻 +8 槽是另一个可执行指针 = UnregisterNatives），否则取最低地址。

**Rust 移植要点：**
- ARM64 指令解析（ADRP/ADR/ADD 立即数拼装）是今天改动的核心，纯位运算，移植到 Rust 直接、无依赖。**先确认 art.rs 是否已有同类指令解析工具可复用**（本项目已在 libart 里定位 execute/nterp/verify_class，很可能已有 ADRP 解析）。
- `loadExecSegment`（取 PT_LOAD+PF_X 段）、`findStringInELF`、扫 RW 段找指针表 → 用 `object`/`goblin` 读 program header 即可。
- BPF 侧要新增 ringbuf + uprobe program，需改 bpf.c/header.h 并重新生成绑定（本项目用 aya，需确认 ringbuf/map 定义方式）。
- 这是**依赖链最长**的模块：A（拿到 .so）→ B（重建）→ C（注入符号）三者串起来才有完整价值。

### 模块 D — CompactDex 检测

来源：`1218b2e0f`(dex_parser.go)

检测 cdex magic，报清晰诊断而不是 "invalid dex magic"。**不做** cdex→dex 转换（超范围，README 指向 vdexExtractor）。

**Rust 移植要点：** 最小改动，在 dex.rs 的 magic 校验处加一个 cdex 分支给友好报错即可。

## 三、BPF 侧改动清单（模块 C 需要）

- `bpf/header.h`：新增 JNI 事件结构体 + `jni_events` ringbuf map。
- `bpf/bpf.c`：新增 `uprobe_libart_registerNatives`，遍历 JNINativeMethod 数组（**假设 64-bit 布局**，需注释标明），清零 record 后 submit，emit TGID。
- Rust 侧（aya）：新增 ringbuf 消费者；`attach_probe` 增加 registerNatives 挂载点；art.rs 增加 `verify_class` 之外的 register_natives target 解析。

## 四、风险与注意

1. **模块 B 正确性风险最高**：section header / relocation 重建对字节布局极敏感，错一个字段 IDA 就加载失败或符号错位。必须保留上游的对比验证（libc/libz 重建后 readelf/nm 逐字段比对）。
2. **RegisterNatives ABI/参数假设**（同已存在的 VerifyClass 风险）：`JNINativeMethod` 数组的遍历、fnPtr 位置依赖 ART 版本与 64-bit 假设，需真机多版本验证。
3. **字符串 xref 的架构限定**：ARM64 专用（ADRP/ADR）。x86_64 目标不适用 —— 本项目若只针对 ARM64 Android 则无碍。
4. **watch 模式非 eBPF**：是 uretprobe 的轮询替代，靠采样，可能漏掉极短命的映射。
5. **工作量**：Go 侧净增约 1500 行且密度高，模块 B/C 是大头；模块 A/D 相对轻。

## 五、Rust 现状 gap

Rust 版当前只有 3 个子命令：`Dump` / `Fix` / `Offsets`（main.rs:19-27）。逐模块对照：

| 模块 | Rust 现状 | 缺口 |
|------|-----------|------|
| **A. native .so dump** | **部分**：有实验性 raw dump（`Dump --native-elf-scan`，dump.rs:491 `save_native_elf`），但走 **eBPF mmap/mprotect 探针触发**，只把内存原样写盘、不重建 ELF；仅认 ELFCLASS64/ET_DYN/AARCH64（dump.rs:1512） | 无独立 `dumpso` 命令；无 `/proc/maps + process_vm_readv` 主动扫描（上游是不依赖 eBPF 的主机制）；无 `--watch`；无匿名 ELF 区专扫；system-filter 不覆盖 so；无 ELF32 |
| **B. .so 修复/重建** | **完全无**。fix.rs（740 行）只修 DEX（回填 bytecode + 重算 DEX 头，fix.rs:176-331） | 全部：header-only 修复、从 PT_DYNAMIC 重建 section header table、packed-reloc、ELF32、self-check |
| **C. JNI 名称恢复** | **完全无**（全树 grep `jni/RegisterNatives` 零命中） | BPF 侧 uprobe+ringbuf、用户态事件收集、fnPtr→offset、`jni_symbols_*.txt`、fixso --symbols 注入 .symtab、`FindRegisterNativesOffset` |
| **D. CompactDex 检测** | **无**。magic 硬校验 `dex\n`（dex.rs:3, dump.rs:1572），cdex 被直接跳过 | 加 cdex magic 分支 + 友好诊断 |

**可直接复用的现成设施（重要，决定工作量）：**
- **ARM64 指令解析**：art.rs 已有 ADRP/ADR/ADD 解码 + `find_function_entry`(art.rs:612 靠 `sub sp`/`stp x29,x30` 序言回溯) + `executable_load_segments`(art.rs:742) + `segment_data`/`read_inst`/`sign_extend`。**但 ADRP/ADR/ADD 解码目前内联在 `find_execute_by_interpreting_string`(art.rs:523) 里，未抽成通用函数。** → 模块 C 今天的 string-xref 与这段几乎同构（换字符串常量 + 加 JNINativeInterface 表优选），**最省力的一块**，但建议先把解码抽成公共工具再复用。
- **三级 offset 查找框架**：art.rs `find_art_offsets_inner`(149-384) 已实现 符号表 → 指令签名 → 字符串 xref，`TargetSource` 枚举齐全 → RegisterNatives 的 symbol/string 双路可直接套进这套框架。
- **跨进程读内存**：dump.rs 已有 `read_remote_mem` / `read_remote_mem` 式封装（native-elf-scan 与 dex fallback 用）→ 模块 A 的 process_vm_readv 可复用。
- **BPF 加载**：aya + `include_bytes_aligned!`(dump.rs:76) + BTF(dump.rs:64) → 模块 C 新增 ringbuf 需按 aya 方式定义并加消费者。
- **无可复用**：ELF **写/重建**（模块 B）—— goblin 仅用于解析 libart，重建 section header 需手写字节布局，是纯新增。

## 六、建议实施顺序

按"先易后难、先无 eBPF 后有 eBPF、依赖在后"排：

1. **模块 D — CompactDex 检测**（最小）。dex.rs 加 cdex magic 常量，dump.rs 校验处加分支给友好诊断。半天量级，先落地见效。
2. **前置重构 — 抽出 art.rs 的 ARM64 ADRP/ADR/ADD 解码为公共工具函数**。既为模块 C 铺路，也让现有 `find_execute_by_interpreting_string` 更清晰。低风险，有现成测试点。
3. **模块 A — `dumpso` 子命令**（独立、不依赖 eBPF）。新增 `Command::DumpSo`，实现 /proc/maps 段合并 + process_vm_readv + 匿名 ELF 扫描 + `--watch` + system-filter；复用现有跨进程读内存封装。可选：顺带让现有 `--native-elf-scan` 也过 system-filter。
4. **模块 B — `fixso` / so_rebuild**（最大最难，独立于 eBPF）。先做 header-only 修复，再做 PT_DYNAMIC 重建 + packed-reloc + ELF32。**必须**照搬上游验证法：拿 libc.so/libz.so 重建后用 readelf/nm 逐字段比对。A 的产物直接喂给它验证。
5. **模块 C — JNI 名称恢复**（依赖 A+B 产物 + BPF 侧新增，最后做）。BPF uprobe/ringbuf → 用户态收集 + fnPtr→offset → 写 `jni_symbols_*.txt` → `fixso --symbols` 注入 .symtab；offset 查找复用第 2 步工具 + 套第 5 节的三级框架 + 今天的 string-xref。串起 dump→dumpso→fixso -s 完整链路。

**里程碑价值**：第 1、3 步各自独立可用；第 4 步让 dumpso 产物能进 IDA；第 5 步才需要动 BPF/真机验证，风险集中在最后。
