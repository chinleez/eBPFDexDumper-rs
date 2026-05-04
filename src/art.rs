use anyhow::{Context, Result};
use goblin::elf::{program_header, Elf};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

fn log_resolve(quiet: bool, args: std::fmt::Arguments<'_>) {
    if !quiet {
        println!("{args}");
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
pub struct ArtRuntimeLayout {
    pub shadow_frame_method_offset: u32,
    pub art_method_declaring_class_offset: u32,
    pub art_method_dex_method_index_offset: u32,
    pub art_method_data_offset: u32,
    pub class_dex_cache_offset: u32,
    pub dex_cache_dex_file_offset: u32,
    pub dex_file_begin_offset: u32,
    pub dex_header_file_size_offset: u32,
    pub code_item_insns_size_offset: u32,
    pub code_item_insns_offset: u32,
}

impl ArtRuntimeLayout {
    /// AOSP main-line ART layout for Android 13–17 ARM64 ROMs.
    ///
    /// The BPF program assumes `mirror::Class::dex_cache_` and
    /// `ArtMethod::declaring_class_` are 32-bit `HeapReference` /
    /// `GcRoot<Class>` (compressed references), which is the AOSP default on
    /// 64-bit Android. Vendor ROMs that disable compressed references (rare
    /// on phones, occasionally seen in emulators / desktop ART builds) need
    /// to override the layout via `--art-layout` and adjust the `class_*` /
    /// `dex_cache_*` offsets accordingly. The other offsets (DexFile,
    /// DexHeader, CodeItem) are dictated by the DEX format itself and are
    /// version-stable.
    pub const fn android_13_plus_default() -> Self {
        Self {
            shadow_frame_method_offset: 0x08,
            art_method_declaring_class_offset: 0x00,
            art_method_dex_method_index_offset: 0x08,
            art_method_data_offset: 0x10,
            class_dex_cache_offset: 0x10,
            dex_cache_dex_file_offset: 0x10,
            dex_file_begin_offset: 0x08,
            dex_header_file_size_offset: 0x20,
            code_item_insns_size_offset: 0x0c,
            code_item_insns_offset: 0x10,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "ShadowFrame.method=0x{:x}, ArtMethod.declaring_class=0x{:x}, ArtMethod.dex_method_index=0x{:x}, ArtMethod.data=0x{:x}, Class.dex_cache=0x{:x}, DexCache.dex_file=0x{:x}, DexFile.begin=0x{:x}, DexHeader.file_size=0x{:x}, CodeItem.insns_size=0x{:x}, CodeItem.insns=0x{:x}",
            self.shadow_frame_method_offset,
            self.art_method_declaring_class_offset,
            self.art_method_dex_method_index_offset,
            self.art_method_data_offset,
            self.class_dex_cache_offset,
            self.dex_cache_dex_file_offset,
            self.dex_file_begin_offset,
            self.dex_header_file_size_offset,
            self.code_item_insns_size_offset,
            self.code_item_insns_offset
        )
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
pub enum TargetSource {
    Manual,
    Symbol,
    Pattern,
    StringRef,
}

impl std::fmt::Display for TargetSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let source = match self {
            TargetSource::Manual => "manual",
            TargetSource::Symbol => "symbol",
            TargetSource::Pattern => "pattern",
            TargetSource::StringRef => "string-ref",
        };
        f.write_str(source)
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub addr: u64,
    pub source: TargetSource,
}

impl ResolvedTarget {
    fn new(addr: u64, source: TargetSource) -> Self {
        Self { addr, source }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArtHookTargets {
    pub execute: Option<ResolvedTarget>,
    pub execute_nterp: Option<ResolvedTarget>,
    pub execute_nterp_with_clinit: Option<ResolvedTarget>,
    pub verify_class: Option<ResolvedTarget>,
    pub dex_file_ctor: Option<ResolvedTarget>,
    pub register_dex_file: Option<ResolvedTarget>,
    pub nterp_invoke_addrs: Vec<ResolvedTarget>,
}

impl ArtHookTargets {
    pub fn has_main_entry(&self) -> bool {
        self.execute.is_some()
            || self.execute_nterp.is_some()
            || self.execute_nterp_with_clinit.is_some()
    }
}

pub fn find_art_offsets(
    libart_path: &Path,
    manual_execute_offset: Option<u64>,
    manual_nterp_offset: Option<u64>,
) -> Result<ArtHookTargets> {
    find_art_offsets_inner(
        libart_path,
        manual_execute_offset,
        manual_nterp_offset,
        false,
    )
}

pub fn find_art_offsets_quiet(
    libart_path: &Path,
    manual_execute_offset: Option<u64>,
    manual_nterp_offset: Option<u64>,
) -> Result<ArtHookTargets> {
    find_art_offsets_inner(
        libart_path,
        manual_execute_offset,
        manual_nterp_offset,
        true,
    )
}

fn find_art_offsets_inner(
    libart_path: &Path,
    manual_execute_offset: Option<u64>,
    manual_nterp_offset: Option<u64>,
    quiet: bool,
) -> Result<ArtHookTargets> {
    let bytes = fs::read(libart_path)
        .with_context(|| format!("failed to read {}", libart_path.display()))?;
    let elf = Elf::parse(&bytes).context("failed to parse ELF")?;
    let sym_map = parse_libart_symbols(&elf);

    let mut targets = ArtHookTargets {
        execute: manual_execute_offset.map(|addr| ResolvedTarget::new(addr, TargetSource::Manual)),
        execute_nterp: manual_nterp_offset
            .map(|addr| ResolvedTarget::new(addr, TargetSource::Manual)),
        ..Default::default()
    };

    for (name, value) in sym_map {
        if targets.execute.is_none()
            && name.contains("3art")
            && name.contains("11interpreter")
            && name.contains("7Execute")
        {
            targets.execute = Some(ResolvedTarget::new(value, TargetSource::Symbol));
            continue;
        }
        if targets.execute_nterp.is_none() && name == "ExecuteNterpImpl" {
            targets.execute_nterp = Some(ResolvedTarget::new(value, TargetSource::Symbol));
            continue;
        }
        if targets.execute_nterp_with_clinit.is_none() && name == "ExecuteNterpWithClinitImpl" {
            targets.execute_nterp_with_clinit =
                Some(ResolvedTarget::new(value, TargetSource::Symbol));
            continue;
        }
        if targets.verify_class.is_none()
            && name.contains("3art")
            && name.contains("8verifier")
            && name.contains("13ClassVerifier")
            && name.contains("11VerifyClass")
        {
            targets.verify_class = Some(ResolvedTarget::new(value, TargetSource::Symbol));
            continue;
        }
        if targets.dex_file_ctor.is_none() && is_art_dex_file_constructor_symbol(&name) {
            targets.dex_file_ctor = Some(ResolvedTarget::new(value, TargetSource::Symbol));
            continue;
        }
        if targets.register_dex_file.is_none() && is_art_register_dex_file_symbol(&name) {
            targets.register_dex_file = Some(ResolvedTarget::new(value, TargetSource::Symbol));
        }
    }

    if targets.execute_nterp.is_none() {
        match find_pattern_uaddrs(&elf, &bytes, EXECUTE_NTERP_IMPL_SIG) {
            Ok(addrs) if !addrs.is_empty() => {
                let addr = addrs[0];
                targets.execute_nterp = Some(ResolvedTarget::new(addr, TargetSource::Pattern));
                if addrs.len() > 1 {
                    log_resolve(
                        quiet,
                        format_args!(
                        "[!] ExecuteNterpImpl signature matched {} sites; using first: 0x{addr:x}",
                        addrs.len()
                    ),
                    );
                } else {
                    log_resolve(
                        quiet,
                        format_args!("[+] ExecuteNterpImpl found by signature at 0x{addr:x}"),
                    );
                }
            }
            Ok(_) => log_resolve(
                quiet,
                format_args!("[-] ExecuteNterpImpl not found by symbol or signature"),
            ),
            Err(err) => log_resolve(
                quiet,
                format_args!("[-] ExecuteNterpImpl not found by symbol or signature: {err:#}"),
            ),
        }
    }

    if targets.execute_nterp_with_clinit.is_none() {
        let mut found = None;
        let mut diagnostics: Vec<String> = Vec::new();
        if let Some(execute_nterp) = targets.execute_nterp {
            match find_nterp_with_clinit_by_branch(&elf, &bytes, execute_nterp.addr) {
                Ok(addrs) if !addrs.is_empty() => {
                    let addr = addrs[0];
                    found = Some(addr);
                    if addrs.len() > 1 {
                        log_resolve(quiet, format_args!(
                            "[!] ExecuteNterpWithClinitImpl branch scan matched {} sites; using first: 0x{addr:x}",
                            addrs.len()
                        ));
                    } else {
                        log_resolve(
                            quiet,
                            format_args!(
                                "[+] ExecuteNterpWithClinitImpl found by branch scan at 0x{addr:x}"
                            ),
                        );
                    }
                }
                Ok(_) => diagnostics.push("branch scan no match".to_string()),
                Err(err) => diagnostics.push(format!("branch scan: {err:#}")),
            }
        }
        if found.is_none() {
            match find_pattern_uaddrs(&elf, &bytes, EXECUTE_NTERP_WITH_CLINIT_SIG) {
                Ok(addrs) if !addrs.is_empty() => {
                    let addr = addrs[0];
                    found = Some(addr);
                    if addrs.len() > 1 {
                        log_resolve(quiet, format_args!(
                            "[!] ExecuteNterpWithClinitImpl signature matched {} sites; using first: 0x{addr:x}",
                            addrs.len()
                        ));
                    } else {
                        log_resolve(
                            quiet,
                            format_args!(
                                "[+] ExecuteNterpWithClinitImpl found by signature at 0x{addr:x}"
                            ),
                        );
                    }
                }
                Ok(_) => diagnostics.push("signature no match".to_string()),
                Err(err) => diagnostics.push(format!("signature: {err:#}")),
            }
        }
        if let Some(addr) = found {
            targets.execute_nterp_with_clinit =
                Some(ResolvedTarget::new(addr, TargetSource::Pattern));
        } else {
            // Android 13 ART has no separate ExecuteNterpWithClinitImpl variant; the
            // clinit barrier is handled inside ExecuteNterpImpl. This is expected on
            // older ROMs and not an error as long as ExecuteNterpImpl is attached.
            let tag = if targets.execute_nterp.is_some() {
                "[!]"
            } else {
                "[-]"
            };
            let detail = if diagnostics.is_empty() {
                "no candidate".to_string()
            } else {
                diagnostics.join("; ")
            };
            log_resolve(
                quiet,
                format_args!(
                    "{tag} ExecuteNterpWithClinitImpl not located (likely Android 13 or fully inlined): {detail}"
                ),
            );
        }
    }

    if targets.execute.is_none() {
        match find_execute_by_interpreting_string(&elf, &bytes, quiet) {
            Ok(addr) => {
                targets.execute = Some(ResolvedTarget::new(addr, TargetSource::StringRef));
                log_resolve(
                    quiet,
                    format_args!("[+] Execute found by 'Interpreting ' string at 0x{addr:x}"),
                );
            }
            Err(err) => {
                // Android 15+ ROMs strip and inline art::interpreter::Execute into the
                // nterp main entries; treat the miss as informational once nterp is up.
                let tag = if targets.execute_nterp.is_some()
                    || targets.execute_nterp_with_clinit.is_some()
                {
                    "[!]"
                } else {
                    "[-]"
                };
                log_resolve(
                    quiet,
                    format_args!(
                        "{tag} art::interpreter::Execute not located; nterp covers main path: {err:#}"
                    ),
                );
            }
        }
    }

    {
        let mut all = BTreeSet::new();
        let mut last_err: Option<anyhow::Error> = None;
        for sig in NTERP_OP_INVOKE_SIGS {
            match find_pattern_uaddrs(&elf, &bytes, sig) {
                Ok(addrs) => {
                    for addr in addrs {
                        all.insert(addr);
                    }
                }
                Err(err) => last_err = Some(err),
            }
        }
        if all.is_empty() {
            if let Some(err) = last_err {
                log_resolve(
                    quiet,
                    format_args!("[-] nterp_op_invoke_* pattern not found: {err:#}"),
                );
            } else {
                log_resolve(
                    quiet,
                    format_args!("[-] nterp_op_invoke_* pattern not found"),
                );
            }
        } else {
            targets.nterp_invoke_addrs = all
                .into_iter()
                .map(|addr| ResolvedTarget::new(addr, TargetSource::Pattern))
                .collect();
        }
    }

    if !targets.has_main_entry() {
        anyhow::bail!(
            "failed to locate any ART main entry in libart.so (Execute, ExecuteNterpImpl, ExecuteNterpWithClinitImpl)"
        );
    }
    if targets.verify_class.is_none() {
        log_resolve(
            quiet,
            format_args!("[!] VerifyClass not found; continuing without VerifyClass hook"),
        );
    }

    Ok(targets)
}

pub fn resolve_runtime_layout(_libart_path: &Path) -> Result<ArtRuntimeLayout> {
    // Android 13+ currently uses this compact 64-bit ART layout for the fields
    // the dumper needs. Keeping it behind a resolver lets later versions swap
    // in source-derived or live-probed layouts without touching the BPF program.
    Ok(ArtRuntimeLayout::android_13_plus_default())
}

pub fn parse_libart_symbols(elf: &Elf<'_>) -> HashMap<String, u64> {
    let mut out = HashMap::new();

    for sym in elf.syms.iter() {
        if sym.st_value == 0 {
            continue;
        }
        if let Some(name) = elf
            .strtab
            .get_at(sym.st_name)
            .filter(|name| is_target_art_symbol(name))
        {
            out.insert(name.to_string(), sym.st_value);
        }
    }

    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 {
            continue;
        }
        if let Some(name) = elf
            .dynstrtab
            .get_at(sym.st_name)
            .filter(|name| is_target_art_symbol(name))
        {
            out.insert(name.to_string(), sym.st_value);
        }
    }

    out
}

fn is_target_art_symbol(name: &str) -> bool {
    (name.contains("3art") && name.contains("11interpreter") && name.contains("7Execute"))
        || name == "ExecuteNterpImpl"
        || name == "ExecuteNterpWithClinitImpl"
        || (name.contains("3art")
            && name.contains("8verifier")
            && name.contains("13ClassVerifier")
            && name.contains("11VerifyClass"))
        || is_art_dex_file_constructor_symbol(name)
        || is_art_register_dex_file_symbol(name)
}

fn is_art_register_dex_file_symbol(name: &str) -> bool {
    // ClassLinker has multiple RegisterDexFile overloads across versions:
    //   * RegisterDexFile(DexFile const&, ObjPtr<ClassLoader>)   <- mangled tail "ERKNS_7DexFile..."
    //   * RegisterDexFile(unique_ptr<DexFile const, ...>, ...)   <- mangled tail "EONSt3__1..." or similar
    // Only the first form passes a raw DexFile* in x1, which is the ABI the
    // uprobe_libart_registerDexFile BPF program assumes. Pin the suffix so we
    // don't accidentally attach to an overload whose x1 is something else.
    name.starts_with("_ZN3art11ClassLinker15RegisterDexFileERKNS_7DexFile")
}

fn is_art_dex_file_constructor_symbol(name: &str) -> bool {
    // Direct DexFile ctors (most Android 13–15 ROMs):
    //   ABI x0=this(DexFile*), x1=base(uint8_t const*), x2=size(size_t).
    // uprobe_libart_dexFileCtor reads x1 as the dex begin pointer.
    if name.starts_with("_ZN3art7DexFileC1") || name.starts_with("_ZN3art7DexFileC2") {
        return true;
    }
    // Android 16/17 strip and inline the DexFile ctor entirely. DexFileLoader::OpenOne
    //   OpenOne(uintptr_t base, uint32_t size, OatDexFile const*, bool, bool, std::string*)
    //   ABI x0=this(DexFileLoader*), x1=base, x2=size — same x1=base shape as the ctor,
    // so the same uprobe_libart_dexFileCtor program works.
    // NOTE: on most stripped libart this symbol exists in dynsym with st_value=0
    // (treated as an import placeholder); attach simply skips it. When a ROM
    // does export it with a real address, the ABI assumption above holds.
    if name.starts_with("_ZN3art13DexFileLoader7OpenOne") {
        return true;
    }
    false
}

// Multiple nterp_op_invoke_* signatures. The dumper attaches uprobes to every
// match across all patterns, so adding a candidate only ever broadens coverage.
//   1. Android 13–15 invoke handler prologue (load+cmp on v-table-ish slot).
//   2. Android 16/17 invoke-virtual/super/direct/static prologue: load class +
//      fetch dex_method_index from the invoke instruction (`ubfx`-free path).
pub const NTERP_OP_INVOKE_SIGS: &[&[u8]] = &[
    &[0x03, 0x0c, 0x40, 0xf9, 0x5f, 0x00, 0x03, 0xeb],
    &[
        0xc3, 0x06, 0xc0, 0x79, 0xe9, 0x7e, 0x08, 0x53, 0x62, 0x1c, 0x00, 0x12, 0xa0, 0x5b, 0x62,
        0xb8,
    ],
];

const EXECUTE_NTERP_IMPL_SIG: &[u8] = &[
    0xf0, 0x0b, 0x40, 0xd1, 0x1f, 0x02, 0x40, 0xb9, 0xff, 0x83, 0x02, 0xd1, 0xe8, 0x27, 0x00, 0x6d,
    0xea, 0x2f, 0x01, 0x6d, 0xec, 0x37, 0x02, 0x6d, 0xee, 0x3f, 0x03, 0x6d, 0xf3, 0x53, 0x04, 0xa9,
    0xf5, 0x5b, 0x05, 0xa9, 0xf7, 0x63, 0x06, 0xa9, 0xf9, 0x6b, 0x07, 0xa9, 0xfb, 0x73, 0x08, 0xa9,
    0xfd, 0x7b, 0x09, 0xa9, 0x16, 0x08, 0x40, 0xf9,
];

const EXECUTE_NTERP_WITH_CLINIT_SIG: &[u8] = &[
    0x08, 0x00, 0x40, 0xb9, 0x09, 0x81, 0x40, 0x39, 0x3f, 0x05, 0x00, 0x71,
];

pub fn find_pattern_uaddrs(elf: &Elf<'_>, bytes: &[u8], pattern: &[u8]) -> Result<Vec<u64>> {
    if pattern.is_empty() {
        anyhow::bail!("pattern is empty");
    }

    let mut addrs = Vec::new();
    let mut seen = BTreeSet::new();
    for ph in executable_load_segments(elf) {
        let data = segment_data(bytes, ph)?;
        if data.len() < pattern.len() {
            continue;
        }
        let mut off = 0usize;
        while off + pattern.len() <= data.len() {
            let Some(idx) = find_subslice(&data[off..], pattern) else {
                break;
            };
            let seg_off = off + idx;
            let uaddr = ph.p_vaddr + seg_off as u64;
            if seen.insert(uaddr) {
                addrs.push(uaddr);
            }
            off = seg_off + 1;
        }
    }

    if addrs.is_empty() {
        anyhow::bail!("pattern not found");
    }
    Ok(addrs)
}

fn find_execute_by_interpreting_string(elf: &Elf<'_>, bytes: &[u8], quiet: bool) -> Result<u64> {
    let str_addr = find_string_in_elf(elf, bytes, b"Interpreting ")
        .context("failed to find 'Interpreting ' string")?;
    log_resolve(
        quiet,
        format_args!("[+] Found 'Interpreting ' string at 0x{str_addr:x}"),
    );

    let (code_vaddr, code_data) = executable_load_segments(elf)
        .find_map(|ph| segment_data(bytes, ph).ok().map(|data| (ph.p_vaddr, data)))
        .context("code segment not found")?;

    let mut ref_addrs = Vec::new();
    for i in (0..code_data.len().saturating_sub(8)).step_by(4) {
        let pc = code_vaddr + i as u64;
        let inst = read_inst(code_data, i);
        if (inst & 0x9f00_0000) == 0x9000_0000 {
            let immlo = (inst >> 29) & 0x3;
            let immhi = (inst >> 5) & 0x7ffff;
            let mut imm = (((immhi << 2) | immlo) as i64) << 12;
            if (imm & (1 << 32)) != 0 {
                imm |= !0i64 << 33;
            }
            let page_addr = (pc & !0xfff).wrapping_add(imm as u64);
            let next_inst = read_inst(code_data, i + 4);
            if (next_inst & 0xffc0_0000) == 0x9100_0000 {
                let imm12 = (next_inst >> 10) & 0xfff;
                if page_addr + imm12 as u64 == str_addr {
                    ref_addrs.push(pc);
                }
            }
        }

        if (inst & 0x9f00_0000) == 0x1000_0000 {
            let immlo = (inst >> 29) & 0x3;
            let immhi = (inst >> 5) & 0x7ffff;
            let mut imm = ((immhi << 2) | immlo) as i64;
            if (imm & (1 << 20)) != 0 {
                imm |= !0i64 << 21;
            }
            if pc.wrapping_add(imm as u64) == str_addr {
                ref_addrs.push(pc);
            }
        }
    }

    if ref_addrs.is_empty() {
        anyhow::bail!("no code references to 'Interpreting ' string found");
    }
    log_resolve(
        quiet,
        format_args!(
            "[+] Found {} references to 'Interpreting ' string",
            ref_addrs.len()
        ),
    );

    for ref_addr in ref_addrs {
        let Some(func_addr) = find_function_entry(code_data, code_vaddr, ref_addr) else {
            continue;
        };
        if check_for_6th_parameter(code_data, code_vaddr, func_addr) {
            log_resolve(
                quiet,
                format_args!(
                    "[+] Execute function found at 0x{func_addr:x} (6 parameters, uses W5)"
                ),
            );
            return Ok(func_addr);
        }
    }

    anyhow::bail!("Execute function not found (no 6-parameter function found)")
}

fn find_string_in_elf(elf: &Elf<'_>, bytes: &[u8], target: &[u8]) -> Result<u64> {
    for ph in elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == program_header::PT_LOAD)
    {
        let data = segment_data(bytes, ph)?;
        if let Some(idx) = find_subslice(data, target) {
            return Ok(ph.p_vaddr + idx as u64);
        }
    }
    anyhow::bail!("string {:?} not found", String::from_utf8_lossy(target))
}

fn find_function_entry(code_data: &[u8], code_vaddr: u64, ref_addr: u64) -> Option<u64> {
    if ref_addr < code_vaddr {
        return None;
    }
    let start_off = (ref_addr - code_vaddr) as usize;
    let max_search = start_off.min(0x2000);
    let mut off = start_off;
    while off >= start_off - max_search {
        if off + 4 > code_data.len() {
            return None;
        }
        let inst = read_inst(code_data, off);
        if (inst & 0xffc0_03ff) == 0xd100_03ff {
            let imm12 = (inst >> 10) & 0xfff;
            if (0x20..=0x400).contains(&imm12) {
                return Some(code_vaddr + off as u64);
            }
        }
        if (inst & 0xffc0_7fff) == 0xa980_7bfd {
            return Some(code_vaddr + off as u64);
        }
        if off < 4 {
            break;
        }
        off -= 4;
    }
    None
}

fn check_for_6th_parameter(code_data: &[u8], code_vaddr: u64, func_addr: u64) -> bool {
    if func_addr < code_vaddr {
        return false;
    }
    let start_off = (func_addr - code_vaddr) as usize;
    let check_len = (code_data.len().saturating_sub(start_off)).min(200);
    for off in (start_off..start_off + check_len).step_by(4) {
        if off + 4 > code_data.len() {
            break;
        }
        let inst = read_inst(code_data, off);
        if (inst & 0x7f00_0000) == 0x3600_0000 || (inst & 0x7f00_0000) == 0x3700_0000 {
            let rt = inst & 0x1f;
            let b5 = (inst >> 31) & 1;
            if rt == 5 && b5 == 0 {
                return true;
            }
        }
    }
    false
}

fn find_nterp_with_clinit_by_branch(
    elf: &Elf<'_>,
    bytes: &[u8],
    execute_nterp_addr: u64,
) -> Result<Vec<u64>> {
    let mut addrs = Vec::new();
    let mut seen = BTreeSet::new();
    for ph in executable_load_segments(elf) {
        let data = segment_data(bytes, ph)?;
        if data.len() < 8 {
            continue;
        }
        for off in (0..data.len() - 8).step_by(4) {
            let pc = ph.p_vaddr + off as u64;
            let first = read_inst(data, off);
            let second = read_inst(data, off + 4);
            let Some(class_reg) = ldr_w_from_reg(first, 0) else {
                continue;
            };
            if ldr_status_from_reg(second, class_reg).is_none() {
                continue;
            }
            if branch_window_targets(data, ph.p_vaddr, off, execute_nterp_addr) && seen.insert(pc) {
                addrs.push(pc);
            }
        }
    }
    if addrs.is_empty() {
        anyhow::bail!("ExecuteNterpWithClinitImpl branch pattern not found");
    }
    Ok(addrs)
}

fn ldr_w_from_reg(inst: u32, expected_rn: u32) -> Option<u32> {
    if (inst & 0xffc0_0000) != 0xb940_0000 {
        return None;
    }
    let rn = (inst >> 5) & 0x1f;
    (rn == expected_rn).then_some(inst & 0x1f)
}

fn ldr_status_from_reg(inst: u32, expected_rn: u32) -> Option<u32> {
    // Android 14 reads a byte field, Android 15+ can read a packed 32-bit status field.
    if (inst & 0xffc0_0000) != 0x3940_0000 && (inst & 0xffc0_0000) != 0xb940_0000 {
        return None;
    }
    let rn = (inst >> 5) & 0x1f;
    (rn == expected_rn).then_some(inst & 0x1f)
}

fn branch_window_targets(data: &[u8], code_vaddr: u64, start_off: usize, target: u64) -> bool {
    let end = (start_off + 14 * 4).min(data.len());
    for off in (start_off..end).step_by(4) {
        let pc = code_vaddr + off as u64;
        let inst = read_inst(data, off);
        if branch_target(pc, inst) == Some(target) {
            return true;
        }
    }
    false
}

fn branch_target(pc: u64, inst: u32) -> Option<u64> {
    if (inst & 0xfc00_0000) == 0x1400_0000 {
        let imm = sign_extend((inst & 0x03ff_ffff) as i64, 26) << 2;
        return Some(pc.wrapping_add(imm as u64));
    }
    if (inst & 0xff00_0010) == 0x5400_0000 {
        let imm = sign_extend(((inst >> 5) & 0x7ffff) as i64, 19) << 2;
        return Some(pc.wrapping_add(imm as u64));
    }
    None
}

fn sign_extend(value: i64, bits: u8) -> i64 {
    let shift = 64 - bits;
    (value << shift) >> shift
}

fn executable_load_segments<'a>(
    elf: &'a Elf<'a>,
) -> impl Iterator<Item = &'a goblin::elf::program_header::ProgramHeader> + 'a {
    elf.program_headers.iter().filter(|ph| {
        ph.p_type == program_header::PT_LOAD && (ph.p_flags & program_header::PF_X) != 0
    })
}

fn segment_data<'a>(
    bytes: &'a [u8],
    ph: &goblin::elf::program_header::ProgramHeader,
) -> Result<&'a [u8]> {
    let start = ph.p_offset as usize;
    let end = start
        .checked_add(ph.p_filesz as usize)
        .context("segment size overflow")?;
    bytes
        .get(start..end)
        .with_context(|| format!("segment out of bounds at file offset 0x{:x}", ph.p_offset))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_inst(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().expect("instruction slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_function_entry_from_sub_sp_prologue() {
        let mut code = vec![0u8; 0x100];
        let prologue = 0xd100_83ffu32;
        code[0x20..0x24].copy_from_slice(&prologue.to_le_bytes());
        assert_eq!(find_function_entry(&code, 0x1000, 0x1060), Some(0x1020));
    }

    #[test]
    fn detects_w5_tbz_or_tbnz() {
        let mut code = vec![0u8; 0x100];
        let tbnz_w5 = 0x3700_0005u32;
        code[0x10..0x14].copy_from_slice(&tbnz_w5.to_le_bytes());
        assert!(check_for_6th_parameter(&code, 0x1000, 0x1000));
    }

    #[test]
    fn finds_overlapping_subslice() {
        assert_eq!(find_subslice(b"aaaab", b"aab"), Some(2));
    }

    #[test]
    fn recognizes_nterp_with_clinit_symbol() {
        assert!(is_target_art_symbol("ExecuteNterpWithClinitImpl"));
    }

    #[test]
    fn main_entry_check_does_not_require_verify_class() {
        let targets = ArtHookTargets {
            execute_nterp: Some(ResolvedTarget::new(0x1234, TargetSource::Symbol)),
            verify_class: None,
            ..Default::default()
        };
        assert!(targets.has_main_entry());
    }

    #[test]
    fn decodes_unconditional_branch_target() {
        let pc = 0x1000;
        let inst = 0x1400_0004;
        assert_eq!(branch_target(pc, inst), Some(0x1010));
    }

    #[test]
    fn decodes_conditional_branch_target() {
        let pc = 0x1000;
        let inst = 0x5400_0042;
        assert_eq!(branch_target(pc, inst), Some(0x1008));
    }

    #[test]
    fn detects_android_14_and_15_clinit_loads() {
        assert_eq!(ldr_w_from_reg(0xb940_0008, 0), Some(8));
        assert_eq!(ldr_status_from_reg(0x3940_0109, 8), Some(9));
        assert_eq!(ldr_status_from_reg(0xb940_0109, 8), Some(9));
        assert_eq!(ldr_w_from_reg(0xb940_0010, 0), Some(16));
        assert_eq!(ldr_status_from_reg(0xb940_6a11, 16), Some(17));
    }
}
