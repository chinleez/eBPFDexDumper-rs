//! Repairing raw memory dumps of native `.so` libraries so static-analysis
//! tools (IDA/Ghidra/objdump) can load them.
//!
//! A dump built from `/proc/<pid>/maps` places each segment's bytes at
//! `vaddr - base` in the output buffer, which does not match the on-disk file
//! layout the original ELF header describes. The preferred fix reconstructs a
//! full section header table from the PT_DYNAMIC segment (see
//! [`rebuild_so_sections`]), restoring `.dynsym`/`.dynstr`, relocation, hash
//! and version sections. If that can't run (e.g. no PT_DYNAMIC) it falls back
//! to a minimal header-only fix. This is a port of the upstream Go
//! `so_rebuild.go` / `fix_so.go`, rewritten for ELF32/ELF64.

use crate::so::sanitize_so_name;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

// program header types
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

// section header types
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_RELR: u32 = 19;
const SHT_ANDROID_REL: u32 = 0x6000_0001;
const SHT_ANDROID_RELA: u32 = 0x6000_0002;
const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;
const SHT_GNU_HASH: u32 = 0x6fff_fff6;
const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

// section header flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXEC: u64 = 0x4;
const SHF_INFO_LINK: u64 = 0x40;

// dynamic tags
const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_ANDROID_REL: i64 = 0x6000_000f;
const DT_ANDROID_RELSZ: i64 = 0x6000_0010;
const DT_ANDROID_RELA: i64 = 0x6000_0011;
const DT_ANDROID_RELASZ: i64 = 0x6000_0012;
const DT_ANDROID_RELR: i64 = 0x6fffe000;
const DT_ANDROID_RELRSZ: i64 = 0x6fffe001;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}
fn wr_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn wr_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn wr_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Abstracts the byte-level differences between ELF32 and ELF64 so the rebuild
/// logic is written once. Accessors take a slice positioned at the start of the
/// relevant structure (or the whole file, for the header).
#[derive(Clone, Copy)]
struct ElfLayout {
    is64: bool,
}

impl ElfLayout {
    fn pick(self, a: usize, b: usize) -> usize {
        if self.is64 {
            a
        } else {
            b
        }
    }
    fn ehdr_size(self) -> usize {
        self.pick(64, 52)
    }
    fn phdr_size(self) -> usize {
        self.pick(56, 32)
    }
    fn shdr_size(self) -> usize {
        self.pick(64, 40)
    }
    fn dyn_size(self) -> usize {
        self.pick(16, 8)
    }
    fn sym_size(self) -> usize {
        self.pick(24, 16)
    }
    fn word(self) -> u64 {
        self.pick(8, 4) as u64
    }

    fn read_addr(self, b: &[u8], off64: usize, off32: usize) -> u64 {
        if self.is64 {
            rd_u64(b, off64)
        } else {
            rd_u32(b, off32) as u64
        }
    }
    fn put_addr(self, b: &mut [u8], off64: usize, off32: usize, v: u64) {
        if self.is64 {
            wr_u64(b, off64, v);
        } else {
            wr_u32(b, off32, v as u32);
        }
    }

    // ELF header accessors
    fn phoff(self, d: &[u8]) -> u64 {
        self.read_addr(d, 32, 28)
    }
    fn phentsize(self, d: &[u8]) -> usize {
        rd_u16(d, self.pick(54, 42)) as usize
    }
    fn phnum(self, d: &[u8]) -> usize {
        rd_u16(d, self.pick(56, 44)) as usize
    }
    fn set_shoff(self, d: &mut [u8], v: u64) {
        self.put_addr(d, 40, 32, v);
    }
    fn set_shentsize(self, d: &mut [u8], v: u16) {
        wr_u16(d, self.pick(58, 46), v);
    }
    fn set_shnum(self, d: &mut [u8], v: u16) {
        wr_u16(d, self.pick(60, 48), v);
    }
    fn set_shstrndx(self, d: &mut [u8], v: u16) {
        wr_u16(d, self.pick(62, 50), v);
    }

    // Program header accessors (b positioned at a phdr entry)
    fn p_type(self, b: &[u8]) -> u32 {
        rd_u32(b, 0)
    }
    fn p_vaddr(self, b: &[u8]) -> u64 {
        self.read_addr(b, 16, 8)
    }
    fn p_filesz(self, b: &[u8]) -> u64 {
        self.read_addr(b, 32, 16)
    }
    fn p_memsz(self, b: &[u8]) -> u64 {
        self.read_addr(b, 40, 20)
    }
    fn set_p_offset(self, b: &mut [u8], v: u64) {
        self.put_addr(b, 8, 4, v);
    }
    fn set_p_filesz(self, b: &mut [u8], v: u64) {
        self.put_addr(b, 32, 16, v);
    }

    // Dynamic entry accessors (b positioned at a dyn entry)
    fn d_tag(self, b: &[u8]) -> i64 {
        if self.is64 {
            rd_u64(b, 0) as i64
        } else {
            rd_u32(b, 0) as i32 as i64
        }
    }
    fn d_val(self, b: &[u8]) -> u64 {
        self.read_addr(b, 8, 4)
    }

    // Symbol accessors (b positioned at a sym entry). ELF32 and ELF64 order
    // their fields differently, so these are not simple width swaps.
    fn sym_value(self, b: &[u8]) -> u64 {
        if self.is64 {
            rd_u64(b, 8)
        } else {
            rd_u32(b, 4) as u64
        }
    }
    fn sym_info(self, b: &[u8]) -> u8 {
        if self.is64 {
            b[4]
        } else {
            b[12]
        }
    }
    fn sym_shndx_off(self) -> usize {
        self.pick(6, 14)
    }
    fn sym_shndx(self, b: &[u8]) -> u16 {
        rd_u16(b, self.sym_shndx_off())
    }
    fn set_sym_shndx(self, b: &mut [u8], v: u16) {
        let o = self.sym_shndx_off();
        wr_u16(b, o, v);
    }

    /// Writes one section header entry in the right class layout.
    #[allow(clippy::too_many_arguments)]
    fn put_shdr(
        self,
        b: &mut [u8],
        name: u32,
        typ: u32,
        flags: u64,
        addr: u64,
        off: u64,
        size: u64,
        link: u32,
        info: u32,
        align: u64,
        entsize: u64,
    ) {
        wr_u32(b, 0, name);
        wr_u32(b, 4, typ);
        if self.is64 {
            wr_u64(b, 8, flags);
            wr_u64(b, 16, addr);
            wr_u64(b, 24, off);
            wr_u64(b, 32, size);
            wr_u32(b, 40, link);
            wr_u32(b, 44, info);
            wr_u64(b, 48, align);
            wr_u64(b, 56, entsize);
        } else {
            wr_u32(b, 8, flags as u32);
            wr_u32(b, 12, addr as u32);
            wr_u32(b, 16, off as u32);
            wr_u32(b, 20, size as u32);
            wr_u32(b, 24, link);
            wr_u32(b, 28, info);
            wr_u32(b, 32, align as u32);
            wr_u32(b, 36, entsize as u32);
        }
    }

    /// Writes one symbol table entry in the right class layout.
    #[allow(clippy::too_many_arguments)]
    fn put_sym(
        self,
        b: &mut [u8],
        name: u32,
        value: u64,
        size: u64,
        info: u8,
        other: u8,
        shndx: u16,
    ) {
        if self.is64 {
            wr_u32(b, 0, name);
            b[4] = info;
            b[5] = other;
            wr_u16(b, 6, shndx);
            wr_u64(b, 8, value);
            wr_u64(b, 16, size);
        } else {
            wr_u32(b, 0, name);
            wr_u32(b, 4, value as u32);
            wr_u32(b, 8, size as u32);
            b[12] = info;
            b[13] = other;
            wr_u16(b, 14, shndx);
        }
    }
}

/// A work-in-progress section header, with link/info kept as names until the
/// final index assignment.
#[derive(Clone, Default)]
struct SecDesc {
    name: String,
    typ: u32,
    flags: u64,
    addr: u64,
    size: u64,
    /// True if size is known precisely (don't overwrite via neighbor calc).
    has_size: bool,
    link_name: String,
    info_name: String,
    info: u32,
    entsize: u64,
    align: u64,
    /// Non-alloc appended section payload (.symtab/.strtab); offset set at emit.
    file_data: Option<Vec<u8>>,
    file_off: u64,
}

struct LoadSeg {
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

/// A caller-supplied symbol (e.g. a recovered JNI function name at a known
/// offset) to write into a real `.symtab` so IDA/Ghidra show the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectedSym {
    pub name: String,
    /// Offset within the module.
    pub value: u64,
}

/// Index of the allocatable section whose address range contains `value`, or 0
/// (SHN_UNDEF) if none does.
fn section_index_of(value: u64, secs: &[SecDesc]) -> u16 {
    for (i, s) in secs.iter().enumerate() {
        if s.flags & SHF_ALLOC == 0 || s.size == 0 {
            continue;
        }
        if value >= s.addr && value < s.addr + s.size {
            return i as u16;
        }
    }
    0
}

/// Takes a memory image of an ELF shared object (ELF32 or ELF64, little-endian)
/// as produced by dumping `[base,end)` from process memory (bytes live at file
/// offset == virtual address) and returns a copy with `p_offset` normalized and
/// a freshly reconstructed section header table appended.
///
/// The reconstruction is driven by the PT_DYNAMIC segment, which survives in a
/// memory dump: DT_SYMTAB/STRTAB/HASH/GNU_HASH/REL/RELA/RELR/JMPREL/PLTGOT/
/// VERSYM/VERDEF/VERNEED/INIT_ARRAY/FINI_ARRAY give the addresses (and often
/// sizes) of the corresponding sections. Sections whose size isn't directly
/// known are sized from the next section's start after sorting by address.
pub fn rebuild_so_sections(image: &[u8], injected: &[InjectedSym]) -> Result<Vec<u8>> {
    let mut data = image.to_vec();

    if data.len() < 16 {
        anyhow::bail!("image too small");
    }
    if data[0..4] != [0x7f, b'E', b'L', b'F'] {
        anyhow::bail!("not an ELF image");
    }
    if data[4] != 1 && data[4] != 2 {
        anyhow::bail!("unsupported EI_CLASS={}", data[4]);
    }
    if data[5] != 1 {
        anyhow::bail!("only little-endian images supported (EI_DATA={})", data[5]);
    }
    let l = ElfLayout { is64: data[4] == 2 };
    if data.len() < l.ehdr_size() {
        anyhow::bail!("image smaller than ELF header");
    }

    let phoff = l.phoff(&data);
    let mut phentsize = l.phentsize(&data);
    let phnum = l.phnum(&data);
    if phentsize == 0 {
        phentsize = l.phdr_size();
    }
    if phoff == 0 || phnum == 0 {
        anyhow::bail!("no program headers");
    }

    // Parse program headers: normalize p_offset=p_vaddr, collect LOADs + DYNAMIC.
    let mut loads: Vec<LoadSeg> = Vec::new();
    let mut dyn_addr = 0u64;
    let mut dyn_size = 0u64;
    for i in 0..phnum {
        let off = phoff as usize + i * phentsize;
        if off + l.phdr_size() > data.len() {
            break;
        }
        let ph = &data[off..];
        let p_type = l.p_type(ph);
        let p_vaddr = l.p_vaddr(ph);
        let p_filesz = l.p_filesz(ph);
        let p_memsz = l.p_memsz(ph);

        // memory image: file offset equals virtual address
        l.set_p_offset(&mut data[off..], p_vaddr);

        match p_type {
            PT_LOAD => {
                loads.push(LoadSeg {
                    vaddr: p_vaddr,
                    filesz: p_filesz,
                    memsz: p_memsz,
                });
                if p_memsz > p_filesz {
                    // in a memory image the whole segment is present
                    l.set_p_filesz(&mut data[off..], p_memsz);
                }
            }
            PT_DYNAMIC => {
                dyn_addr = p_vaddr;
                dyn_size = p_memsz;
            }
            _ => {}
        }
    }
    if dyn_addr == 0 {
        anyhow::bail!("no PT_DYNAMIC segment; cannot rebuild sections");
    }
    if loads.is_empty() {
        anyhow::bail!("no PT_LOAD segments");
    }

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut load_file_end = 0u64; // highest vaddr backed by file bytes (end of .data, before .bss)
    for seg in &loads {
        if seg.vaddr < min_vaddr {
            min_vaddr = seg.vaddr;
        }
        if seg.vaddr + seg.memsz > max_vaddr {
            max_vaddr = seg.vaddr + seg.memsz;
        }
        if seg.vaddr + seg.filesz > load_file_end {
            load_file_end = seg.vaddr + seg.filesz;
        }
    }
    let _ = min_vaddr;

    // Parse the dynamic segment (singleton tags only).
    let mut dyn_map: std::collections::HashMap<i64, u64> = std::collections::HashMap::new();
    let dyn_ent = l.dyn_size();
    let dyn_limit = (dyn_addr + dyn_size) as usize;
    let mut off = dyn_addr as usize;
    while off + dyn_ent <= data.len() && off + dyn_ent <= dyn_limit {
        let tag = l.d_tag(&data[off..]);
        let val = l.d_val(&data[off..]);
        if tag == DT_NULL {
            break;
        }
        dyn_map.insert(tag, val);
        off += dyn_ent;
    }
    let get = |tag: i64| dyn_map.get(&tag).copied();

    // Determine dynamic symbol count (needed for .dynsym / .gnu.version sizes).
    let mut symcount: usize = 0;
    if let Some(h) = get(DT_HASH) {
        if h as usize + 8 <= data.len() {
            // SysV hash: nchain (at +4) == number of symbol table entries
            symcount = rd_u32(&data, h as usize + 4) as usize;
        }
    } else if let Some(gh) = get(DT_GNU_HASH) {
        symcount = gnu_hash_sym_count(l, &data, gh as usize);
    }

    let sym_ent = l.sym_size() as u64;
    let rela_ent: u64 = if l.is64 { 24 } else { 12 };
    let rel_ent: u64 = if l.is64 { 16 } else { 8 };

    let mut secs: Vec<SecDesc> = Vec::new();
    secs.push(SecDesc::default()); // index 0 is always the NULL section

    let strtab_addr = get(DT_STRTAB);
    let strsz = get(DT_STRSZ).unwrap_or(0);

    let sized = |d: &mut SecDesc, size: u64| {
        if size > 0 {
            d.size = size;
            d.has_size = true;
        }
    };

    if let Some(gh) = get(DT_GNU_HASH) {
        secs.push(SecDesc {
            name: ".gnu.hash".into(),
            typ: SHT_GNU_HASH,
            flags: SHF_ALLOC,
            addr: gh,
            link_name: ".dynsym".into(),
            align: l.word(),
            ..Default::default()
        });
    }
    if let Some(h) = get(DT_HASH) {
        secs.push(SecDesc {
            name: ".hash".into(),
            typ: SHT_HASH,
            flags: SHF_ALLOC,
            addr: h,
            link_name: ".dynsym".into(),
            entsize: 4,
            align: l.word(),
            ..Default::default()
        });
    }
    if let Some(sym) = get(DT_SYMTAB) {
        let mut syment = get(DT_SYMENT).unwrap_or(0);
        if syment == 0 {
            syment = sym_ent;
        }
        let mut d = SecDesc {
            name: ".dynsym".into(),
            typ: SHT_DYNSYM,
            flags: SHF_ALLOC,
            addr: sym,
            link_name: ".dynstr".into(),
            entsize: syment,
            align: l.word(),
            ..Default::default()
        };
        if symcount > 0 {
            d.size = symcount as u64 * syment;
            d.has_size = true;
        }
        d.info = count_local_syms(l, &data, sym as usize, symcount) as u32;
        secs.push(d);
    }
    if let Some(addr) = strtab_addr {
        let mut d = SecDesc {
            name: ".dynstr".into(),
            typ: SHT_STRTAB,
            flags: SHF_ALLOC,
            addr,
            align: 1,
            ..Default::default()
        };
        sized(&mut d, strsz);
        secs.push(d);
    }
    if let Some(vs) = get(DT_VERSYM) {
        let mut d = SecDesc {
            name: ".gnu.version".into(),
            typ: SHT_GNU_VERSYM,
            flags: SHF_ALLOC,
            addr: vs,
            link_name: ".dynsym".into(),
            entsize: 2,
            align: 2,
            ..Default::default()
        };
        if symcount > 0 {
            d.size = symcount as u64 * 2;
            d.has_size = true;
        }
        secs.push(d);
    }
    if let Some(vd) = get(DT_VERDEF) {
        let mut d = SecDesc {
            name: ".gnu.version_d".into(),
            typ: SHT_GNU_VERDEF,
            flags: SHF_ALLOC,
            addr: vd,
            link_name: ".dynstr".into(),
            align: l.word(),
            ..Default::default()
        };
        if let Some(cnt) = get(DT_VERDEFNUM) {
            d.info = cnt as u32;
        }
        secs.push(d);
    }
    if let Some(vn) = get(DT_VERNEED) {
        let mut d = SecDesc {
            name: ".gnu.version_r".into(),
            typ: SHT_GNU_VERNEED,
            flags: SHF_ALLOC,
            addr: vn,
            link_name: ".dynstr".into(),
            align: l.word(),
            ..Default::default()
        };
        if let Some(cnt) = get(DT_VERNEEDNUM) {
            d.info = cnt as u32;
        }
        secs.push(d);
    }
    if let Some(rela) = get(DT_RELA) {
        let mut d = SecDesc {
            name: ".rela.dyn".into(),
            typ: SHT_RELA,
            flags: SHF_ALLOC,
            addr: rela,
            link_name: ".dynsym".into(),
            entsize: rela_ent,
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_RELASZ).unwrap_or(0));
        secs.push(d);
    }
    if let Some(rel) = get(DT_REL) {
        let mut d = SecDesc {
            name: ".rel.dyn".into(),
            typ: SHT_REL,
            flags: SHF_ALLOC,
            addr: rel,
            link_name: ".dynsym".into(),
            entsize: rel_ent,
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_RELSZ).unwrap_or(0));
        secs.push(d);
    }
    if let Some(relr) = get(DT_RELR) {
        let mut d = SecDesc {
            name: ".relr.dyn".into(),
            typ: SHT_RELR,
            flags: SHF_ALLOC,
            addr: relr,
            entsize: l.word(),
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_RELRSZ).unwrap_or(0));
        secs.push(d);
    }
    // Android packed relocations. The payload stays packed; we only anchor a
    // correctly typed section header at it so IDA/readelf decode it. These tags
    // are mutually exclusive with the standard DT_REL/RELA/RELR above.
    if let Some(ar) = get(DT_ANDROID_RELA) {
        let mut d = SecDesc {
            name: ".rela.dyn".into(),
            typ: SHT_ANDROID_RELA,
            flags: SHF_ALLOC,
            addr: ar,
            link_name: ".dynsym".into(),
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_ANDROID_RELASZ).unwrap_or(0));
        secs.push(d);
    }
    if let Some(ar) = get(DT_ANDROID_REL) {
        let mut d = SecDesc {
            name: ".rel.dyn".into(),
            typ: SHT_ANDROID_REL,
            flags: SHF_ALLOC,
            addr: ar,
            link_name: ".dynsym".into(),
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_ANDROID_RELSZ).unwrap_or(0));
        secs.push(d);
    }
    if let Some(ar) = get(DT_ANDROID_RELR) {
        let mut d = SecDesc {
            name: ".relr.dyn".into(),
            typ: SHT_ANDROID_RELR,
            flags: SHF_ALLOC,
            addr: ar,
            entsize: l.word(),
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_ANDROID_RELRSZ).unwrap_or(0));
        secs.push(d);
    }
    // .rela.plt / .rel.plt — the JMPREL table; its form follows DT_PLTREL
    // (defaulting to the arch norm: RELA on 64-bit, REL on 32-bit).
    let mut plt_is_rela = l.is64;
    if let Some(pr) = get(DT_PLTREL) {
        plt_is_rela = pr as i64 == DT_RELA;
    }
    let plt_rel_ent = if plt_is_rela { rela_ent } else { rel_ent };
    if let Some(jmp) = get(DT_JMPREL) {
        let (name, typ) = if plt_is_rela {
            (".rela.plt", SHT_RELA)
        } else {
            (".rel.plt", SHT_REL)
        };
        let mut d = SecDesc {
            name: name.into(),
            typ,
            flags: SHF_ALLOC | SHF_INFO_LINK,
            addr: jmp,
            link_name: ".dynsym".into(),
            info_name: ".got.plt".into(),
            entsize: plt_rel_ent,
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_PLTRELSZ).unwrap_or(0));
        secs.push(d);
    }
    if let Some(ini) = get(DT_INIT) {
        secs.push(SecDesc {
            name: ".init".into(),
            typ: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXEC,
            addr: ini,
            align: 4,
            ..Default::default()
        });
    }
    // .plt starts right after the JMPREL table; exact size finalized by the
    // neighbor pass.
    if let Some(jmp) = get(DT_JMPREL) {
        let pltrelsz = get(DT_PLTRELSZ).unwrap_or(0);
        let plt_addr = (jmp + pltrelsz + 0xf) & !0xf;
        secs.push(SecDesc {
            name: ".plt".into(),
            typ: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXEC,
            addr: plt_addr,
            entsize: 16,
            align: 16,
            ..Default::default()
        });
    }
    // .text: seeded just past .plt (or .init); size computed from neighbors.
    let mut text_start = 0u64;
    if let Some(v) = get(DT_INIT) {
        text_start = v;
    }
    if let Some(jmp) = get(DT_JMPREL) {
        let pltrelsz = get(DT_PLTRELSZ).unwrap_or(0);
        text_start = (jmp + pltrelsz + 0xf) & !0xf;
    }
    if text_start != 0 {
        secs.push(SecDesc {
            name: ".text".into(),
            typ: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXEC,
            addr: text_start + 0x40,
            align: l.word(),
            ..Default::default()
        });
    }
    if let Some(ia) = get(DT_INIT_ARRAY) {
        let mut d = SecDesc {
            name: ".init_array".into(),
            typ: SHT_INIT_ARRAY,
            flags: SHF_WRITE | SHF_ALLOC,
            addr: ia,
            entsize: l.word(),
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_INIT_ARRAYSZ).unwrap_or(0));
        secs.push(d);
    }
    if let Some(fa) = get(DT_FINI_ARRAY) {
        let mut d = SecDesc {
            name: ".fini_array".into(),
            typ: SHT_FINI_ARRAY,
            flags: SHF_WRITE | SHF_ALLOC,
            addr: fa,
            entsize: l.word(),
            align: l.word(),
            ..Default::default()
        };
        sized(&mut d, get(DT_FINI_ARRAYSZ).unwrap_or(0));
        secs.push(d);
    }
    secs.push(SecDesc {
        name: ".dynamic".into(),
        typ: SHT_DYNAMIC,
        flags: SHF_WRITE | SHF_ALLOC,
        addr: dyn_addr,
        size: dyn_size,
        has_size: true,
        link_name: ".dynstr".into(),
        entsize: dyn_ent as u64,
        align: l.word(),
        ..Default::default()
    });
    // .got.plt (DT_PLTGOT): 3 reserved GOT slots + one slot per PLT relocation.
    let mut got_plt_end = 0u64;
    if let Some(got) = get(DT_PLTGOT) {
        let mut d = SecDesc {
            name: ".got.plt".into(),
            typ: SHT_PROGBITS,
            flags: SHF_WRITE | SHF_ALLOC,
            addr: got,
            entsize: l.word(),
            align: l.word(),
            ..Default::default()
        };
        let pltrelsz = get(DT_PLTRELSZ).unwrap_or(0);
        if pltrelsz > 0 && plt_rel_ent > 0 {
            d.size = (3 + pltrelsz / plt_rel_ent) * l.word();
            d.has_size = true;
            got_plt_end = got + d.size;
        }
        secs.push(d);
    }
    // .data: from the end of .got.plt up to the file-backed load end.
    if got_plt_end > 0 && got_plt_end < load_file_end {
        secs.push(SecDesc {
            name: ".data".into(),
            typ: SHT_PROGBITS,
            flags: SHF_WRITE | SHF_ALLOC,
            addr: got_plt_end,
            align: l.word(),
            ..Default::default()
        });
    }
    // .bss: the memsz-beyond-filesz tail.
    if max_vaddr > load_file_end {
        secs.push(SecDesc {
            name: ".bss".into(),
            typ: SHT_NOBITS,
            flags: SHF_WRITE | SHF_ALLOC,
            addr: load_file_end,
            size: max_vaddr - load_file_end,
            has_size: true,
            align: l.word(),
            ..Default::default()
        });
    }

    // Sort allocatable sections by address (NULL stays at index 0).
    let mut body: Vec<SecDesc> = secs.split_off(1);
    body.sort_by_key(|s| s.addr);

    // Neighbor-based size pass: any section without a precise size grows to the
    // next section's start; precise sizes are clamped only if they'd overlap.
    for i in 0..body.len() {
        let next = if i + 1 < body.len() {
            body[i + 1].addr
        } else if body[i].typ == SHT_NOBITS {
            max_vaddr
        } else {
            load_file_end
        };
        if next <= body[i].addr {
            continue;
        }
        let gap = next - body[i].addr;
        // Unsized sections grow to the gap; precise sizes are clamped if they'd
        // overlap the next section.
        if !body[i].has_size || body[i].size > gap {
            body[i].size = gap;
        }
    }

    // Reassemble: NULL + sorted allocatable sections.
    secs.append(&mut body); // secs currently holds only [NULL]

    // Injected symbols become a real .symtab/.strtab appended at the end of the
    // file (non-alloc), so tools display caller-supplied names. st_shndx points
    // at the rebuilt section containing the value.
    if !injected.is_empty() {
        let sym_sz = l.sym_size();
        let mut strtab = vec![0u8];
        let mut symtab = vec![0u8; (injected.len() + 1) * sym_sz]; // entry 0 is the null symbol
        for (i, s) in injected.iter().enumerate() {
            let name_off = strtab.len() as u32;
            strtab.extend_from_slice(s.name.as_bytes());
            strtab.push(0);
            let shndx = section_index_of(s.value, &secs);
            l.put_sym(
                &mut symtab[(i + 1) * sym_sz..],
                name_off,
                s.value,
                0,
                0x12, // STB_GLOBAL|STT_FUNC
                0,
                shndx,
            );
        }
        secs.push(SecDesc {
            name: ".symtab".into(),
            typ: SHT_SYMTAB,
            entsize: sym_sz as u64,
            align: l.word(),
            file_data: Some(symtab),
            link_name: ".strtab".into(),
            info: 1,
            ..Default::default()
        });
        secs.push(SecDesc {
            name: ".strtab".into(),
            typ: SHT_STRTAB,
            align: 1,
            file_data: Some(strtab),
            ..Default::default()
        });
    }

    let shstrtab_idx = secs.len();
    secs.push(SecDesc {
        name: ".shstrtab".into(),
        typ: SHT_STRTAB,
        align: 1,
        ..Default::default()
    });

    // Build the section header string table.
    let mut shstrtab = vec![0u8];
    let mut name_off: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    name_off.insert(String::new(), 0);
    for s in &secs {
        if s.name.is_empty() || name_off.contains_key(&s.name) {
            continue;
        }
        name_off.insert(s.name.clone(), shstrtab.len() as u32);
        shstrtab.extend_from_slice(s.name.as_bytes());
        shstrtab.push(0);
    }

    // name -> index for link/info resolution
    let mut idx_of: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (i, s) in secs.iter().enumerate() {
        if !s.name.is_empty() {
            idx_of.insert(s.name.clone(), i as u32);
        }
    }

    // Remap each defined .dynsym entry's st_shndx to the rebuilt section that
    // contains its address so the indexes are valid again.
    if let Some(sym_addr) = get(DT_SYMTAB) {
        if symcount > 0 {
            remap_sym_shndx(l, &mut data, sym_addr as usize, symcount, &secs);
        }
    }

    // Lay out appended data at end of file: [non-alloc payloads][.shstrtab][shdr].
    for s in secs.iter_mut() {
        let Some(payload) = s.file_data.clone() else {
            continue;
        };
        while s.align > 1 && !(data.len() as u64).is_multiple_of(s.align) {
            data.push(0);
        }
        s.file_off = data.len() as u64;
        data.extend_from_slice(&payload);
    }
    let shstrtab_off = data.len() as u64;
    data.extend_from_slice(&shstrtab);
    while !data.len().is_multiple_of(l.word() as usize) {
        data.push(0);
    }
    let shoff = data.len() as u64;

    let shdr_size = l.shdr_size();
    let mut shtable = vec![0u8; secs.len() * shdr_size];
    for (i, s) in secs.iter().enumerate() {
        let b = &mut shtable[i * shdr_size..(i + 1) * shdr_size];
        let sh_name = if s.name.is_empty() {
            0
        } else {
            name_off[&s.name]
        };
        let (sh_addr, sh_offset, sh_size);
        if s.name.is_empty() {
            sh_addr = 0;
            sh_offset = 0;
            sh_size = s.size;
        } else if s.name == ".shstrtab" {
            sh_addr = 0;
            sh_offset = shstrtab_off;
            sh_size = shstrtab.len() as u64;
        } else if let Some(payload) = &s.file_data {
            // non-alloc appended section (.symtab/.strtab): file only, no addr
            sh_addr = 0;
            sh_offset = s.file_off;
            sh_size = payload.len() as u64;
        } else {
            sh_addr = s.addr;
            sh_offset = s.addr; // memory image: offset == addr
            sh_size = s.size;
        }
        let link = if s.link_name.is_empty() {
            0
        } else {
            idx_of.get(&s.link_name).copied().unwrap_or(0)
        };
        let info = if s.info_name.is_empty() {
            s.info
        } else {
            idx_of.get(&s.info_name).copied().unwrap_or(0)
        };
        l.put_shdr(
            b, sh_name, s.typ, s.flags, sh_addr, sh_offset, sh_size, link, info, s.align, s.entsize,
        );
    }
    data.extend_from_slice(&shtable);

    // Patch the ELF header to point at the rebuilt table.
    l.set_shoff(&mut data, shoff);
    l.set_shentsize(&mut data, shdr_size as u16);
    l.set_shnum(&mut data, secs.len() as u16);
    l.set_shstrndx(&mut data, shstrtab_idx as u16);

    Ok(data)
}

/// Parses rebuilt ELF bytes strictly (via the section header table, the way
/// IDA/BFD would) and returns how many dynamic symbols are readable, as a
/// confidence signal that the rebuild is loadable and useful.
pub fn self_check_so(data: &[u8]) -> Result<usize> {
    let elf = goblin::elf::Elf::parse(data).context("parse rebuilt elf")?;
    Ok(elf.dynsyms.len())
}

/// Rewrites each defined .dynsym entry's st_shndx to the rebuilt allocatable
/// section whose address range contains the symbol's value. UND (0) and
/// reserved (>=0xff00, e.g. SHN_ABS) entries are left untouched.
fn remap_sym_shndx(l: ElfLayout, data: &mut [u8], off: usize, count: usize, secs: &[SecDesc]) {
    let sym_size = l.sym_size();
    for i in 0..count {
        let o = off + i * sym_size;
        if o + sym_size > data.len() {
            break;
        }
        let shndx = l.sym_shndx(&data[o..]);
        if shndx == 0 || shndx >= 0xff00 {
            continue;
        }
        let value = l.sym_value(&data[o..]);
        for (si, s) in secs.iter().enumerate() {
            if s.flags & SHF_ALLOC == 0 || s.size == 0 {
                continue;
            }
            if value >= s.addr && value < s.addr + s.size {
                l.set_sym_shndx(&mut data[o..], si as u16);
                break;
            }
        }
    }
}

/// Derives the dynamic symbol count from a DT_GNU_HASH table (which has no
/// explicit count): walk the hash chain of the highest-indexed bucket until its
/// terminator bit is set. The bloom filter is word-sized; buckets and the chain
/// array are always 32-bit.
fn gnu_hash_sym_count(l: ElfLayout, data: &[u8], off: usize) -> usize {
    if off + 16 > data.len() {
        return 0;
    }
    let nbuckets = rd_u32(data, off) as usize;
    let symoffset = rd_u32(data, off + 4) as usize;
    let bloom_size = rd_u32(data, off + 8) as usize;
    if nbuckets == 0 {
        return symoffset;
    }
    let buckets_off = off + 16 + bloom_size * l.word() as usize;
    let chain_base = buckets_off + nbuckets * 4;
    if chain_base > data.len() {
        return 0;
    }
    let mut max_sym = 0usize;
    for i in 0..nbuckets {
        let o = buckets_off + i * 4;
        if o + 4 > data.len() {
            break;
        }
        let b = rd_u32(data, o) as usize;
        if b > max_sym {
            max_sym = b;
        }
    }
    if max_sym < symoffset {
        return symoffset;
    }
    let mut sym = max_sym;
    loop {
        let o = chain_base + (sym - symoffset) * 4;
        if o + 4 > data.len() {
            break;
        }
        let h = rd_u32(data, o);
        if h & 1 != 0 {
            break;
        }
        sym += 1;
    }
    sym + 1
}

/// Counts leading STB_LOCAL entries to seed .dynsym sh_info. Best-effort.
fn count_local_syms(l: ElfLayout, data: &[u8], off: usize, count: usize) -> usize {
    if count == 0 {
        return 1;
    }
    let sym_size = l.sym_size();
    let mut locals = 0;
    for i in 0..count {
        let o = off + i * sym_size;
        if o + sym_size > data.len() {
            break;
        }
        if l.sym_info(&data[o..]) >> 4 == 0 {
            // STB_LOCAL
            locals += 1;
        } else {
            break;
        }
    }
    if locals == 0 {
        1
    } else {
        locals
    }
}

/// Repairs a raw memory dump of a native library. Prefers a full section-header
/// rebuild; falls back to a minimal header-only fix (normalize p_offset, raise
/// p_filesz to p_memsz, zero the section header table).
pub fn fix_one_so(so_path: &Path, out_path: &Path, injected: &[InjectedSym]) -> Result<()> {
    let data = fs::read(so_path).context("read so")?;
    if data.len() < 16 || data[0..4] != [0x7f, b'E', b'L', b'F'] {
        anyhow::bail!("not a valid ELF file");
    }
    if data[4] != 1 && data[4] != 2 {
        anyhow::bail!("unsupported EI_CLASS={} (want ELF32 or ELF64)", data[4]);
    }
    let base = out_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    let base = base.as_deref().unwrap_or("?");

    // Preferred path: rebuild the section header table from the dynamic segment.
    match rebuild_so_sections(&data, injected) {
        Ok(rebuilt) => {
            fs::write(out_path, &rebuilt).context("write out")?;
            match self_check_so(&rebuilt) {
                Ok(n) => println!(
                    "[fixso] {base}: rebuilt section headers, {n} dynamic symbols readable"
                ),
                Err(e) => println!(
                    "[fixso] {base}: rebuilt section headers, but self-check couldn't read symbols: {e}"
                ),
            }
            return Ok(());
        }
        Err(e) => {
            let src = so_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned());
            println!(
                "[fixso] section rebuild unavailable for {} ({e}); falling back to header-only fix",
                src.as_deref().unwrap_or("?")
            );
        }
    }

    // Fallback: normalize p_offset and zero out the section header table.
    let mut data = data;
    let l = ElfLayout { is64: data[4] == 2 };
    if data.len() < l.ehdr_size() {
        anyhow::bail!("truncated ELF header");
    }
    let phoff = l.phoff(&data);
    let mut phentsize = l.phentsize(&data);
    let phnum = l.phnum(&data);
    if phentsize == 0 {
        phentsize = l.phdr_size();
    }
    if phoff == 0 || phnum == 0 {
        anyhow::bail!("no program headers");
    }
    let mut fixed = 0;
    for i in 0..phnum {
        let off = phoff as usize + i * phentsize;
        if off + l.phdr_size() > data.len() {
            break;
        }
        if l.p_type(&data[off..]) != PT_LOAD {
            continue;
        }
        let vaddr = l.p_vaddr(&data[off..]);
        let filesz = l.p_filesz(&data[off..]);
        let memsz = l.p_memsz(&data[off..]);
        l.set_p_offset(&mut data[off..], vaddr);
        if memsz > filesz {
            l.set_p_filesz(&mut data[off..], memsz);
        }
        fixed += 1;
    }
    if fixed == 0 {
        anyhow::bail!("no PT_LOAD segments found");
    }
    l.set_shoff(&mut data, 0);
    l.set_shnum(&mut data, 0);
    l.set_shstrndx(&mut data, 0);
    fs::write(out_path, &data).context("write out")?;
    Ok(())
}

/// Scans `dir` for dumped .so files and writes fixed copies to a "fix"
/// subdirectory. Injected symbols are module-relative, so `symbols_target`
/// (the module stem from a jni_symbols_<stem>.txt) restricts injection to the
/// matching library; an empty target with a non-empty set injects into every
/// .so (origin couldn't be determined).
pub fn fix_so_directory(dir: &Path, injected: &[InjectedSym], symbols_target: &str) -> Result<()> {
    let fix_dir = dir.join("fix");
    fs::create_dir_all(&fix_dir)
        .with_context(|| format!("failed to create fix dir {}", fix_dir.display()))?;

    let mut so_files = Vec::new();
    collect_so_files(dir, &fix_dir, &mut so_files)?;

    let mut count = 0;
    let mut injected_into = 0;
    for path in &so_files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        // Route the symbol map only to its own library.
        let syms: &[InjectedSym] = if !injected.is_empty()
            && (symbols_target.is_empty() || so_matches_module(&name, symbols_target))
        {
            injected
        } else {
            &[]
        };

        let stem = name.strip_suffix(".so").unwrap_or(&name);
        let out_path = fix_dir.join(format!("{stem}_fix.so"));
        if let Err(e) = fix_one_so(path, &out_path, syms) {
            println!("[!] Fix failed for {}: {e}", path.display());
            continue;
        }
        if !syms.is_empty() {
            injected_into += 1;
            println!("[+] Injected {} symbol(s) into {name}", syms.len());
        }
        println!("[+] Wrote {}", out_path.display());
        count += 1;
    }

    if count == 0 {
        anyhow::bail!("no .so files found in {}", dir.display());
    }
    if !injected.is_empty() && !symbols_target.is_empty() && injected_into == 0 {
        println!(
            "[!] Symbol map targets module {symbols_target:?} but no matching .so was found in {}; no symbols injected",
            dir.display()
        );
    }
    println!("[+] Fixed {count} .so file(s)");
    Ok(())
}

/// Recursively collects `*.so` files under `dir`, skipping the `fix/` output.
fn collect_so_files(dir: &Path, fix_dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if path == fix_dir {
                continue;
            }
            collect_so_files(&path, fix_dir, out)?;
        } else if path.extension().is_some_and(|e| e == "so") {
            out.push(path);
        }
    }
    Ok(())
}

/// Whether a dumped .so file belongs to module `stem`. dumpso names files
/// `so_<pid>_<base>_<size>_<stem>.so`; JNI maps are `jni_symbols_<stem>.txt`,
/// so stems are compared after sanitizing; a plain `<stem>.so` matches too.
fn so_matches_module(so_file_name: &str, stem: &str) -> bool {
    let base = sanitize_so_name(so_file_name);
    base == stem || base.ends_with(&format!("_{stem}"))
}

/// Reads an "offset name" map for `fixso --symbols`. Blank lines and `#`
/// comments are ignored. The offset is a hex module offset (0x/0X optional).
pub fn parse_symbol_file(path: &Path) -> Result<Vec<InjectedSym>> {
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let base = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let base = base.as_deref().unwrap_or("?");
    let mut syms = Vec::new();
    for (i, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(off_str), Some(name)) = (fields.next(), fields.next()) else {
            continue;
        };
        let hex = off_str
            .strip_prefix("0x")
            .or_else(|| off_str.strip_prefix("0X"))
            .unwrap_or(off_str);
        match u64::from_str_radix(hex, 16) {
            Ok(off) => syms.push(InjectedSym {
                name: name.to_string(),
                value: off,
            }),
            Err(_) => println!(
                "[!] symbols {base}:{}: skipping line, bad hex offset {off_str:?}",
                i + 1
            ),
        }
    }
    Ok(syms)
}

/// Extracts the module stem from a `jni_symbols_<stem>.txt` file so fixso can
/// inject those symbols only into the matching .so. Returns "" for any other
/// name, letting the caller fall back to injecting into every library.
pub fn module_stem_from_symbols_file(path: &Path) -> String {
    let Some(base) = path.file_name().map(|n| n.to_string_lossy()) else {
        return String::new();
    };
    let Some(stem) = base
        .strip_prefix("jni_symbols_")
        .and_then(|s| s.strip_suffix(".txt"))
    else {
        return String::new();
    };
    stem.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnu_hash_and_sysv_count_and_helpers() {
        assert!(so_matches_module("so_1234_7f00_2000_libfoo.so", "libfoo"));
        assert!(so_matches_module("libfoo.so", "libfoo"));
        assert!(!so_matches_module("libbar.so", "libfoo"));
        assert_eq!(
            module_stem_from_symbols_file(Path::new("jni_symbols_libfoo.txt")),
            "libfoo"
        );
        assert_eq!(module_stem_from_symbols_file(Path::new("other.txt")), "");
    }

    /// Builds a minimal but real ELF64 memory image (file offset == vaddr) with
    /// PT_LOAD + PT_DYNAMIC, a SysV .hash, .dynsym/.dynstr and one defined
    /// symbol, then rebuilds sections and re-parses with goblin to prove the
    /// rebuilt section header table is valid and symbols are recoverable.
    #[test]
    fn rebuild_produces_parseable_sections_and_injected_symtab() {
        let image = synth_elf64();
        let injected = vec![InjectedSym {
            name: "Java_com_x_native".to_string(),
            value: 0x1000, // inside .text region
        }];
        let rebuilt = rebuild_so_sections(&image, &injected).expect("rebuild");

        let elf = goblin::elf::Elf::parse(&rebuilt).expect("goblin parse rebuilt");
        // Section header table was rebuilt and is non-trivial.
        assert!(elf.section_headers.len() > 3, "expected rebuilt sections");
        let names: Vec<&str> = elf
            .section_headers
            .iter()
            .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name))
            .collect();
        assert!(names.contains(&".dynsym"), "sections: {names:?}");
        assert!(names.contains(&".dynstr"));
        assert!(names.contains(&".symtab"));
        assert!(names.contains(&".shstrtab"));

        // The injected symbol is readable via the rebuilt .symtab (proves the
        // section header + strtab offsets are correct).
        let injected_name = elf
            .syms
            .iter()
            .filter_map(|s| elf.strtab.get_at(s.st_name))
            .any(|n| n == "Java_com_x_native");
        assert!(injected_name, "injected symbol not found in .symtab");
    }

    // --- synthetic ELF64 builder --------------------------------------------

    fn synth_elf64() -> Vec<u8> {
        // Layout (file offset == vaddr):
        //   0x0000 ELF header (64) + 2 phdrs (56 each)
        //   0x0200 .dynstr
        //   0x0240 .dynsym (2 entries * 24)
        //   0x02c0 .hash
        //   0x0300 .dynamic
        //   0x1000 .text (fake)
        //   0x2000 end (memsz)
        let mut img = vec![0u8; 0x2000];

        // --- ELF header (ELF64, LE, ET_DYN, EM_AARCH64) ---
        img[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        img[4] = 2; // ELFCLASS64
        img[5] = 1; // little-endian
        img[6] = 1; // EI_VERSION
        wr_u16(&mut img, 16, 3); // e_type = ET_DYN
        wr_u16(&mut img, 18, 183); // e_machine = EM_AARCH64
        wr_u32(&mut img, 20, 1); // e_version
        wr_u64(&mut img, 32, 64); // e_phoff
        wr_u16(&mut img, 52, 64); // e_ehsize
        wr_u16(&mut img, 54, 56); // e_phentsize
        wr_u16(&mut img, 56, 2); // e_phnum

        // --- program headers at 0x40 ---
        // PT_LOAD covering the whole image
        let ph0 = 64;
        wr_u32(&mut img, ph0, PT_LOAD);
        wr_u32(&mut img, ph0 + 4, 5); // PF_R|PF_X
        wr_u64(&mut img, ph0 + 8, 0); // p_offset
        wr_u64(&mut img, ph0 + 16, 0); // p_vaddr
        wr_u64(&mut img, ph0 + 32, 0x2000); // p_filesz
        wr_u64(&mut img, ph0 + 40, 0x2000); // p_memsz
                                            // PT_DYNAMIC
        let ph1 = 64 + 56;
        wr_u32(&mut img, ph1, PT_DYNAMIC);
        wr_u32(&mut img, ph1 + 4, 6); // PF_R|PF_W
        wr_u64(&mut img, ph1 + 16, 0x300); // p_vaddr
        wr_u64(&mut img, ph1 + 32, 0x80); // p_filesz
        wr_u64(&mut img, ph1 + 40, 0x80); // p_memsz

        // --- .dynstr at 0x200: "\0native\0" ---
        let dynstr = 0x200usize;
        img[dynstr] = 0;
        let name = b"native";
        img[dynstr + 1..dynstr + 1 + name.len()].copy_from_slice(name);
        let strsz = 1 + name.len() + 1;

        // --- .dynsym at 0x240: null sym + 1 defined func at 0x1000 ---
        let dynsym = 0x240usize;
        let l = ElfLayout { is64: true };
        // entry 0 = null (already zero)
        // entry 1: name=1 ("native"), value=0x1000, info=STB_GLOBAL|STT_FUNC, shndx=1 (placeholder)
        l.put_sym(&mut img[dynsym + 24..], 1, 0x1000, 0, 0x12, 0, 1);
        let symcount = 2u32;

        // --- SysV .hash at 0x2c0: nbucket=1, nchain=symcount, bucket[0]=1, chain[..] ---
        let hash = 0x2c0usize;
        wr_u32(&mut img, hash, 1); // nbucket
        wr_u32(&mut img, hash + 4, symcount); // nchain == symbol count
        wr_u32(&mut img, hash + 8, 1); // bucket[0]
        wr_u32(&mut img, hash + 12, 0); // chain[0]
        wr_u32(&mut img, hash + 16, 0); // chain[1]

        // --- .dynamic at 0x300 ---
        let dynamic = 0x300usize;
        let mut d = dynamic;
        let mut put_dyn = |img: &mut [u8], d: &mut usize, tag: i64, val: u64| {
            wr_u64(img, *d, tag as u64);
            wr_u64(img, *d + 8, val);
            *d += 16;
        };
        put_dyn(&mut img, &mut d, DT_HASH, hash as u64);
        put_dyn(&mut img, &mut d, DT_STRTAB, dynstr as u64);
        put_dyn(&mut img, &mut d, DT_SYMTAB, dynsym as u64);
        put_dyn(&mut img, &mut d, DT_STRSZ, strsz as u64);
        put_dyn(&mut img, &mut d, DT_SYMENT, 24);
        put_dyn(&mut img, &mut d, DT_NULL, 0);

        img
    }
}
