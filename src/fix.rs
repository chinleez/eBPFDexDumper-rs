use crate::dex::{read_uleb128, DexParser};
use adler2::Adler32;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MethodCodeRecord {
    pub name: String,
    pub method_idx: u32,
    pub code: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixStats {
    pub applied: usize,
    pub skipped: usize,
    pub length_mismatch: usize,
}

pub fn fix_dex_directory(output_dir: &Path) -> Result<()> {
    let pairs = find_pairs(output_dir)?;
    if pairs.is_empty() {
        anyhow::bail!("no dex_*_code.json found in {}", output_dir.display());
    }

    let fix_dir = output_dir.join("fix");
    fs::create_dir_all(&fix_dir)
        .with_context(|| format!("failed to create {}", fix_dir.display()))?;

    for (base, json_path) in pairs {
        let dex_path = output_dir.join(format!("{base}.dex"));
        if !dex_path.exists() {
            continue;
        }
        let out_path = fix_dir.join(format!("{base}_fix.dex"));
        match fix_one_dex(&dex_path, &json_path, &out_path) {
            Ok(stats) => {
                println!(
                    "Applied: {}, Skipped: {}, LengthMismatch: {} for {}",
                    stats.applied,
                    stats.skipped,
                    stats.length_mismatch,
                    dex_path.file_name().unwrap_or_default().to_string_lossy()
                );
                println!("[+] Wrote {}", out_path.display());
            }
            Err(err) => {
                println!("[!] Fix failed for {}: {err:#}", dex_path.display());
            }
        }
    }

    Ok(())
}

pub fn fix_one_dex(dex_path: &Path, json_path: &Path, out_path: &Path) -> Result<FixStats> {
    let mut dex_bytes =
        fs::read(dex_path).with_context(|| format!("failed to read {}", dex_path.display()))?;
    let stats = fix_one_dex_bytes_from_json_file(&mut dex_bytes, json_path)?;
    fs::write(out_path, &dex_bytes)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    Ok(stats)
}

pub fn fix_one_dex_bytes_from_json_file(
    dex_bytes: &mut [u8],
    json_path: &Path,
) -> Result<FixStats> {
    let parser = DexParser::new(dex_bytes)?;
    let method2off = build_method_code_off_map(&parser)?;
    let records = read_records(json_path)?;
    let stats = apply_records_to_dex(dex_bytes, &method2off, &records)?;
    recalc_dex_header(dex_bytes);
    Ok(stats)
}

pub fn apply_records_to_dex(
    dex_bytes: &mut [u8],
    method2off: &HashMap<u32, u32>,
    records: &[MethodCodeRecord],
) -> Result<FixStats> {
    let mut stats = FixStats::default();
    for record in records {
        let Some(&code_off) = method2off.get(&record.method_idx) else {
            stats.skipped += 1;
            continue;
        };
        if code_off == 0 || code_off as usize + 0x10 > dex_bytes.len() {
            stats.skipped += 1;
            continue;
        }

        let code_off = code_off as usize;
        let insns_units = le32(&dex_bytes[code_off + 0x0c..]) as usize;
        let expected_len = insns_units.saturating_mul(2);
        let code_bytes = match hex::decode(&record.code) {
            Ok(code_bytes) => code_bytes,
            Err(_) => {
                stats.skipped += 1;
                continue;
            }
        };
        let write_len = expected_len.min(code_bytes.len());
        let insns_start = code_off + 0x10;
        let insns_end = insns_start.saturating_add(expected_len);
        if insns_end > dex_bytes.len() {
            stats.skipped += 1;
            continue;
        }
        if write_len != code_bytes.len() || write_len != expected_len {
            stats.length_mismatch += 1;
        }
        dex_bytes[insns_start..insns_start + write_len].copy_from_slice(&code_bytes[..write_len]);
        if write_len < expected_len {
            dex_bytes[insns_start + write_len..insns_end].fill(0);
        }
        stats.applied += 1;
    }
    Ok(stats)
}

pub fn build_method_code_off_map(parser: &DexParser<'_>) -> Result<HashMap<u32, u32>> {
    let mut result = HashMap::new();
    let data = parser.data();
    let header = parser.header();
    const CLASS_DEF_SIZE: usize = 32;

    for idx in 0..header.class_defs_size {
        let off = header.class_defs_off as usize + idx as usize * CLASS_DEF_SIZE;
        let class_def = data
            .get(off..off + CLASS_DEF_SIZE)
            .context("class_def out of bounds")?;
        let class_data_off = le32(&class_def[24..]);
        if class_data_off == 0 {
            continue;
        }

        let mut pos = class_data_off as usize;
        let (static_fields_size, next) = read_uleb128(data, pos)?;
        pos = next;
        let (instance_fields_size, next) = read_uleb128(data, pos)?;
        pos = next;
        let (direct_methods_size, next) = read_uleb128(data, pos)?;
        pos = next;
        let (virtual_methods_size, next) = read_uleb128(data, pos)?;
        pos = next;

        skip_fields(data, &mut pos, static_fields_size)?;
        skip_fields(data, &mut pos, instance_fields_size)?;
        read_methods(data, &mut pos, direct_methods_size, &mut result)?;
        read_methods(data, &mut pos, virtual_methods_size, &mut result)?;
    }

    Ok(result)
}

pub fn recalc_dex_header(dex: &mut [u8]) {
    if dex.len() < 32 {
        return;
    }

    let mut sha1 = Sha1::new();
    sha1.update(&dex[32..]);
    let sig = sha1.finalize();
    dex[12..32].copy_from_slice(&sig);

    let mut adler = Adler32::new();
    adler.write_slice(&dex[12..]);
    let sum = adler.checksum();
    dex[8] = sum as u8;
    dex[9] = (sum >> 8) as u8;
    dex[10] = (sum >> 16) as u8;
    dex[11] = (sum >> 24) as u8;
}

fn read_records(json_path: &Path) -> Result<Vec<MethodCodeRecord>> {
    let file = fs::File::open(json_path)
        .with_context(|| format!("failed to open {}", json_path.display()))?;
    serde_json::from_reader(file)
        .with_context(|| format!("failed to parse {}", json_path.display()))
}

fn find_pairs(output_dir: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut pairs = HashMap::new();
    collect_pairs(output_dir, &mut pairs)?;
    Ok(pairs)
}

fn collect_pairs(dir: &Path, pairs: &mut HashMap<String, PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_pairs(&entry.path(), pairs)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(base) = dex_code_json_base(&name) {
            pairs.insert(base, entry.path());
        }
    }
    Ok(())
}

fn dex_code_json_base(name: &str) -> Option<String> {
    if !name.starts_with("dex_") || !name.ends_with("_code.json") {
        return None;
    }
    let stem = name.strip_suffix("_code.json")?;
    let mut parts = stem.split('_');
    if parts.next()? != "dex" {
        return None;
    }
    let begin = parts.next()?;
    let size = parts.next()?;
    if parts.next().is_some() || begin.is_empty() || size.is_empty() {
        return None;
    }
    if begin.bytes().all(|b| b.is_ascii_hexdigit()) && size.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(stem.to_string())
    } else {
        None
    }
}

fn skip_fields(data: &[u8], pos: &mut usize, count: u32) -> Result<()> {
    for _ in 0..count {
        let (_, next) = read_uleb128(data, *pos)?;
        *pos = next;
        let (_, next) = read_uleb128(data, *pos)?;
        *pos = next;
    }
    Ok(())
}

fn read_methods(
    data: &[u8],
    pos: &mut usize,
    count: u32,
    result: &mut HashMap<u32, u32>,
) -> Result<()> {
    let mut last_method = 0u32;
    for _ in 0..count {
        let (diff, next) = read_uleb128(data, *pos)?;
        *pos = next;
        last_method = last_method.saturating_add(diff);
        let (_, next) = read_uleb128(data, *pos)?;
        *pos = next;
        let (code_off, next) = read_uleb128(data, *pos)?;
        *pos = next;
        result.insert(last_method, code_off);
    }
    Ok(())
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[0..4].try_into().expect("slice length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::DEX_HEADER_SIZE;

    #[test]
    fn parses_code_json_base() {
        assert_eq!(
            dex_code_json_base("dex_1234_abcd_code.json").as_deref(),
            Some("dex_1234_abcd")
        );
        assert!(dex_code_json_base("dex_1234_nope_code.json").is_none());
        assert!(dex_code_json_base("not_dex_1234_abcd_code.json").is_none());
    }

    #[test]
    fn applies_code_record_and_recalculates_header() {
        let mut dex = minimal_dex_with_code_item();
        let parser = DexParser::new(&dex).unwrap();
        let map = build_method_code_off_map(&parser).unwrap();
        assert_eq!(map.get(&0), Some(&0x90));

        let records = vec![MethodCodeRecord {
            name: "void Lx;.m()".to_string(),
            method_idx: 0,
            code: "01020304".to_string(),
        }];
        let stats = apply_records_to_dex(&mut dex, &map, &records).unwrap();
        assert_eq!(
            stats,
            FixStats {
                applied: 1,
                skipped: 0,
                length_mismatch: 0
            }
        );
        assert_eq!(&dex[0xa0..0xa4], &[1, 2, 3, 4]);

        recalc_dex_header(&mut dex);
        assert_ne!(&dex[12..32], &[0u8; 20]);
        assert_ne!(&dex[8..12], &[0u8; 4]);
    }

    fn minimal_dex_with_code_item() -> Vec<u8> {
        let mut dex = vec![0u8; 0xb0];
        let dex_len = dex.len() as u32;
        dex[0..8].copy_from_slice(b"dex\n035\0");
        put_u32(&mut dex, 32, dex_len);
        put_u32(&mut dex, 36, DEX_HEADER_SIZE as u32);
        put_u32(&mut dex, 96, 1);
        put_u32(&mut dex, 100, 0x70);

        // class_def_item.class_data_off at +24.
        put_u32(&mut dex, 0x70 + 24, 0x80);

        // class_data_item: 0 static, 0 instance, 1 direct, 0 virtual.
        dex[0x80] = 0;
        dex[0x81] = 0;
        dex[0x82] = 1;
        dex[0x83] = 0;
        // encoded_method: method_idx_diff=0, access_flags=0, code_off=0x90.
        dex[0x84] = 0;
        dex[0x85] = 0;
        dex[0x86] = 0x90 | 0x80;
        dex[0x87] = 0x01;

        // code_item.insns_size at +0x0c. Two code units = four bytes.
        put_u32(&mut dex, 0x90 + 0x0c, 2);
        dex
    }

    fn put_u32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
}
