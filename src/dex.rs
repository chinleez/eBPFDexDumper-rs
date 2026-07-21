use std::fmt;

pub const DEX_FILE_MAGIC: u32 = 0x0a78_6564;
/// "cdex" — ART's CompactDex. These files use a compressed CodeItem layout and
/// shared data, so they need a cdex->dex conversion before standard DEX tooling
/// (including this dumper) can read them.
pub const COMPACT_DEX_FILE_MAGIC: u32 = 0x7865_6463;
pub const DEX_HEADER_SIZE: usize = 0x70;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DexError {
    #[error("dex file too small")]
    TooSmall,
    #[error("invalid dex magic: {0:x}")]
    InvalidMagic(u32),
    #[error(
        "CompactDex (cdex) detected: this tool emits standard DEX; convert cdex->dex first (e.g. vdexExtractor) — see README"
    )]
    CompactDex,
    #[error("{0} out of bounds")]
    OutOfBounds(&'static str),
    #[error("{kind} index out of bounds: {idx}")]
    IndexOutOfBounds { kind: &'static str, idx: u32 },
    #[error("invalid ULEB128")]
    InvalidUleb128,
}

#[derive(Clone, Debug)]
pub struct DexParser<'a> {
    data: &'a [u8],
    header: DexHeader,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodInfo {
    pub class_name: String,
    pub method_name: String,
    pub return_type: String,
    pub parameters: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoInfo {
    pub return_type: String,
    pub parameters: Vec<String>,
}

impl<'a> DexParser<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, DexError> {
        let header = DexHeader::parse(data)?;
        let magic = u32::from_le_bytes(
            header.magic[0..4]
                .try_into()
                .map_err(|_| DexError::TooSmall)?,
        );
        if magic == COMPACT_DEX_FILE_MAGIC {
            return Err(DexError::CompactDex);
        }
        if magic != DEX_FILE_MAGIC {
            return Err(DexError::InvalidMagic(magic));
        }
        Ok(Self { data, header })
    }

    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn get_string(&self, string_idx: u32) -> Result<String, DexError> {
        if string_idx >= self.header.string_ids_size {
            return Err(DexError::IndexOutOfBounds {
                kind: "string",
                idx: string_idx,
            });
        }

        let offset = checked_u32_add(self.header.string_ids_off, string_idx.saturating_mul(4))
            .ok_or(DexError::OutOfBounds("string id offset"))?;
        let string_data_off = self.read_u32(offset as usize, "string id offset")?;
        self.read_string_data(string_data_off)
    }

    pub fn get_type_descriptor(&self, type_idx: u32) -> Result<String, DexError> {
        if type_idx >= self.header.type_ids_size {
            return Err(DexError::IndexOutOfBounds {
                kind: "type",
                idx: type_idx,
            });
        }

        let offset = checked_u32_add(self.header.type_ids_off, type_idx.saturating_mul(4))
            .ok_or(DexError::OutOfBounds("type id offset"))?;
        let descriptor_idx = self.read_u32(offset as usize, "type id offset")?;
        self.get_string(descriptor_idx)
    }

    pub fn get_method_info(&self, method_idx: u32) -> Result<MethodInfo, DexError> {
        if method_idx >= self.header.method_ids_size {
            return Err(DexError::IndexOutOfBounds {
                kind: "method",
                idx: method_idx,
            });
        }

        let offset = checked_u32_add(self.header.method_ids_off, method_idx.saturating_mul(8))
            .ok_or(DexError::OutOfBounds("method id offset"))? as usize;
        let item = self
            .data
            .get(offset..offset + 8)
            .ok_or(DexError::OutOfBounds("method id offset"))?;
        let class_idx = u16::from_le_bytes([item[0], item[1]]) as u32;
        let proto_idx = u16::from_le_bytes([item[2], item[3]]) as u32;
        let name_idx = u32::from_le_bytes(item[4..8].try_into().expect("slice length"));

        let class_name = self.get_type_descriptor(class_idx)?;
        let method_name = self.get_string(name_idx)?;
        let proto = self.get_proto_info(proto_idx)?;

        Ok(MethodInfo {
            class_name,
            method_name,
            return_type: proto.return_type,
            parameters: proto.parameters,
        })
    }

    pub fn get_proto_info(&self, proto_idx: u32) -> Result<ProtoInfo, DexError> {
        if proto_idx >= self.header.proto_ids_size {
            return Err(DexError::IndexOutOfBounds {
                kind: "proto",
                idx: proto_idx,
            });
        }

        let offset = checked_u32_add(self.header.proto_ids_off, proto_idx.saturating_mul(12))
            .ok_or(DexError::OutOfBounds("proto id offset"))? as usize;
        let item = self
            .data
            .get(offset..offset + 12)
            .ok_or(DexError::OutOfBounds("proto id offset"))?;
        let return_type_idx = u32::from_le_bytes(item[4..8].try_into().expect("slice length"));
        let parameters_off = u32::from_le_bytes(item[8..12].try_into().expect("slice length"));

        let return_type = self.get_type_descriptor(return_type_idx)?;
        let parameters = if parameters_off != 0 {
            self.get_parameter_types(parameters_off)?
        } else {
            Vec::new()
        };

        Ok(ProtoInfo {
            return_type,
            parameters,
        })
    }

    pub fn read_string_data(&self, offset: u32) -> Result<String, DexError> {
        let mut pos = usize::try_from(offset).map_err(|_| DexError::OutOfBounds("string data"))?;
        if pos >= self.data.len() {
            return Err(DexError::OutOfBounds("string data"));
        }

        // string_data_item: ULEB128 utf16_size then MUTF-8 bytes terminated by 0x00.
        // utf16_size counts UTF-16 code units (not bytes) so we can't use it for slicing.
        let (_utf16_len, new_pos) = read_uleb128(self.data, pos)?;
        pos = new_pos;

        let tail = self
            .data
            .get(pos..)
            .ok_or(DexError::OutOfBounds("string data"))?;
        let nul_off = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(DexError::OutOfBounds("string data"))?;
        Ok(decode_mutf8(&tail[..nul_off]))
    }

    fn get_parameter_types(&self, offset: u32) -> Result<Vec<String>, DexError> {
        let offset = offset as usize;
        let size = self.read_u32(offset, "type list size")?;
        let mut parameters = Vec::with_capacity(size as usize);

        for i in 0..size {
            let item_offset = offset
                .checked_add(4)
                .and_then(|v| v.checked_add(i as usize * 2))
                .ok_or(DexError::OutOfBounds("type item offset"))?;
            let item = self
                .data
                .get(item_offset..item_offset + 2)
                .ok_or(DexError::OutOfBounds("type item offset"))?;
            let type_idx = u16::from_le_bytes([item[0], item[1]]) as u32;
            parameters.push(self.get_type_descriptor(type_idx)?);
        }

        Ok(parameters)
    }

    fn read_u32(&self, offset: usize, label: &'static str) -> Result<u32, DexError> {
        let bytes = self
            .data
            .get(offset..offset + 4)
            .ok_or(DexError::OutOfBounds(label))?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("slice length")))
    }
}

impl DexHeader {
    pub fn parse(data: &[u8]) -> Result<Self, DexError> {
        let data = data.get(..DEX_HEADER_SIZE).ok_or(DexError::TooSmall)?;
        Ok(Self {
            magic: data[0..8].try_into().expect("slice length"),
            checksum: le32(data, 8),
            signature: data[12..32].try_into().expect("slice length"),
            file_size: le32(data, 32),
            header_size: le32(data, 36),
            endian_tag: le32(data, 40),
            link_size: le32(data, 44),
            link_off: le32(data, 48),
            map_off: le32(data, 52),
            string_ids_size: le32(data, 56),
            string_ids_off: le32(data, 60),
            type_ids_size: le32(data, 64),
            type_ids_off: le32(data, 68),
            proto_ids_size: le32(data, 72),
            proto_ids_off: le32(data, 76),
            field_ids_size: le32(data, 80),
            field_ids_off: le32(data, 84),
            method_ids_size: le32(data, 88),
            method_ids_off: le32(data, 92),
            class_defs_size: le32(data, 96),
            class_defs_off: le32(data, 100),
            data_size: le32(data, 104),
            data_off: le32(data, 108),
        })
    }
}

impl MethodInfo {
    pub fn pretty_method(&self) -> String {
        let mut out = String::with_capacity(128);
        fmt_type(&mut out, &self.return_type);
        out.push(' ');
        fmt_class_name(&mut out, &self.class_name);
        out.push('.');
        out.push_str(&self.method_name);
        out.push('(');
        for (idx, param) in self.parameters.iter().enumerate() {
            if idx > 0 {
                out.push_str(", ");
            }
            fmt_type(&mut out, param);
        }
        out.push(')');
        out
    }
}

impl fmt::Display for MethodInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pretty_method())
    }
}

/// Decode Modified UTF-8 (DEX / Java) into a Rust `String`.
///
/// MUTF-8 differs from standard UTF-8 in two places:
/// - U+0000 is encoded as the two-byte sequence `C0 80` (so a real NUL byte
///   never appears inside the data and can be used as terminator).
/// - Code points >= U+10000 are encoded as a UTF-16 surrogate pair, with each
///   surrogate written as a separate three-byte sequence (six bytes total),
///   instead of a four-byte UTF-8 sequence.
///
/// Malformed sequences are replaced with U+FFFD to match the original
/// `from_utf8_lossy` behaviour.
fn decode_mutf8(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 < 0x80 {
            out.push(b0 as char);
            i += 1;
            continue;
        }
        if b0 & 0xE0 == 0xC0 {
            if i + 2 > bytes.len() {
                out.push('\u{FFFD}');
                break;
            }
            let b1 = bytes[i + 1];
            if b1 & 0xC0 != 0x80 {
                out.push('\u{FFFD}');
                i += 1;
                continue;
            }
            let cp = (u32::from(b0 & 0x1F) << 6) | u32::from(b1 & 0x3F);
            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            i += 2;
            continue;
        }
        if b0 & 0xF0 == 0xE0 {
            if i + 3 > bytes.len() {
                out.push('\u{FFFD}');
                break;
            }
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            if b1 & 0xC0 != 0x80 || b2 & 0xC0 != 0x80 {
                out.push('\u{FFFD}');
                i += 1;
                continue;
            }
            let cu1 =
                (u32::from(b0 & 0x0F) << 12) | (u32::from(b1 & 0x3F) << 6) | u32::from(b2 & 0x3F);
            if (0xD800..=0xDBFF).contains(&cu1)
                && i + 6 <= bytes.len()
                && bytes[i + 3] & 0xF0 == 0xE0
            {
                let b3 = bytes[i + 3];
                let b4 = bytes[i + 4];
                let b5 = bytes[i + 5];
                if b4 & 0xC0 == 0x80 && b5 & 0xC0 == 0x80 {
                    let cu2 = (u32::from(b3 & 0x0F) << 12)
                        | (u32::from(b4 & 0x3F) << 6)
                        | u32::from(b5 & 0x3F);
                    if (0xDC00..=0xDFFF).contains(&cu2) {
                        let cp = 0x10000 + (((cu1 - 0xD800) << 10) | (cu2 - 0xDC00));
                        if let Some(c) = char::from_u32(cp) {
                            out.push(c);
                            i += 6;
                            continue;
                        }
                    }
                }
            }
            out.push(char::from_u32(cu1).unwrap_or('\u{FFFD}'));
            i += 3;
            continue;
        }
        out.push('\u{FFFD}');
        i += 1;
    }
    out
}

pub fn read_uleb128(data: &[u8], mut pos: usize) -> Result<(u32, usize), DexError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        let b = *data.get(pos).ok_or(DexError::InvalidUleb128)?;
        pos += 1;
        result |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err(DexError::InvalidUleb128);
        }
    }
    Ok((result, pos))
}

pub fn format_type(type_desc: &str) -> String {
    let mut out = String::new();
    fmt_type(&mut out, type_desc);
    out
}

fn fmt_type(out: &mut String, type_desc: &str) {
    match type_desc {
        "V" => out.push_str("void"),
        "Z" => out.push_str("boolean"),
        "B" => out.push_str("byte"),
        "S" => out.push_str("short"),
        "C" => out.push_str("char"),
        "I" => out.push_str("int"),
        "J" => out.push_str("long"),
        "F" => out.push_str("float"),
        "D" => out.push_str("double"),
        _ if type_desc.starts_with('[') => {
            fmt_type(out, &type_desc[1..]);
            out.push_str("[]");
        }
        _ if type_desc.len() > 2 && type_desc.starts_with('L') && type_desc.ends_with(';') => {
            fmt_class_name(out, type_desc);
        }
        _ => out.push_str(type_desc),
    }
}

fn fmt_class_name(out: &mut String, class_name: &str) {
    if class_name.len() > 2 && class_name.starts_with('L') && class_name.ends_with(';') {
        for b in class_name[1..class_name.len() - 1].bytes() {
            out.push(if b == b'/' { '.' } else { b as char });
        }
    } else {
        out.push_str(class_name);
    }
}

fn checked_u32_add(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

fn le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("slice length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_dex_magic_is_detected() {
        // A cdex header is at least DEX_HEADER_SIZE bytes; only the leading
        // magic matters for detection.
        let mut data = vec![0u8; DEX_HEADER_SIZE];
        data[..4].copy_from_slice(b"cdex");
        assert!(matches!(DexParser::new(&data), Err(DexError::CompactDex)));
    }

    #[test]
    fn uleb128_reads_multibyte_values() {
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26], 0).unwrap(), (624_485, 3));
    }

    #[test]
    fn type_format_matches_java_style() {
        assert_eq!(format_type("I"), "int");
        assert_eq!(format_type("[[I"), "int[][]");
        assert_eq!(format_type("Ljava/lang/String;"), "java.lang.String");
    }

    #[test]
    fn mutf8_decodes_ascii_and_bmp() {
        // ASCII fast path.
        assert_eq!(decode_mutf8(b"hello"), "hello");
        // 2-byte sequence: U+00E9 'é' = C3 A9.
        assert_eq!(decode_mutf8(&[0xC3, 0xA9]), "é");
        // 3-byte sequence: U+4E2D '中' = E4 B8 AD.
        assert_eq!(decode_mutf8(&[0xE4, 0xB8, 0xAD]), "中");
    }

    #[test]
    fn mutf8_decodes_embedded_nul_pair() {
        // MUTF-8 encodes U+0000 as C0 80, which must round-trip to '\0'.
        assert_eq!(decode_mutf8(&[b'a', 0xC0, 0x80, b'b']), "a\u{0000}b");
    }

    #[test]
    fn mutf8_decodes_surrogate_pair() {
        // U+1F600 grinning face. UTF-16: D83D DE00.
        // MUTF-8: ED A0 BD ED B8 80.
        let bytes = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_mutf8(&bytes), "\u{1F600}");
    }

    #[test]
    fn mutf8_replaces_malformed_with_fffd() {
        // Lone high surrogate (no low surrogate following) decodes to U+FFFD.
        assert_eq!(decode_mutf8(&[0xED, 0xA0, 0xBD]), "\u{FFFD}");
        // Truncated 2-byte sequence.
        assert_eq!(decode_mutf8(&[0xC3]), "\u{FFFD}");
        // Stray continuation byte.
        assert_eq!(decode_mutf8(&[b'a', 0x80, b'b']), "a\u{FFFD}b");
    }

    #[test]
    fn pretty_method_uses_class_and_params() {
        let info = MethodInfo {
            class_name: "Lcom/example/Foo;".to_string(),
            method_name: "bar".to_string(),
            return_type: "V".to_string(),
            parameters: vec!["I".to_string(), "Ljava/lang/String;".to_string()],
        };
        assert_eq!(
            info.pretty_method(),
            "void com.example.Foo.bar(int, java.lang.String)"
        );
    }
}
