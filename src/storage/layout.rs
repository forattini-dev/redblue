use std::convert::TryInto;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::storage::encoding::DecodeError;

pub const MAGIC: &[u8; 8] = b"RBSTORE0";
pub const VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentKind {
    Ports = 1,
    Subdomains = 2,
    Whois = 3,
    Tls = 4,
    Dns = 5,
    Http = 6,
    Host = 7,
}

impl SegmentKind {
    pub fn from_u8(value: u8) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(SegmentKind::Ports),
            2 => Ok(SegmentKind::Subdomains),
            3 => Ok(SegmentKind::Whois),
            4 => Ok(SegmentKind::Tls),
            5 => Ok(SegmentKind::Dns),
            6 => Ok(SegmentKind::Http),
            7 => Ok(SegmentKind::Host),
            _ => Err(DecodeError("unknown segment kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentFlags(u8);

impl SegmentFlags {
    pub const NONE: SegmentFlags = SegmentFlags(0);
    pub const HAS_INDEX: SegmentFlags = SegmentFlags(0b0000_0001);
    pub const HAS_FILTER: SegmentFlags = SegmentFlags(0b0000_0010);
    pub const HAS_METADATA: SegmentFlags = SegmentFlags(0b0000_0100);

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> SegmentFlags {
        SegmentFlags(bits)
    }

    pub fn contains(self, other: SegmentFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn insert(&mut self, other: SegmentFlags) {
        self.0 |= other.0;
    }
}

impl Default for SegmentFlags {
    fn default() -> Self {
        SegmentFlags::NONE
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub version: u16,
    pub section_count: u16,
    pub directory_offset: u64,
}

impl FileHeader {
    pub const SIZE: usize = 8 + 2 + 2 + 8; // magic + version + count + offset

    pub fn write<W: Write + Seek>(&self, mut writer: W) -> std::io::Result<()> {
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(MAGIC)?;
        writer.write_all(&self.version.to_le_bytes())?;
        writer.write_all(&self.section_count.to_le_bytes())?;
        writer.write_all(&self.directory_offset.to_le_bytes())?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self, DecodeError> {
        let mut magic = [0u8; 8];
        reader
            .read_exact(&mut magic)
            .map_err(|_| DecodeError("unable to read file header"))?;
        if &magic != MAGIC {
            return Err(DecodeError("invalid magic header"));
        }

        let version = read_u16(&mut reader)?;
        if version != VERSION && version != 1 {
            return Err(DecodeError("unsupported store version"));
        }

        let section_count = read_u16(&mut reader)?;
        let directory_offset = read_u64(&mut reader)?;

        Ok(Self {
            version,
            section_count,
            directory_offset,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SectionEntry {
    pub kind: SegmentKind,
    pub offset: u64,
    pub length: u64,
    pub index_offset: u64,
    pub index_length: u64,
    pub metadata_offset: u64,
    pub metadata_length: u64,
    pub flags: SegmentFlags,
}

impl SectionEntry {
    pub const SIZE_V1: usize = 1 + 7 + 8 + 8;
    pub const SIZE_V2: usize = 1 + 1 + 6 + (8 * 6); // kind + flags + padding + offsets/lengths

    pub fn new(kind: SegmentKind, offset: u64, length: u64) -> Self {
        Self {
            kind,
            offset,
            length,
            index_offset: 0,
            index_length: 0,
            metadata_offset: 0,
            metadata_length: 0,
            flags: SegmentFlags::NONE,
        }
    }

    pub fn size_for_version(version: u16) -> usize {
        if version >= 2 {
            Self::SIZE_V2
        } else {
            Self::SIZE_V1
        }
    }

    pub fn write_all(entries: &[SectionEntry], buf: &mut Vec<u8>, version: u16) {
        if version >= 2 {
            for entry in entries {
                buf.push(entry.kind as u8);
                buf.push(entry.flags.bits());
                buf.extend_from_slice(&[0u8; 6]);
                buf.extend_from_slice(&entry.offset.to_le_bytes());
                buf.extend_from_slice(&entry.length.to_le_bytes());
                buf.extend_from_slice(&entry.index_offset.to_le_bytes());
                buf.extend_from_slice(&entry.index_length.to_le_bytes());
                buf.extend_from_slice(&entry.metadata_offset.to_le_bytes());
                buf.extend_from_slice(&entry.metadata_length.to_le_bytes());
            }
        } else {
            for entry in entries {
                buf.push(entry.kind as u8);
                buf.extend_from_slice(&[0u8; 7]);
                buf.extend_from_slice(&entry.offset.to_le_bytes());
                buf.extend_from_slice(&entry.length.to_le_bytes());
            }
        }
    }

    pub fn read_all(
        bytes: &[u8],
        expected: usize,
        version: u16,
    ) -> Result<Vec<SectionEntry>, DecodeError> {
        let entry_size = Self::size_for_version(version);
        if bytes.len() != expected * entry_size {
            return Err(DecodeError("invalid section directory size"));
        }
        let mut entries = Vec::with_capacity(expected);
        let mut offset = 0usize;
        for _ in 0..expected {
            let kind =
                SegmentKind::from_u8(bytes[offset]).map_err(|_| DecodeError("bad segment kind"))?;
            if version >= 2 {
                let flags = SegmentFlags::from_bits(bytes[offset + 1]);
                offset += 8; // kind + flags + padding
                let seg_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let seg_length = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let index_offset =
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let index_length =
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let metadata_offset =
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let metadata_length =
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                entries.push(SectionEntry {
                    kind,
                    offset: seg_offset,
                    length: seg_length,
                    index_offset,
                    index_length,
                    metadata_offset,
                    metadata_length,
                    flags,
                });
            } else {
                offset += 8; // kind + padding
                let seg_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let seg_length = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                entries.push(SectionEntry {
                    kind,
                    offset: seg_offset,
                    length: seg_length,
                    index_offset: 0,
                    index_length: 0,
                    metadata_offset: 0,
                    metadata_length: 0,
                    flags: SegmentFlags::NONE,
                });
            }
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentMetadata;

impl SegmentMetadata {
    const MAGIC: [u8; 4] = *b"MDv1";

    pub fn encode(pairs: &[(String, String)]) -> Vec<u8> {
        if pairs.is_empty() {
            return Vec::new();
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&Self::MAGIC);
        let count = pairs.len() as u16;
        buf.extend_from_slice(&count.to_le_bytes());
        for (key, value) in pairs {
            let key_bytes = key.as_bytes();
            let value_bytes = value.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(key_bytes);
            buf.extend_from_slice(&(value_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(value_bytes);
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Vec<(String, String)>, DecodeError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if bytes.len() < 6 {
            return Err(DecodeError("metadata block too small"));
        }
        if &bytes[..4] != Self::MAGIC {
            return Err(DecodeError("invalid metadata magic"));
        }
        let mut offset = 4;
        let count = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let mut pairs = Vec::with_capacity(count);
        for _ in 0..count {
            if offset + 2 > bytes.len() {
                return Err(DecodeError("metadata truncated"));
            }
            let key_len =
                u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + key_len > bytes.len() {
                return Err(DecodeError("metadata key overflow"));
            }
            let key = std::str::from_utf8(&bytes[offset..offset + key_len])
                .map_err(|_| DecodeError("metadata key invalid utf-8"))?
                .to_string();
            offset += key_len;

            if offset + 2 > bytes.len() {
                return Err(DecodeError("metadata truncated"));
            }
            let value_len =
                u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + value_len > bytes.len() {
                return Err(DecodeError("metadata value overflow"));
            }
            let value = std::str::from_utf8(&bytes[offset..offset + value_len])
                .map_err(|_| DecodeError("metadata value invalid utf-8"))?
                .to_string();
            offset += value_len;

            pairs.push((key, value));
        }
        Ok(pairs)
    }
}

fn read_u16<R: Read>(mut reader: R) -> Result<u16, DecodeError> {
    let mut buf = [0u8; 2];
    reader
        .read_exact(&mut buf)
        .map_err(|_| DecodeError("unexpected eof (u16)"))?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u64<R: Read>(mut reader: R) -> Result<u64, DecodeError> {
    let mut buf = [0u8; 8];
    reader
        .read_exact(&mut buf)
        .map_err(|_| DecodeError("unexpected eof (u64)"))?;
    Ok(u64::from_le_bytes(buf))
}
