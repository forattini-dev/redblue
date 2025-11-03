use std::io::{Read, Seek, SeekFrom, Write};

use crate::storage::encoding::DecodeError;

pub const MAGIC: &[u8; 8] = b"RBSTORE0";
pub const VERSION: u16 = 1;

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
        if version != VERSION {
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
}

impl SectionEntry {
    pub const SIZE: usize = 1 + 7 + 8 + 8; // kind + padding + offset + length

    pub fn write_all(entries: &[SectionEntry], buf: &mut Vec<u8>) {
        for entry in entries {
            buf.push(entry.kind as u8);
            buf.extend_from_slice(&[0u8; 7]); // padding for alignment / future flags
            buf.extend_from_slice(&entry.offset.to_le_bytes());
            buf.extend_from_slice(&entry.length.to_le_bytes());
        }
    }

    pub fn read_all(bytes: &[u8], expected: usize) -> Result<Vec<SectionEntry>, DecodeError> {
        if bytes.len() != expected * Self::SIZE {
            return Err(DecodeError("invalid section directory size"));
        }
        let mut entries = Vec::with_capacity(expected);
        let mut offset = 0usize;
        for _ in 0..expected {
            let kind =
                SegmentKind::from_u8(bytes[offset]).map_err(|_| DecodeError("bad segment kind"))?;
            offset += 8; // kind + padding
            let seg_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let seg_length = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            entries.push(SectionEntry {
                kind,
                offset: seg_offset,
                length: seg_length,
            });
        }
        Ok(entries)
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
