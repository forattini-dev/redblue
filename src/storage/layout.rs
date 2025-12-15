use std::convert::TryInto;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::storage::encoding::DecodeError;

pub const MAGIC: &[u8; 8] = b"RBSTORE0";
pub const MAGIC_ENCRYPTED: &[u8; 8] = b"RBSTOREE";
pub const VERSION: u16 = 3; // Bumped for encryption support

/// Salt size for key derivation
pub const ENCRYPTION_SALT_SIZE: usize = 32;
/// Key check blob size: NONCE(12) + KEY_CHECK_LEN(32) + TAG(16) = 60
pub const KEY_CHECK_SIZE: usize = 60;

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
    Proxy = 8,
    Mitre = 9,
    Ioc = 10,
    Vuln = 11,
    Sessions = 12,
    Playbooks = 13,
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
            8 => Ok(SegmentKind::Proxy),
            9 => Ok(SegmentKind::Mitre),
            10 => Ok(SegmentKind::Ioc),
            11 => Ok(SegmentKind::Vuln),
            12 => Ok(SegmentKind::Sessions),
            13 => Ok(SegmentKind::Playbooks),
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
    pub encrypted: bool,
}

impl FileHeader {
    /// Size of header WITHOUT encryption data
    pub const SIZE: usize = 8 + 2 + 2 + 8; // magic + version + count + offset
    /// Size of encryption header data (salt + key_check)
    pub const ENCRYPTION_DATA_SIZE: usize = ENCRYPTION_SALT_SIZE + KEY_CHECK_SIZE;

    /// Total header size when encrypted
    pub fn total_header_size(&self) -> usize {
        if self.encrypted {
            Self::SIZE + Self::ENCRYPTION_DATA_SIZE
        } else {
            Self::SIZE
        }
    }

    /// Write header for encrypted file
    pub fn write_encrypted<W: Write + Seek>(
        &self,
        mut writer: W,
        salt: &[u8; ENCRYPTION_SALT_SIZE],
        key_check: &[u8],
    ) -> std::io::Result<()> {
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(MAGIC_ENCRYPTED)?;
        writer.write_all(&self.version.to_le_bytes())?;
        writer.write_all(&self.section_count.to_le_bytes())?;
        writer.write_all(&self.directory_offset.to_le_bytes())?;
        // Write encryption data
        writer.write_all(salt)?;
        writer.write_all(key_check)?;
        Ok(())
    }

    /// Write header for unencrypted file (legacy, for compatibility)
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

        let encrypted = if &magic == MAGIC_ENCRYPTED {
            true
        } else if &magic == MAGIC {
            false
        } else {
            return Err(DecodeError("invalid magic header"));
        };

        let version = read_u16(&mut reader)?;
        if version > VERSION {
            return Err(DecodeError("unsupported store version"));
        }

        let section_count = read_u16(&mut reader)?;
        let directory_offset = read_u64(&mut reader)?;

        Ok(Self {
            version,
            section_count,
            directory_offset,
            encrypted,
        })
    }

    /// Read encryption data (salt + key_check) from reader
    /// Call this after read() if encrypted == true
    pub fn read_encryption_data<R: Read>(
        mut reader: R,
    ) -> Result<([u8; ENCRYPTION_SALT_SIZE], Vec<u8>), DecodeError> {
        let mut salt = [0u8; ENCRYPTION_SALT_SIZE];
        reader
            .read_exact(&mut salt)
            .map_err(|_| DecodeError("unable to read encryption salt"))?;

        let mut key_check = vec![0u8; KEY_CHECK_SIZE];
        reader
            .read_exact(&mut key_check)
            .map_err(|_| DecodeError("unable to read key check"))?;

        Ok((salt, key_check))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ==================== SegmentKind Tests ====================

    #[test]
    fn test_segment_kind_from_u8() {
        assert_eq!(SegmentKind::from_u8(1).unwrap(), SegmentKind::Ports);
        assert_eq!(SegmentKind::from_u8(2).unwrap(), SegmentKind::Subdomains);
        assert_eq!(SegmentKind::from_u8(3).unwrap(), SegmentKind::Whois);
        assert_eq!(SegmentKind::from_u8(4).unwrap(), SegmentKind::Tls);
        assert_eq!(SegmentKind::from_u8(5).unwrap(), SegmentKind::Dns);
        assert_eq!(SegmentKind::from_u8(6).unwrap(), SegmentKind::Http);
        assert_eq!(SegmentKind::from_u8(7).unwrap(), SegmentKind::Host);
        assert_eq!(SegmentKind::from_u8(8).unwrap(), SegmentKind::Proxy);
    }

    #[test]
    fn test_segment_kind_invalid() {
        assert!(SegmentKind::from_u8(0).is_err());
        assert!(SegmentKind::from_u8(9).is_err());
        assert!(SegmentKind::from_u8(255).is_err());
    }

    // ==================== SegmentFlags Tests ====================

    #[test]
    fn test_segment_flags_none() {
        let flags = SegmentFlags::NONE;
        assert_eq!(flags.bits(), 0);
        assert!(!flags.contains(SegmentFlags::HAS_INDEX));
        assert!(!flags.contains(SegmentFlags::HAS_FILTER));
        assert!(!flags.contains(SegmentFlags::HAS_METADATA));
    }

    #[test]
    fn test_segment_flags_insert() {
        let mut flags = SegmentFlags::NONE;
        flags.insert(SegmentFlags::HAS_INDEX);
        assert!(flags.contains(SegmentFlags::HAS_INDEX));
        assert!(!flags.contains(SegmentFlags::HAS_FILTER));

        flags.insert(SegmentFlags::HAS_FILTER);
        assert!(flags.contains(SegmentFlags::HAS_INDEX));
        assert!(flags.contains(SegmentFlags::HAS_FILTER));
    }

    #[test]
    fn test_segment_flags_from_bits() {
        let flags = SegmentFlags::from_bits(0b0000_0111);
        assert!(flags.contains(SegmentFlags::HAS_INDEX));
        assert!(flags.contains(SegmentFlags::HAS_FILTER));
        assert!(flags.contains(SegmentFlags::HAS_METADATA));
    }

    #[test]
    fn test_segment_flags_default() {
        let flags = SegmentFlags::default();
        assert_eq!(flags.bits(), 0);
    }

    // ==================== FileHeader Tests ====================

    #[test]
    fn test_file_header_size() {
        assert_eq!(FileHeader::SIZE, 20);
    }

    #[test]
    fn test_file_header_write_read() {
        let header = FileHeader {
            version: VERSION,
            section_count: 5,
            directory_offset: 12345,
            encrypted: false,
        };

        let mut buf = Cursor::new(vec![0u8; FileHeader::SIZE]);
        header.write(&mut buf).unwrap();

        buf.seek(SeekFrom::Start(0)).unwrap();
        let decoded = FileHeader::read(&mut buf).unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.section_count, 5);
        assert_eq!(decoded.directory_offset, 12345);
        assert!(!decoded.encrypted);
    }

    #[test]
    fn test_file_header_encrypted() {
        let header = FileHeader {
            version: VERSION,
            section_count: 3,
            directory_offset: 5000,
            encrypted: true,
        };

        let salt = [0xABu8; ENCRYPTION_SALT_SIZE];
        let key_check = vec![0xCDu8; KEY_CHECK_SIZE];

        let total_size = FileHeader::SIZE + FileHeader::ENCRYPTION_DATA_SIZE;
        let mut buf = Cursor::new(vec![0u8; total_size]);
        header.write_encrypted(&mut buf, &salt, &key_check).unwrap();

        buf.seek(SeekFrom::Start(0)).unwrap();
        let decoded = FileHeader::read(&mut buf).unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.section_count, 3);
        assert_eq!(decoded.directory_offset, 5000);
        assert!(decoded.encrypted);

        // Read encryption data
        let (decoded_salt, decoded_key_check) = FileHeader::read_encryption_data(&mut buf).unwrap();
        assert_eq!(decoded_salt, salt);
        assert_eq!(decoded_key_check, key_check);
    }

    #[test]
    fn test_file_header_invalid_magic() {
        let mut buf = Cursor::new(b"INVALID0".to_vec());
        buf.write_all(&[0u8; 12]).unwrap();
        buf.seek(SeekFrom::Start(0)).unwrap();

        assert!(FileHeader::read(&mut buf).is_err());
    }

    #[test]
    fn test_file_header_version_1_supported() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&1u16.to_le_bytes()); // version 1
        buf.extend_from_slice(&3u16.to_le_bytes()); // section_count
        buf.extend_from_slice(&1000u64.to_le_bytes()); // directory_offset

        let header = FileHeader::read(Cursor::new(buf)).unwrap();
        assert_eq!(header.version, 1);
        assert!(!header.encrypted);
    }

    #[test]
    fn test_file_header_unsupported_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&99u16.to_le_bytes()); // unsupported version
        buf.extend_from_slice(&[0u8; 10]);

        assert!(FileHeader::read(Cursor::new(buf)).is_err());
    }

    #[test]
    fn test_total_header_size() {
        let unencrypted = FileHeader {
            version: VERSION,
            section_count: 0,
            directory_offset: 0,
            encrypted: false,
        };
        assert_eq!(unencrypted.total_header_size(), FileHeader::SIZE);

        let encrypted = FileHeader {
            version: VERSION,
            section_count: 0,
            directory_offset: 0,
            encrypted: true,
        };
        assert_eq!(encrypted.total_header_size(), FileHeader::SIZE + FileHeader::ENCRYPTION_DATA_SIZE);
    }

    // ==================== SectionEntry Tests ====================

    #[test]
    fn test_section_entry_new() {
        let entry = SectionEntry::new(SegmentKind::Ports, 100, 500);
        assert_eq!(entry.kind, SegmentKind::Ports);
        assert_eq!(entry.offset, 100);
        assert_eq!(entry.length, 500);
        assert_eq!(entry.index_offset, 0);
        assert_eq!(entry.index_length, 0);
        assert_eq!(entry.flags.bits(), 0);
    }

    #[test]
    fn test_section_entry_size_v1() {
        assert_eq!(SectionEntry::size_for_version(1), SectionEntry::SIZE_V1);
    }

    #[test]
    fn test_section_entry_size_v2() {
        assert_eq!(SectionEntry::size_for_version(2), SectionEntry::SIZE_V2);
    }

    #[test]
    fn test_section_entry_write_read_v2() {
        let entries = vec![
            SectionEntry {
                kind: SegmentKind::Ports,
                offset: 100,
                length: 500,
                index_offset: 600,
                index_length: 50,
                metadata_offset: 650,
                metadata_length: 20,
                flags: SegmentFlags::HAS_INDEX,
            },
            SectionEntry {
                kind: SegmentKind::Subdomains,
                offset: 700,
                length: 300,
                index_offset: 0,
                index_length: 0,
                metadata_offset: 0,
                metadata_length: 0,
                flags: SegmentFlags::NONE,
            },
        ];

        let mut buf = Vec::new();
        SectionEntry::write_all(&entries, &mut buf, 2);

        let decoded = SectionEntry::read_all(&buf, 2, 2).unwrap();
        assert_eq!(decoded.len(), 2);

        assert_eq!(decoded[0].kind, SegmentKind::Ports);
        assert_eq!(decoded[0].offset, 100);
        assert_eq!(decoded[0].length, 500);
        assert_eq!(decoded[0].index_offset, 600);
        assert!(decoded[0].flags.contains(SegmentFlags::HAS_INDEX));

        assert_eq!(decoded[1].kind, SegmentKind::Subdomains);
        assert_eq!(decoded[1].offset, 700);
    }

    #[test]
    fn test_section_entry_write_read_v1() {
        let entries = vec![
            SectionEntry::new(SegmentKind::Dns, 200, 400),
        ];

        let mut buf = Vec::new();
        SectionEntry::write_all(&entries, &mut buf, 1);

        let decoded = SectionEntry::read_all(&buf, 1, 1).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].kind, SegmentKind::Dns);
        assert_eq!(decoded[0].offset, 200);
        assert_eq!(decoded[0].length, 400);
    }

    #[test]
    fn test_section_entry_invalid_size() {
        let buf = vec![0u8; 10]; // Too small
        assert!(SectionEntry::read_all(&buf, 2, 2).is_err());
    }

    // ==================== SegmentMetadata Tests ====================

    #[test]
    fn test_metadata_encode_decode_empty() {
        let pairs: Vec<(String, String)> = vec![];
        let encoded = SegmentMetadata::encode(&pairs);
        assert!(encoded.is_empty());

        let decoded = SegmentMetadata::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_metadata_encode_decode() {
        let pairs = vec![
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value2".to_string()),
            ("target".to_string(), "example.com".to_string()),
        ];

        let encoded = SegmentMetadata::encode(&pairs);
        let decoded = SegmentMetadata::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], ("key1".to_string(), "value1".to_string()));
        assert_eq!(decoded[1], ("key2".to_string(), "value2".to_string()));
        assert_eq!(decoded[2], ("target".to_string(), "example.com".to_string()));
    }

    #[test]
    fn test_metadata_decode_invalid_magic() {
        let buf = b"XXXX\x01\x00key\x00\x03val\x00\x03".to_vec();
        assert!(SegmentMetadata::decode(&buf).is_err());
    }

    #[test]
    fn test_metadata_decode_truncated() {
        let buf = b"MDv1\x01".to_vec(); // Too short
        assert!(SegmentMetadata::decode(&buf).is_err());
    }

    #[test]
    fn test_metadata_with_unicode() {
        let pairs = vec![
            ("emoji".to_string(), "🚀🔥".to_string()),
            ("日本語".to_string(), "テスト".to_string()),
        ];

        let encoded = SegmentMetadata::encode(&pairs);
        let decoded = SegmentMetadata::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].1, "🚀🔥");
        assert_eq!(decoded[1].0, "日本語");
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn test_read_u16() {
        let buf = vec![0x34, 0x12]; // Little-endian 0x1234
        let result = read_u16(Cursor::new(buf)).unwrap();
        assert_eq!(result, 0x1234);
    }

    #[test]
    fn test_read_u64() {
        let buf = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let result = read_u64(Cursor::new(buf)).unwrap();
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_read_u16_eof() {
        let buf = vec![0x34]; // Only 1 byte
        assert!(read_u16(Cursor::new(buf)).is_err());
    }
}
