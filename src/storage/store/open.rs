//! Database opening operations
//!
//! Methods for opening databases (encrypted and unencrypted).

use std::fs;
use std::path::Path;

use crate::storage::encoding::DecodeError;
use crate::storage::encryption::{PageEncryptor, SecureKey};
use crate::storage::layout::{FileHeader, SectionEntry, SegmentKind, MAGIC_ENCRYPTED};
use crate::storage::segments::actions::{ActionSegment, TraceSegment};
use crate::storage::segments::dns::DnsSegment;
use crate::storage::segments::hosts::HostSegment;
use crate::storage::segments::http::HttpSegment;
use crate::storage::segments::iocs::IocSegment;
use crate::storage::segments::loot::LootSegment;
use crate::storage::segments::mitre::MitreSegment;
use crate::storage::segments::playbooks::PlaybookSegment;
use crate::storage::segments::ports::PortSegment;
use crate::storage::segments::proxy::ProxySegment;
use crate::storage::segments::sessions::SessionSegment;
use crate::storage::segments::subdomains::SubdomainSegment;
use crate::storage::segments::tls::TlsSegment;
use crate::storage::segments::vuln::VulnSegment;
use crate::storage::segments::whois::WhoisSegment;

use super::encryption::{generate_key_check, generate_salt, EncryptionState};
use super::Database;

fn decode_err_to_io(err: DecodeError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.0)
}

impl Database {
    /// Open database with encryption (password-based)
    /// This is the recommended way to open a database.
    /// If the file doesn't exist, creates a new encrypted database.
    /// If the file exists and is encrypted, decrypts it with the password.
    /// If the file exists and is NOT encrypted, returns an error (migration not supported).
    pub fn open_encrypted<P: AsRef<Path>>(path: P, password: &str) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            // Create new encrypted database
            let salt = generate_salt();
            let key = SecureKey::from_passphrase(password, &salt);
            let encryptor = PageEncryptor::new(key);
            let key_check = generate_key_check(&encryptor);

            return Ok(Self {
                path,
                ports: PortSegment::new(),
                subdomains: SubdomainSegment::new(),
                whois: WhoisSegment::new(),
                tls: TlsSegment::new(),
                dns: DnsSegment::new(),
                http: HttpSegment::new(),
                hosts: HostSegment::new(),
                proxy: ProxySegment::new(),
                mitre: MitreSegment::new(),
                iocs: IocSegment::new(),
                vulns: VulnSegment::new(),
                sessions: SessionSegment::new(),
                playbooks: PlaybookSegment::new(),
                actions: ActionSegment::new(),
                traces: TraceSegment::new(),
                loot: LootSegment::new(),
                dirty: false,
                encryption: Some(EncryptionState {
                    encryptor,
                    salt,
                    key_check,
                }),
            });
        }

        let bytes = fs::read(&path)?;
        if bytes.len() < FileHeader::SIZE {
            // File too small, create new encrypted database
            let salt = generate_salt();
            let key = SecureKey::from_passphrase(password, &salt);
            let encryptor = PageEncryptor::new(key);
            let key_check = generate_key_check(&encryptor);

            return Ok(Self {
                path,
                ports: PortSegment::new(),
                subdomains: SubdomainSegment::new(),
                whois: WhoisSegment::new(),
                tls: TlsSegment::new(),
                dns: DnsSegment::new(),
                http: HttpSegment::new(),
                hosts: HostSegment::new(),
                proxy: ProxySegment::new(),
                mitre: MitreSegment::new(),
                iocs: IocSegment::new(),
                vulns: VulnSegment::new(),
                sessions: SessionSegment::new(),
                playbooks: PlaybookSegment::new(),
                actions: ActionSegment::new(),
                traces: TraceSegment::new(),
                loot: LootSegment::new(),
                dirty: false,
                encryption: Some(EncryptionState {
                    encryptor,
                    salt,
                    key_check,
                }),
            });
        }

        let mut header_cursor = std::io::Cursor::new(&bytes);
        let header = FileHeader::read(&mut header_cursor).map_err(decode_err_to_io)?;

        if !header.encrypted {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "database is not encrypted - cannot open with password (migration not supported)",
            ));
        }

        // Read encryption data
        let (salt, key_check) =
            FileHeader::read_encryption_data(&mut header_cursor).map_err(decode_err_to_io)?;

        // Derive key from password
        let key = SecureKey::from_passphrase(password, &salt);
        let encryptor = PageEncryptor::new(key);

        // Validate key
        if !validate_key_check(&encryptor, &key_check) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "incorrect password",
            ));
        }

        let dir_start = header.directory_offset as usize;
        let dir_len =
            header.section_count as usize * SectionEntry::size_for_version(header.version);
        if dir_start + dir_len > bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupted directory",
            ));
        }
        let directory = SectionEntry::read_all(
            &bytes[dir_start..dir_start + dir_len],
            header.section_count as usize,
            header.version,
        )
        .map_err(decode_err_to_io)?;

        let mut db = Self {
            path,
            ports: PortSegment::new(),
            subdomains: SubdomainSegment::new(),
            whois: WhoisSegment::new(),
            tls: TlsSegment::new(),
            dns: DnsSegment::new(),
            http: HttpSegment::new(),
            hosts: HostSegment::new(),
            proxy: ProxySegment::new(),
            mitre: MitreSegment::new(),
            iocs: IocSegment::new(),
            vulns: VulnSegment::new(),
            sessions: SessionSegment::new(),
            playbooks: PlaybookSegment::new(),
            actions: ActionSegment::new(),
            traces: TraceSegment::new(),
            loot: LootSegment::new(),
            dirty: false,
            encryption: Some(EncryptionState {
                encryptor,
                salt,
                key_check,
            }),
        };

        for (seg_idx, entry) in directory.iter().enumerate() {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;
            if end > bytes.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "segment out of bounds",
                ));
            }

            // Decrypt segment
            let encrypted_bytes = &bytes[start..end];
            let segment_bytes = db
                .encryption
                .as_ref()
                .unwrap()
                .encryptor
                .decrypt(seg_idx as u32, encrypted_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            deserialize_segment(&mut db, entry.kind, &segment_bytes)?;
        }

        Ok(db)
    }

    /// Open database without encryption (legacy mode for backward compatibility)
    /// WARNING: Data will be stored in plaintext. Use open_encrypted for security.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self::new_empty(path));
        }

        let bytes = fs::read(&path)?;
        if bytes.len() < FileHeader::SIZE {
            return Ok(Self::new_empty(path));
        }

        let mut header_cursor = std::io::Cursor::new(&bytes);
        let header = FileHeader::read(&mut header_cursor).map_err(decode_err_to_io)?;

        if header.encrypted {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "database is encrypted - use open_encrypted with password",
            ));
        }

        let dir_start = header.directory_offset as usize;
        let dir_len =
            header.section_count as usize * SectionEntry::size_for_version(header.version);
        if dir_start + dir_len > bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupted directory",
            ));
        }
        let directory = SectionEntry::read_all(
            &bytes[dir_start..dir_start + dir_len],
            header.section_count as usize,
            header.version,
        )
        .map_err(decode_err_to_io)?;

        let mut db = Self::new_empty(path);

        for entry in directory {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;
            if end > bytes.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "segment out of bounds",
                ));
            }
            let segment_bytes = &bytes[start..end];
            deserialize_segment(&mut db, entry.kind, segment_bytes)?;
        }

        Ok(db)
    }

    /// Check if the database is encrypted (instance method)
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Check if a database file is encrypted (static method)
    /// Returns true if the file exists and has the encrypted magic header
    pub fn is_encrypted_file<P: AsRef<Path>>(path: P) -> bool {
        use std::io::Read;

        if let Ok(mut file) = fs::File::open(path) {
            let mut magic = [0u8; 8];
            if file.read_exact(&mut magic).is_ok() {
                return &magic == MAGIC_ENCRYPTED;
            }
        }
        false
    }
}

/// Validate key against stored key check
fn validate_key_check(encryptor: &PageEncryptor, key_check: &[u8]) -> bool {
    match encryptor.decrypt(u32::MAX, key_check) {
        Ok(plaintext) => {
            let expected = [0xAAu8; 32];
            plaintext == expected
        }
        Err(_) => false,
    }
}

/// Deserialize a segment by kind into the database
fn deserialize_segment(
    db: &mut Database,
    kind: SegmentKind,
    segment_bytes: &[u8],
) -> std::io::Result<()> {
    match kind {
        SegmentKind::Ports => {
            db.ports = PortSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Subdomains => {
            db.subdomains =
                SubdomainSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Whois => {
            db.whois = WhoisSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Tls => {
            db.tls = TlsSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Dns => {
            db.dns = DnsSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Http => {
            db.http = HttpSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Host => {
            db.hosts = HostSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Proxy => {
            db.proxy = ProxySegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Mitre => {
            db.mitre = MitreSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Ioc => {
            db.iocs = IocSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Vuln => {
            db.vulns = VulnSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Sessions => {
            db.sessions = SessionSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Playbooks => {
            db.playbooks = PlaybookSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Actions => {
            db.actions = ActionSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Traces => {
            db.traces = TraceSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
        SegmentKind::Loot => {
            db.loot = LootSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
        }
    }
    Ok(())
}
