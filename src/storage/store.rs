use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::storage::encoding::DecodeError;
use crate::storage::encryption::{PageEncryptor, SecureKey};
use crate::storage::layout::{
    FileHeader, SectionEntry, SegmentFlags, SegmentKind, SegmentMetadata, ENCRYPTION_SALT_SIZE,
};
use crate::storage::records::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, IocRecord, MitreAttackRecord,
    PlaybookRunRecord, PortScanRecord, ProxyConnectionRecord, ProxyHttpRequestRecord,
    ProxyHttpResponseRecord, ProxyWebSocketRecord, SessionRecord, SubdomainRecord, SubdomainSource,
    TlsScanRecord, VulnerabilityRecord, WhoisRecord,
};
use crate::storage::segments::hosts::HostSegment;
use crate::storage::segments::iocs::IocSegment;
use crate::storage::segments::mitre::MitreSegment;
use crate::storage::segments::playbooks::PlaybookSegment;
use crate::storage::segments::ports::PortSegment;
use crate::storage::segments::proxy::ProxySegment;
use crate::storage::segments::sessions::SessionSegment;
use crate::storage::segments::subdomains::SubdomainSegment;
use crate::storage::segments::tls::TlsSegment;
use crate::storage::segments::vuln::VulnSegment;
use crate::storage::segments::whois::WhoisSegment;
use crate::storage::segments::{dns::DnsSegment, http::HttpSegment};

/// Encryption state for the database
struct EncryptionState {
    encryptor: PageEncryptor,
    salt: [u8; ENCRYPTION_SALT_SIZE],
    key_check: Vec<u8>,
}

#[derive(Debug)]
pub struct Database {
    path: PathBuf,
    ports: PortSegment,
    subdomains: SubdomainSegment,
    whois: WhoisSegment,
    tls: TlsSegment,
    dns: DnsSegment,
    http: HttpSegment,
    hosts: HostSegment,
    proxy: ProxySegment,
    mitre: MitreSegment,
    iocs: IocSegment,
    vulns: VulnSegment,
    sessions: SessionSegment,
    playbooks: PlaybookSegment,
    dirty: bool,
    /// Encryption state - Some = encrypted database
    #[allow(dead_code)]
    encryption: Option<EncryptionState>,
}

impl std::fmt::Debug for EncryptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionState")
            .field("salt", &"[REDACTED]")
            .field("key_check_len", &self.key_check.len())
            .finish()
    }
}

impl Database {
    /// Generate a random salt for key derivation
    fn generate_salt() -> [u8; ENCRYPTION_SALT_SIZE] {
        let mut salt = [0u8; ENCRYPTION_SALT_SIZE];
        let uuid1 = uuid::Uuid::new_v4();
        let uuid2 = uuid::Uuid::new_v4();
        salt[0..16].copy_from_slice(uuid1.as_bytes());
        salt[16..32].copy_from_slice(uuid2.as_bytes());
        salt
    }

    /// Generate key check blob using a known value
    fn generate_key_check(encryptor: &PageEncryptor) -> Vec<u8> {
        let known_value = [0xAAu8; 32];
        encryptor.encrypt(u32::MAX, &known_value)
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

    /// Open database with encryption (password-based)
    /// This is the recommended way to open a database.
    /// If the file doesn't exist, creates a new encrypted database.
    /// If the file exists and is encrypted, decrypts it with the password.
    /// If the file exists and is NOT encrypted, returns an error (migration not supported).
    pub fn open_encrypted<P: AsRef<Path>>(path: P, password: &str) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            // Create new encrypted database
            let salt = Self::generate_salt();
            let key = SecureKey::from_passphrase(password, &salt);
            let encryptor = PageEncryptor::new(key);
            let key_check = Self::generate_key_check(&encryptor);

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
            let salt = Self::generate_salt();
            let key = SecureKey::from_passphrase(password, &salt);
            let encryptor = PageEncryptor::new(key);
            let key_check = Self::generate_key_check(&encryptor);

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
        if !Self::validate_key_check(&encryptor, &key_check) {
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

            match entry.kind {
                SegmentKind::Ports => {
                    db.ports =
                        PortSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Subdomains => {
                    db.subdomains =
                        SubdomainSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Whois => {
                    db.whois =
                        WhoisSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Tls => {
                    db.tls = TlsSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Dns => {
                    db.dns = DnsSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Http => {
                    db.http = HttpSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Host => {
                    db.hosts =
                        HostSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Proxy => {
                    db.proxy =
                        ProxySegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Mitre => {
                    db.mitre =
                        MitreSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Ioc => {
                    db.iocs = IocSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Vuln => {
                    db.vulns =
                        VulnSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Sessions => {
                    db.sessions =
                        SessionSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Playbooks => {
                    db.playbooks =
                        PlaybookSegment::deserialize(&segment_bytes).map_err(decode_err_to_io)?;
                }
            }
        }

        Ok(db)
    }

    /// Open database without encryption (legacy mode for backward compatibility)
    /// WARNING: Data will be stored in plaintext. Use open_encrypted for security.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
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
                dirty: false,
                encryption: None,
            });
        }

        let bytes = fs::read(&path)?;
        if bytes.len() < FileHeader::SIZE {
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
                dirty: false,
                encryption: None,
            });
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
            dirty: false,
            encryption: None,
        };

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
            match entry.kind {
                SegmentKind::Ports => {
                    db.ports = PortSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Subdomains => {
                    db.subdomains =
                        SubdomainSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Whois => {
                    db.whois =
                        WhoisSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
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
                    db.proxy =
                        ProxySegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Mitre => {
                    db.mitre =
                        MitreSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Ioc => {
                    db.iocs = IocSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Vuln => {
                    db.vulns = VulnSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Sessions => {
                    db.sessions =
                        SessionSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
                SegmentKind::Playbooks => {
                    db.playbooks =
                        PlaybookSegment::deserialize(segment_bytes).map_err(decode_err_to_io)?;
                }
            }
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
        use crate::storage::layout::MAGIC_ENCRYPTED;
        use std::io::Read;

        if let Ok(mut file) = fs::File::open(path) {
            let mut magic = [0u8; 8];
            if file.read_exact(&mut magic).is_ok() {
                return &magic == MAGIC_ENCRYPTED;
            }
        }
        false
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }

        let mut segments: Vec<(SegmentKind, Vec<u8>)> = Vec::new();
        segments.push((SegmentKind::Ports, self.ports.serialize()));
        segments.push((SegmentKind::Subdomains, self.subdomains.serialize()));
        segments.push((SegmentKind::Whois, self.whois.serialize()));
        segments.push((SegmentKind::Tls, self.tls.serialize()));
        segments.push((SegmentKind::Dns, self.dns.serialize()));
        segments.push((SegmentKind::Http, self.http.serialize()));
        segments.push((SegmentKind::Host, self.hosts.serialize()));
        segments.push((SegmentKind::Proxy, self.proxy.serialize()));
        segments.push((SegmentKind::Mitre, self.mitre.serialize()));
        segments.push((SegmentKind::Ioc, self.iocs.serialize()));
        segments.push((SegmentKind::Vuln, self.vulns.serialize()));
        segments.push((SegmentKind::Sessions, self.sessions.serialize()));
        segments.push((SegmentKind::Playbooks, self.playbooks.serialize()));

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;

        // Calculate header start offset based on encryption
        let header_size = if self.encryption.is_some() {
            FileHeader::SIZE + FileHeader::ENCRYPTION_DATA_SIZE
        } else {
            FileHeader::SIZE
        };

        // Reserve space for header (write placeholder)
        let placeholder = FileHeader {
            version: crate::storage::layout::VERSION,
            section_count: segments.len() as u16,
            directory_offset: 0,
            encrypted: self.encryption.is_some(),
        };

        if let Some(ref enc) = self.encryption {
            placeholder.write_encrypted(&mut file, &enc.salt, &enc.key_check)?;
        } else {
            placeholder.write(&mut file)?;
        }

        let mut entries = Vec::new();
        let mut offset = header_size as u64;

        for (seg_idx, (kind, data)) in segments.iter().enumerate() {
            // Encrypt segment if encryption is enabled
            let write_data = if let Some(ref enc) = self.encryption {
                enc.encryptor.encrypt(seg_idx as u32, data)
            } else {
                data.clone()
            };

            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&write_data)?;
            let mut entry = SectionEntry::new(*kind, offset, write_data.len() as u64);
            offset += write_data.len() as u64;

            let metadata_pairs = self.segment_metadata(*kind);
            let metadata_bytes = SegmentMetadata::encode(&metadata_pairs);
            if !metadata_bytes.is_empty() {
                // Encrypt metadata if encryption is enabled
                let write_metadata = if let Some(ref enc) = self.encryption {
                    // Use seg_idx + 1000 to avoid collision with segment page IDs
                    enc.encryptor
                        .encrypt((seg_idx + 1000) as u32, &metadata_bytes)
                } else {
                    metadata_bytes
                };

                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&write_metadata)?;
                entry.metadata_offset = offset;
                entry.metadata_length = write_metadata.len() as u64;
                entry.flags.insert(SegmentFlags::HAS_METADATA);
                offset += write_metadata.len() as u64;
            }

            entries.push(entry);
        }

        let directory_offset = offset;
        let mut dir_buf = Vec::new();
        SectionEntry::write_all(&entries, &mut dir_buf, crate::storage::layout::VERSION);
        file.seek(SeekFrom::Start(directory_offset))?;
        file.write_all(&dir_buf)?;
        file.flush()?;

        let header = FileHeader {
            version: crate::storage::layout::VERSION,
            section_count: entries.len() as u16,
            directory_offset,
            encrypted: self.encryption.is_some(),
        };

        if let Some(ref enc) = self.encryption {
            header.write_encrypted(&mut file, &enc.salt, &enc.key_check)?;
        } else {
            header.write(&mut file)?;
        }
        file.sync_all()?;

        self.dirty = false;
        Ok(())
    }

    pub fn insert_port_scan(&mut self, record: PortScanRecord) {
        self.ports.push(record);
        self.dirty = true;
    }

    pub fn find_port(&mut self, ip: IpAddr, port: u16) -> Option<PortScanRecord> {
        self.ports.find(ip, port)
    }

    pub fn open_ports(&mut self, ip: IpAddr) -> Vec<u16> {
        self.ports.get_open_ports(ip)
    }

    pub fn ports_for_ip(&mut self, ip: IpAddr) -> Vec<PortScanRecord> {
        self.ports.iter_ip(ip)
    }

    pub fn port_count(&mut self) -> usize {
        self.ports.len()
    }

    pub fn all_ports(&mut self) -> Vec<PortScanRecord> {
        self.ports.all_records()
    }

    pub fn insert_host(&mut self, record: HostIntelRecord) {
        self.hosts.insert(record);
        self.dirty = true;
    }

    pub fn host_record(&mut self, ip: IpAddr) -> Option<HostIntelRecord> {
        self.hosts.get(ip)
    }

    pub fn all_hosts(&mut self) -> Vec<HostIntelRecord> {
        self.hosts.all()
    }

    pub fn insert_subdomain(
        &mut self,
        domain: &str,
        subdomain: &str,
        ips: Vec<IpAddr>,
        source: SubdomainSource,
        timestamp: u32,
    ) {
        self.subdomains
            .insert(domain, subdomain, ips, source, timestamp);
        self.dirty = true;
    }

    pub fn subdomains_of(&mut self, domain: &str) -> Vec<SubdomainRecord> {
        self.subdomains.get_by_domain(domain)
    }

    pub fn all_subdomains(&mut self) -> Vec<SubdomainRecord> {
        self.subdomains.all_records()
    }

    pub fn insert_whois(
        &mut self,
        domain: &str,
        registrar: &str,
        created: u32,
        expires: u32,
        nameservers: Vec<String>,
        timestamp: u32,
    ) {
        self.whois
            .insert(domain, registrar, created, expires, nameservers, timestamp);
        self.dirty = true;
    }

    pub fn get_whois(&self, domain: &str) -> Option<WhoisRecord> {
        self.whois.get(domain)
    }

    pub fn insert_tls_scan(&mut self, record: TlsScanRecord) {
        self.tls.insert(record);
        self.dirty = true;
    }

    pub fn tls_scans_for_host(&self, host: &str) -> Vec<TlsScanRecord> {
        self.tls.scans_for_host(host)
    }

    pub fn tls_scans(&self) -> impl Iterator<Item = TlsScanRecord> + '_ {
        self.tls.iter()
    }

    pub fn insert_dns(&mut self, record: DnsRecordData) {
        self.dns.insert(record);
        self.dirty = true;
    }

    pub fn insert_http(&mut self, record: HttpHeadersRecord) {
        self.http.insert(record);
        self.dirty = true;
    }

    pub fn dns_records(&mut self) -> impl Iterator<Item = DnsRecordData> + '_ {
        self.dns.iter_mut()
    }

    pub fn dns_for_domain(&mut self, domain: &str) -> Vec<DnsRecordData> {
        self.dns.records_for_domain(domain)
    }

    pub fn http_records(&mut self) -> impl Iterator<Item = HttpHeadersRecord> + '_ {
        self.http.iter()
    }

    pub fn http_for_host(&mut self, host: &str) -> Vec<HttpHeadersRecord> {
        self.http.records_for_host(host)
    }

    pub fn whois_records(&self) -> impl Iterator<Item = WhoisRecord> + '_ {
        self.whois.iter()
    }

    // ==================== Proxy Methods ====================

    pub fn insert_proxy_connection(&mut self, record: ProxyConnectionRecord) {
        self.proxy.push_connection(record);
        self.dirty = true;
    }

    pub fn insert_proxy_http_request(&mut self, record: ProxyHttpRequestRecord) {
        self.proxy.push_request(record);
        self.dirty = true;
    }

    pub fn insert_proxy_http_response(&mut self, record: ProxyHttpResponseRecord) {
        self.proxy.push_response(record);
        self.dirty = true;
    }

    pub fn insert_proxy_websocket(&mut self, record: ProxyWebSocketRecord) {
        self.proxy.push_websocket(record);
        self.dirty = true;
    }

    pub fn proxy_connections(&mut self) -> Vec<ProxyConnectionRecord> {
        self.proxy.all_connections()
    }

    pub fn proxy_http_requests(&mut self) -> Vec<ProxyHttpRequestRecord> {
        self.proxy.all_requests()
    }

    pub fn proxy_http_responses(&mut self) -> Vec<ProxyHttpResponseRecord> {
        self.proxy.all_responses()
    }

    pub fn proxy_websocket_messages(&mut self, connection_id: u64) -> Vec<&ProxyWebSocketRecord> {
        self.proxy.get_websockets_for_connection(connection_id)
    }

    pub fn proxy_connections_for_host(&mut self, host: &str) -> Vec<ProxyConnectionRecord> {
        self.proxy
            .all_connections()
            .into_iter()
            .filter(|c| c.dst_host == host)
            .collect()
    }

    pub fn proxy_requests_for_connection(
        &mut self,
        connection_id: u64,
    ) -> Vec<ProxyHttpRequestRecord> {
        self.proxy
            .get_requests_for_connection(connection_id)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn proxy_responses_for_connection(
        &mut self,
        connection_id: u64,
    ) -> Vec<ProxyHttpResponseRecord> {
        self.proxy
            .get_responses_for_connection(connection_id)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn proxy_connection_count(&self) -> usize {
        self.proxy.connection_count()
    }

    pub fn proxy_request_count(&self) -> usize {
        self.proxy.request_count()
    }

    pub fn proxy_len(&self) -> usize {
        self.proxy.connection_count()
            + self.proxy.request_count()
            + self.proxy.response_count()
            + self.proxy.websocket_count()
    }

    // ==================== Threat Intelligence Methods ====================

    pub fn insert_mitre_record(&mut self, record: MitreAttackRecord) {
        self.mitre.push(record);
        self.dirty = true;
    }

    pub fn mitre_records(&self) -> &Vec<MitreAttackRecord> {
        self.mitre.get_all()
    }

    pub fn mitre_records_by_technique(&self, technique_id: &str) -> Vec<MitreAttackRecord> {
        self.mitre.get_by_technique(technique_id)
    }

    pub fn insert_ioc_record(&mut self, record: IocRecord) {
        self.iocs.push(record);
        self.dirty = true;
    }

    pub fn ioc_records(&self) -> &Vec<IocRecord> {
        self.iocs.get_all()
    }

    pub fn ioc_records_by_type(
        &self,
        ioc_type: crate::storage::records::IocType,
    ) -> Vec<IocRecord> {
        self.iocs.get_by_type(ioc_type)
    }

    pub fn insert_vulnerability(&mut self, record: VulnerabilityRecord) {
        self.vulns.push(record);
        self.dirty = true;
    }

    pub fn vulnerability_records(&self) -> Vec<VulnerabilityRecord> {
        // VulnSegment stores by tech index, need to gather all or expose all()
        // VulnSegment currently doesn't have get_all(), let's check its implementation
        // It has records: Vec<VulnerabilityRecord>, but not exposed publicly.
        // I should update VulnSegment to expose records or implement iterator.
        // For now, I'll assume I can access records via a new method or wait until I fix VulnSegment.
        // But I can't modify VulnSegment here.
        // Let's implement a workaround or note to fix VulnSegment.
        // Actually, VulnSegment struct definition is in another file.
        // I will assume I need to add `get_all` to VulnSegment first.
        // But wait, I can't compile if method missing.
        // Let's assume I will fix VulnSegment in next step.
        // For now:
        self.vulns.get_all()
    }

    pub fn vulnerability_records_by_tech(&self, tech: &str) -> Vec<VulnerabilityRecord> {
        self.vulns.get_by_tech(tech)
    }

    // ==================== Session Methods ====================

    pub fn insert_session(&mut self, record: SessionRecord) {
        self.sessions.push(record);
        self.dirty = true;
    }

    pub fn update_session(&mut self, record: SessionRecord) {
        self.sessions.update(record);
        self.dirty = true;
    }

    pub fn get_session(&self, id: &str) -> Option<SessionRecord> {
        self.sessions.get_by_id(id)
    }

    pub fn sessions_for_target(&self, target: &str) -> Vec<SessionRecord> {
        self.sessions.get_by_target(target)
    }

    pub fn active_sessions(&self) -> Vec<SessionRecord> {
        self.sessions.get_active()
    }

    pub fn all_sessions(&self) -> Vec<SessionRecord> {
        self.sessions.all_records()
    }

    // ==================== Playbook Methods ====================

    pub fn insert_playbook_run(&mut self, record: PlaybookRunRecord) {
        self.playbooks.push(record);
        self.dirty = true;
    }

    pub fn playbook_runs(&self, playbook_name: &str) -> Vec<PlaybookRunRecord> {
        self.playbooks.get_by_playbook(playbook_name)
    }

    pub fn playbook_runs_for_target(&self, target: &str) -> Vec<PlaybookRunRecord> {
        self.playbooks.get_by_target(target)
    }

    pub fn all_playbook_runs(&self) -> Vec<PlaybookRunRecord> {
        self.playbooks.all_records()
    }

    fn segment_metadata(&self, kind: SegmentKind) -> Vec<(String, String)> {
        let mut pairs = Vec::with_capacity(4);
        pairs.push(("segment".to_string(), Self::segment_label(kind).to_string()));
        if let Some(name) = self.path.file_name().and_then(|s| s.to_str()) {
            pairs.push(("target_file".to_string(), name.to_string()));
        }
        let record_count = match kind {
            SegmentKind::Ports => self.ports.len(),
            SegmentKind::Subdomains => self.subdomains.len(),
            SegmentKind::Whois => self.whois.len(),
            SegmentKind::Tls => self.tls.len(),
            SegmentKind::Dns => self.dns.len(),
            SegmentKind::Http => self.http.len(),
            SegmentKind::Host => self.hosts.len(),
            SegmentKind::Proxy => self.proxy_len(),
            SegmentKind::Mitre => self.mitre.get_all().len(),
            SegmentKind::Ioc => self.iocs.get_all().len(),
            SegmentKind::Vuln => self.vulns.get_all().len(),
            SegmentKind::Sessions => self.sessions.len(),
            SegmentKind::Playbooks => self.playbooks.len(),
        };
        pairs.push(("record_count".to_string(), record_count.to_string()));
        pairs
    }

    fn segment_label(kind: SegmentKind) -> &'static str {
        match kind {
            SegmentKind::Ports => "ports",
            SegmentKind::Subdomains => "subdomains",
            SegmentKind::Whois => "whois",
            SegmentKind::Tls => "tls",
            SegmentKind::Dns => "dns",
            SegmentKind::Http => "http",
            SegmentKind::Host => "host",
            SegmentKind::Proxy => "proxy",
            SegmentKind::Mitre => "mitre",
            SegmentKind::Ioc => "ioc",
            SegmentKind::Vuln => "vuln",
            SegmentKind::Sessions => "sessions",
            SegmentKind::Playbooks => "playbooks",
        }
    }
}

fn decode_err_to_io(err: DecodeError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::records::PortStatus;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    struct FileGuard {
        path: PathBuf,
    }

    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_db(name: &str) -> (FileGuard, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("rb_store_{}_{}.db", name, std::process::id()));
        let guard = FileGuard { path: path.clone() };
        let _ = std::fs::remove_file(&path);
        (guard, path)
    }

    // ==================== Open Tests ====================

    #[test]
    fn test_open_new_database() {
        let (_guard, path) = temp_db("open_new");
        let db = Database::open(&path).unwrap();
        assert!(!db.dirty);
    }

    #[test]
    fn test_open_nonexistent_creates_new() {
        let (_guard, path) = temp_db("nonexistent");
        assert!(!path.exists());
        let db = Database::open(&path).unwrap();
        assert!(!db.dirty);
    }

    #[test]
    fn test_open_too_small_file() {
        let (_guard, path) = temp_db("small");
        std::fs::write(&path, b"tiny").unwrap();

        // Should create new empty db if file too small
        let db = Database::open(&path).unwrap();
        assert!(!db.dirty);
    }

    // ==================== Port Tests ====================

    #[test]
    fn test_insert_port_scan() {
        let (_guard, path) = temp_db("port_insert");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let record = PortScanRecord {
            ip,
            port: 80,
            status: PortStatus::Open,
            service_id: 1, // HTTP
            timestamp: 1000,
        };

        db.insert_port_scan(record);
        assert!(db.dirty);
    }

    #[test]
    fn test_find_port() {
        let (_guard, path) = temp_db("port_find");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let record = PortScanRecord {
            ip,
            port: 443,
            status: PortStatus::Open,
            service_id: 2, // HTTPS
            timestamp: 1000,
        };

        db.insert_port_scan(record);

        let found = db.find_port(ip, 443);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.port, 443);
        assert_eq!(found.service_id, 2);
    }

    #[test]
    fn test_open_ports() {
        let (_guard, path) = temp_db("open_ports");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for port in [22, 80, 443] {
            db.insert_port_scan(PortScanRecord {
                ip,
                port,
                status: PortStatus::Open,
                service_id: 0,
                timestamp: 1000,
            });
        }

        db.insert_port_scan(PortScanRecord {
            ip,
            port: 8080,
            status: PortStatus::Closed,
            service_id: 0,
            timestamp: 1000,
        });

        let open = db.open_ports(ip);
        assert_eq!(open.len(), 3);
        assert!(open.contains(&22));
        assert!(open.contains(&80));
        assert!(open.contains(&443));
        assert!(!open.contains(&8080));
    }

    #[test]
    fn test_port_count() {
        let (_guard, path) = temp_db("port_count");
        let mut db = Database::open(&path).unwrap();

        assert_eq!(db.port_count(), 0);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        db.insert_port_scan(PortScanRecord {
            ip,
            port: 80,
            status: PortStatus::Open,
            service_id: 0,
            timestamp: 1000,
        });

        assert_eq!(db.port_count(), 1);
    }

    // ==================== Host Tests ====================

    #[test]
    fn test_insert_host() {
        let (_guard, path) = temp_db("host_insert");
        let mut db = Database::open(&path).unwrap();

        let record = HostIntelRecord {
            ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            os_family: Some("Linux".to_string()),
            confidence: 0.9,
            last_seen: 1000,
            services: vec![],
        };

        db.insert_host(record);
        assert!(db.dirty);

        let found = db.host_record(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(found.is_some());
    }

    #[test]
    fn test_all_hosts() {
        let (_guard, path) = temp_db("all_hosts");
        let mut db = Database::open(&path).unwrap();

        for i in 1..=3 {
            db.insert_host(HostIntelRecord {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                os_family: Some(format!("OS{}", i)),
                confidence: 0.5,
                last_seen: 1000,
                services: vec![],
            });
        }

        let hosts = db.all_hosts();
        assert_eq!(hosts.len(), 3);
    }

    // ==================== Subdomain Tests ====================

    #[test]
    fn test_insert_subdomain() {
        let (_guard, path) = temp_db("subdomain_insert");
        let mut db = Database::open(&path).unwrap();

        let ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        db.insert_subdomain(
            "example.com",
            "www.example.com",
            ips,
            SubdomainSource::DnsBruteforce,
            1000,
        );

        assert!(db.dirty);
    }

    #[test]
    fn test_subdomains_of() {
        let (_guard, path) = temp_db("subdomains_of");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        db.insert_subdomain(
            "example.com",
            "api.example.com",
            vec![ip],
            SubdomainSource::CertTransparency,
            1000,
        );
        db.insert_subdomain(
            "example.com",
            "mail.example.com",
            vec![ip],
            SubdomainSource::DnsBruteforce,
            1001,
        );
        db.insert_subdomain(
            "other.com",
            "www.other.com",
            vec![ip],
            SubdomainSource::SearchEngine,
            1002,
        );

        let subs = db.subdomains_of("example.com");
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn test_all_subdomains() {
        let (_guard, path) = temp_db("all_subdomains");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        db.insert_subdomain(
            "a.com",
            "www.a.com",
            vec![ip],
            SubdomainSource::DnsBruteforce,
            1000,
        );
        db.insert_subdomain(
            "b.com",
            "api.b.com",
            vec![ip],
            SubdomainSource::WebCrawl,
            1001,
        );

        let all = db.all_subdomains();
        assert_eq!(all.len(), 2);
    }

    // ==================== WHOIS Tests ====================

    #[test]
    fn test_insert_whois() {
        let (_guard, path) = temp_db("whois_insert");
        let mut db = Database::open(&path).unwrap();

        db.insert_whois(
            "example.com",
            "Example Registrar",
            1609459200, // 2021-01-01
            1704067200, // 2024-01-01
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            1700000000,
        );

        assert!(db.dirty);

        let found = db.get_whois("example.com");
        assert!(found.is_some());
        let record = found.unwrap();
        assert_eq!(record.registrar, "Example Registrar");
    }

    #[test]
    fn test_whois_records_iterator() {
        let (_guard, path) = temp_db("whois_iter");
        let mut db = Database::open(&path).unwrap();

        db.insert_whois("a.com", "Reg A", 1000, 2000, vec![], 1000);
        db.insert_whois("b.com", "Reg B", 1000, 2000, vec![], 1000);

        let records: Vec<_> = db.whois_records().collect();
        assert_eq!(records.len(), 2);
    }

    // ==================== TLS Tests ====================

    #[test]
    fn test_insert_tls_scan() {
        let (_guard, path) = temp_db("tls_insert");
        let mut db = Database::open(&path).unwrap();

        use crate::storage::records::TlsCipherStrength;

        let record = TlsScanRecord {
            host: "example.com".to_string(),
            port: 443,
            timestamp: 1700000000,
            negotiated_version: Some("TLSv1.3".to_string()),
            negotiated_cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
            negotiated_cipher_code: Some(0x1301),
            negotiated_cipher_strength: TlsCipherStrength::Strong,
            certificate_valid: true,
            versions: vec![],
            ciphers: vec![],
            vulnerabilities: vec![],
            certificate_chain: vec![],
            ja3: None,
            ja3s: None,
            ja3_raw: None,
            ja3s_raw: None,
            peer_fingerprints: vec![],
            certificate_chain_pem: vec![],
        };

        db.insert_tls_scan(record);
        assert!(db.dirty);
    }

    #[test]
    fn test_tls_scans_for_host() {
        let (_guard, path) = temp_db("tls_for_host");
        let mut db = Database::open(&path).unwrap();

        use crate::storage::records::TlsCipherStrength;

        for port in [443, 8443] {
            db.insert_tls_scan(TlsScanRecord {
                host: "example.com".to_string(),
                port,
                timestamp: 1000,
                negotiated_version: Some("TLSv1.3".to_string()),
                negotiated_cipher: None,
                negotiated_cipher_code: None,
                negotiated_cipher_strength: TlsCipherStrength::Strong,
                certificate_valid: true,
                versions: vec![],
                ciphers: vec![],
                vulnerabilities: vec![],
                certificate_chain: vec![],
                ja3: None,
                ja3s: None,
                ja3_raw: None,
                ja3s_raw: None,
                peer_fingerprints: vec![],
                certificate_chain_pem: vec![],
            });
        }

        db.insert_tls_scan(TlsScanRecord {
            host: "other.com".to_string(),
            port: 443,
            timestamp: 1000,
            negotiated_version: Some("TLSv1.2".to_string()),
            negotiated_cipher: None,
            negotiated_cipher_code: None,
            negotiated_cipher_strength: TlsCipherStrength::Medium,
            certificate_valid: true,
            versions: vec![],
            ciphers: vec![],
            vulnerabilities: vec![],
            certificate_chain: vec![],
            ja3: None,
            ja3s: None,
            ja3_raw: None,
            ja3s_raw: None,
            peer_fingerprints: vec![],
            certificate_chain_pem: vec![],
        });

        let scans = db.tls_scans_for_host("example.com");
        assert_eq!(scans.len(), 2);
    }

    // ==================== DNS Tests ====================

    #[test]
    fn test_insert_dns() {
        let (_guard, path) = temp_db("dns_insert");
        let mut db = Database::open(&path).unwrap();

        use crate::storage::records::DnsRecordType;

        let record = DnsRecordData {
            domain: "example.com".to_string(),
            record_type: DnsRecordType::A,
            value: "93.184.216.34".to_string(),
            ttl: 300,
            timestamp: 1000,
        };

        db.insert_dns(record);
        assert!(db.dirty);
    }

    #[test]
    fn test_dns_for_domain() {
        let (_guard, path) = temp_db("dns_for_domain");
        let mut db = Database::open(&path).unwrap();

        use crate::storage::records::DnsRecordType;

        db.insert_dns(DnsRecordData {
            domain: "example.com".to_string(),
            record_type: DnsRecordType::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            timestamp: 1000,
        });

        db.insert_dns(DnsRecordData {
            domain: "example.com".to_string(),
            record_type: DnsRecordType::AAAA,
            value: "::1".to_string(),
            ttl: 300,
            timestamp: 1000,
        });

        let records = db.dns_for_domain("example.com");
        assert_eq!(records.len(), 2);
    }

    // ==================== HTTP Tests ====================

    #[test]
    fn test_insert_http() {
        let (_guard, path) = temp_db("http_insert");
        let mut db = Database::open(&path).unwrap();

        let record = HttpHeadersRecord {
            host: "example.com".to_string(),
            url: "http://example.com/".to_string(),
            method: "GET".to_string(),
            scheme: "http".to_string(),
            http_version: "HTTP/1.1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            server: Some("nginx".to_string()),
            body_size: 1024,
            headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Server".to_string(), "nginx".to_string()),
            ],
            timestamp: 1000,
            tls: None,
        };

        db.insert_http(record);
        assert!(db.dirty);
    }

    #[test]
    fn test_http_for_host() {
        let (_guard, path) = temp_db("http_for_host");
        let mut db = Database::open(&path).unwrap();

        db.insert_http(HttpHeadersRecord {
            host: "example.com".to_string(),
            url: "http://example.com/page1".to_string(),
            method: "GET".to_string(),
            scheme: "http".to_string(),
            http_version: "HTTP/1.1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            server: None,
            body_size: 0,
            headers: vec![],
            timestamp: 1000,
            tls: None,
        });

        db.insert_http(HttpHeadersRecord {
            host: "example.com".to_string(),
            url: "http://example.com/page2".to_string(),
            method: "GET".to_string(),
            scheme: "http".to_string(),
            http_version: "HTTP/1.1".to_string(),
            status_code: 404,
            status_text: "Not Found".to_string(),
            server: None,
            body_size: 0,
            headers: vec![],
            timestamp: 1001,
            tls: None,
        });

        let records = db.http_for_host("example.com");
        assert_eq!(records.len(), 2);
    }

    // ==================== Flush & Persistence Tests ====================

    #[test]
    fn test_flush_creates_file() {
        let (_guard, path) = temp_db("flush");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        db.insert_port_scan(PortScanRecord {
            ip,
            port: 80,
            status: PortStatus::Open,
            service_id: 0,
            timestamp: 1000,
        });

        db.flush().unwrap();
        assert!(!db.dirty);
        assert!(path.exists());
    }

    #[test]
    fn test_flush_no_changes() {
        let (_guard, path) = temp_db("flush_noop");
        let mut db = Database::open(&path).unwrap();

        // No changes, should be no-op
        db.flush().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_roundtrip_persistence() {
        let (_guard, path) = temp_db("roundtrip");

        // Create database with data
        {
            let mut db = Database::open(&path).unwrap();

            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
            db.insert_port_scan(PortScanRecord {
                ip,
                port: 22,
                status: PortStatus::Open,
                service_id: 5, // SSH
                timestamp: 1000,
            });

            db.insert_subdomain(
                "test.com",
                "api.test.com",
                vec![ip],
                SubdomainSource::DnsBruteforce,
                1000,
            );

            db.insert_whois(
                "test.com",
                "Test Registrar",
                1000,
                2000,
                vec!["ns.test.com".to_string()],
                1000,
            );

            db.flush().unwrap();
        }

        // Reopen and verify data
        {
            let mut db = Database::open(&path).unwrap();

            // Check port
            let port = db.find_port(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 22);
            assert!(port.is_some());
            let port = port.unwrap();
            assert_eq!(port.service_id, 5);

            // Check subdomain
            let subs = db.subdomains_of("test.com");
            assert_eq!(subs.len(), 1);
            assert_eq!(subs[0].subdomain, "api.test.com");

            // Check whois
            let whois = db.get_whois("test.com");
            assert!(whois.is_some());
            assert_eq!(whois.unwrap().registrar, "Test Registrar");
        }
    }

    #[test]
    fn test_persistence_with_ipv6() {
        let (_guard, path) = temp_db("ipv6");

        {
            let mut db = Database::open(&path).unwrap();

            let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            db.insert_port_scan(PortScanRecord {
                ip: ipv6,
                port: 80,
                status: PortStatus::Open,
                service_id: 1, // HTTP
                timestamp: 1000,
            });

            db.flush().unwrap();
        }

        {
            let mut db = Database::open(&path).unwrap();

            let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let port = db.find_port(ipv6, 80);
            assert!(port.is_some());
        }
    }

    // ==================== Segment Metadata Tests ====================

    #[test]
    fn test_segment_label() {
        assert_eq!(Database::segment_label(SegmentKind::Ports), "ports");
        assert_eq!(
            Database::segment_label(SegmentKind::Subdomains),
            "subdomains"
        );
        assert_eq!(Database::segment_label(SegmentKind::Whois), "whois");
        assert_eq!(Database::segment_label(SegmentKind::Tls), "tls");
        assert_eq!(Database::segment_label(SegmentKind::Dns), "dns");
        assert_eq!(Database::segment_label(SegmentKind::Http), "http");
        assert_eq!(Database::segment_label(SegmentKind::Host), "host");
        assert_eq!(Database::segment_label(SegmentKind::Proxy), "proxy");
    }

    // ==================== All Records Tests ====================

    #[test]
    fn test_all_ports() {
        let (_guard, path) = temp_db("all_ports");
        let mut db = Database::open(&path).unwrap();

        for i in 1..=5 {
            db.insert_port_scan(PortScanRecord {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                port: 80 + i as u16,
                status: PortStatus::Open,
                service_id: 0,
                timestamp: 1000,
            });
        }

        let all = db.all_ports();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_ports_for_ip() {
        let (_guard, path) = temp_db("ports_for_ip");
        let mut db = Database::open(&path).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        for port in [22, 80, 443] {
            db.insert_port_scan(PortScanRecord {
                ip,
                port,
                status: PortStatus::Open,
                service_id: 0,
                timestamp: 1000,
            });
        }

        db.insert_port_scan(PortScanRecord {
            ip: other_ip,
            port: 8080,
            status: PortStatus::Open,
            service_id: 0,
            timestamp: 1000,
        });

        let ports = db.ports_for_ip(ip);
        assert_eq!(ports.len(), 3);
    }

    // ==================== Encryption Tests ====================

    #[test]
    fn test_open_encrypted_new_database() {
        let (_guard, path) = temp_db("enc_new");
        let db = Database::open_encrypted(&path, "password123").unwrap();
        assert!(db.is_encrypted());
        assert!(!db.dirty);
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let (_guard, path) = temp_db("enc_roundtrip");

        // Create encrypted database with data
        {
            let mut db = Database::open_encrypted(&path, "secure_pass").unwrap();
            assert!(db.is_encrypted());

            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
            db.insert_port_scan(PortScanRecord {
                ip,
                port: 443,
                status: PortStatus::Open,
                service_id: 2,
                timestamp: 1000,
            });

            db.insert_subdomain(
                "example.com",
                "api.example.com",
                vec![ip],
                SubdomainSource::DnsBruteforce,
                1000,
            );

            db.flush().unwrap();
        }

        // Verify file is encrypted (should start with RBSTOREE magic)
        let file_bytes = std::fs::read(&path).unwrap();
        assert_eq!(&file_bytes[0..8], b"RBSTOREE");

        // Reopen with correct password and verify data
        {
            let mut db = Database::open_encrypted(&path, "secure_pass").unwrap();
            assert!(db.is_encrypted());

            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
            let port = db.find_port(ip, 443);
            assert!(port.is_some());
            assert_eq!(port.unwrap().service_id, 2);

            let subs = db.subdomains_of("example.com");
            assert_eq!(subs.len(), 1);
            assert_eq!(subs[0].subdomain, "api.example.com");
        }
    }

    #[test]
    fn test_encrypted_wrong_password() {
        let (_guard, path) = temp_db("enc_wrong_pass");

        // Create encrypted database
        {
            let mut db = Database::open_encrypted(&path, "correct_password").unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
            db.insert_port_scan(PortScanRecord {
                ip,
                port: 80,
                status: PortStatus::Open,
                service_id: 1,
                timestamp: 1000,
            });
            db.flush().unwrap();
        }

        // Try to open with wrong password
        let result = Database::open_encrypted(&path, "wrong_password");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("incorrect password"));
    }

    #[test]
    fn test_open_encrypted_on_unencrypted() {
        let (_guard, path) = temp_db("enc_on_unenc");

        // Create unencrypted database
        {
            let mut db = Database::open(&path).unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
            db.insert_port_scan(PortScanRecord {
                ip,
                port: 80,
                status: PortStatus::Open,
                service_id: 1,
                timestamp: 1000,
            });
            db.flush().unwrap();
        }

        // Try to open with encryption
        let result = Database::open_encrypted(&path, "some_password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not encrypted"));
    }

    #[test]
    fn test_open_unencrypted_on_encrypted() {
        let (_guard, path) = temp_db("unenc_on_enc");

        // Create encrypted database
        {
            let mut db = Database::open_encrypted(&path, "password").unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
            db.insert_port_scan(PortScanRecord {
                ip,
                port: 80,
                status: PortStatus::Open,
                service_id: 1,
                timestamp: 1000,
            });
            db.flush().unwrap();
        }

        // Try to open without encryption
        let result = Database::open(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("encrypted"));
    }

    #[test]
    fn test_encrypted_multiple_segments() {
        let (_guard, path) = temp_db("enc_multi_seg");

        // Create encrypted database with multiple segment types
        {
            let mut db = Database::open_encrypted(&path, "multi_pass").unwrap();

            // Ports
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            db.insert_port_scan(PortScanRecord {
                ip,
                port: 22,
                status: PortStatus::Open,
                service_id: 5,
                timestamp: 1000,
            });

            // Subdomains
            db.insert_subdomain(
                "test.com",
                "www.test.com",
                vec![ip],
                SubdomainSource::WebCrawl,
                1000,
            );

            // WHOIS
            db.insert_whois(
                "test.com",
                "Test Registrar",
                1000,
                2000,
                vec!["ns1.test.com".to_string()],
                1000,
            );

            // Host
            db.insert_host(HostIntelRecord {
                ip,
                os_family: Some("Linux".to_string()),
                confidence: 0.85,
                last_seen: 1000,
                services: vec![],
            });

            db.flush().unwrap();
        }

        // Reopen and verify all segments
        {
            let mut db = Database::open_encrypted(&path, "multi_pass").unwrap();

            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

            // Check ports
            let port = db.find_port(ip, 22);
            assert!(port.is_some());
            assert_eq!(port.unwrap().service_id, 5);

            // Check subdomains
            let subs = db.subdomains_of("test.com");
            assert_eq!(subs.len(), 1);

            // Check WHOIS
            let whois = db.get_whois("test.com");
            assert!(whois.is_some());
            assert_eq!(whois.unwrap().registrar, "Test Registrar");

            // Check host
            let host = db.host_record(ip);
            assert!(host.is_some());
            assert_eq!(host.unwrap().os_family, Some("Linux".to_string()));
        }
    }

    #[test]
    fn test_encrypted_data_not_plaintext() {
        let (_guard, path) = temp_db("enc_not_plain");

        // Create encrypted database with known data
        {
            let mut db = Database::open_encrypted(&path, "secret").unwrap();
            db.insert_whois(
                "searchable-domain.com",
                "Searchable Registrar Inc",
                1000,
                2000,
                vec!["ns.searchable.com".to_string()],
                1000,
            );
            db.flush().unwrap();
        }

        // Read raw file and verify the plaintext strings are NOT present
        let file_bytes = std::fs::read(&path).unwrap();
        let file_content = String::from_utf8_lossy(&file_bytes);

        // These strings should be encrypted, not visible in plaintext
        assert!(!file_content.contains("searchable-domain.com"));
        assert!(!file_content.contains("Searchable Registrar Inc"));
        assert!(!file_content.contains("ns.searchable.com"));
    }

    #[test]
    fn test_is_encrypted() {
        let (_guard1, path1) = temp_db("is_enc_true");
        let (_guard2, path2) = temp_db("is_enc_false");

        let enc_db = Database::open_encrypted(&path1, "pass").unwrap();
        let plain_db = Database::open(&path2).unwrap();

        assert!(enc_db.is_encrypted());
        assert!(!plain_db.is_encrypted());
    }

    // ==================== Proxy Tests ====================

    #[test]
    fn test_insert_proxy_connection() {
        let (_guard, path) = temp_db("proxy_conn");
        let mut db = Database::open(&path).unwrap();

        let record = ProxyConnectionRecord {
            connection_id: 1,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 50000,
            dst_host: "example.com".to_string(),
            dst_port: 443,
            protocol: 0, // TCP
            started_at: 1000,
            ended_at: 0,
            bytes_sent: 100,
            bytes_received: 200,
            tls_intercepted: true,
        };

        db.insert_proxy_connection(record);
        assert!(db.dirty);
    }

    #[test]
    fn test_proxy_connections() {
        let (_guard, path) = temp_db("proxy_conns");
        let mut db = Database::open(&path).unwrap();

        db.insert_proxy_connection(ProxyConnectionRecord {
            connection_id: 1,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 50000,
            dst_host: "example.com".to_string(),
            dst_port: 443,
            protocol: 0,
            started_at: 1000,
            ended_at: 0,
            bytes_sent: 0,
            bytes_received: 0,
            tls_intercepted: true,
        });

        db.insert_proxy_connection(ProxyConnectionRecord {
            connection_id: 2,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 50001,
            dst_host: "test.com".to_string(),
            dst_port: 80,
            protocol: 0,
            started_at: 2000,
            ended_at: 0,
            bytes_sent: 0,
            bytes_received: 0,
            tls_intercepted: false,
        });

        let connections = db.proxy_connections();
        assert_eq!(connections.len(), 2);
    }

    #[test]
    fn test_proxy_connections_for_host() {
        let (_guard, path) = temp_db("proxy_host");
        let mut db = Database::open(&path).unwrap();

        db.insert_proxy_connection(ProxyConnectionRecord {
            connection_id: 1,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 50000,
            dst_host: "example.com".to_string(),
            dst_port: 443,
            protocol: 0,
            started_at: 1000,
            ended_at: 0,
            bytes_sent: 0,
            bytes_received: 0,
            tls_intercepted: true,
        });

        db.insert_proxy_connection(ProxyConnectionRecord {
            connection_id: 2,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 50001,
            dst_host: "other.com".to_string(),
            dst_port: 80,
            protocol: 0,
            started_at: 2000,
            ended_at: 0,
            bytes_sent: 0,
            bytes_received: 0,
            tls_intercepted: false,
        });

        let conns = db.proxy_connections_for_host("example.com");
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].dst_host, "example.com");
    }

    #[test]
    fn test_insert_proxy_http_request() {
        let (_guard, path) = temp_db("proxy_req");
        let mut db = Database::open(&path).unwrap();

        let record = ProxyHttpRequestRecord {
            connection_id: 1,
            request_seq: 1,
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "example.com".to_string(),
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: vec![],
            timestamp: 1000,
            client_addr: None,
        };

        db.insert_proxy_http_request(record);
        assert!(db.dirty);
    }

    #[test]
    fn test_proxy_requests_for_connection() {
        let (_guard, path) = temp_db("proxy_reqs_conn");
        let mut db = Database::open(&path).unwrap();

        db.insert_proxy_http_request(ProxyHttpRequestRecord {
            connection_id: 1,
            request_seq: 1,
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "example.com".to_string(),
            headers: vec![],
            body: vec![],
            timestamp: 1000,
            client_addr: None,
        });

        db.insert_proxy_http_request(ProxyHttpRequestRecord {
            connection_id: 1,
            request_seq: 2,
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "example.com".to_string(),
            headers: vec![],
            body: b"test data".to_vec(),
            timestamp: 2000,
            client_addr: None,
        });

        db.insert_proxy_http_request(ProxyHttpRequestRecord {
            connection_id: 2,
            request_seq: 1,
            method: "GET".to_string(),
            path: "/other".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "other.com".to_string(),
            headers: vec![],
            body: vec![],
            timestamp: 3000,
            client_addr: None,
        });

        let reqs = db.proxy_requests_for_connection(1);
        assert_eq!(reqs.len(), 2);
    }

    #[test]
    fn test_proxy_len() {
        let (_guard, path) = temp_db("proxy_len");
        let mut db = Database::open(&path).unwrap();

        assert_eq!(db.proxy_len(), 0);

        db.insert_proxy_connection(ProxyConnectionRecord {
            connection_id: 1,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 50000,
            dst_host: "example.com".to_string(),
            dst_port: 443,
            protocol: 0,
            started_at: 1000,
            ended_at: 0,
            bytes_sent: 0,
            bytes_received: 0,
            tls_intercepted: true,
        });

        db.insert_proxy_http_request(ProxyHttpRequestRecord {
            connection_id: 1,
            request_seq: 1,
            method: "GET".to_string(),
            path: "/".to_string(),
            http_version: "HTTP/1.1".to_string(),
            host: "example.com".to_string(),
            headers: vec![],
            body: vec![],
            timestamp: 1000,
            client_addr: None,
        });

        db.insert_proxy_http_response(ProxyHttpResponseRecord {
            connection_id: 1,
            request_seq: 1,
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: b"Hello".to_vec(),
            timestamp: 1001,
            content_type: None,
        });

        // 1 connection + 1 request + 1 response = 3
        assert_eq!(db.proxy_len(), 3);
    }
}
