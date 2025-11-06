use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::storage::encoding::DecodeError;
use crate::storage::layout::{
    FileHeader, SectionEntry, SegmentFlags, SegmentKind, SegmentMetadata,
};
use crate::storage::schema::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PortScanRecord, SubdomainRecord,
    SubdomainSource, TlsScanRecord, WhoisRecord,
};
use crate::storage::segments::hosts::HostSegment;
use crate::storage::segments::ports::PortSegment;
use crate::storage::segments::subdomains::SubdomainSegment;
use crate::storage::segments::tls::TlsSegment;
use crate::storage::segments::whois::WhoisSegment;
use crate::storage::segments::{dns::DnsSegment, http::HttpSegment};

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
    dirty: bool,
}

impl Database {
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
                dirty: false,
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
                dirty: false,
            });
        }

        let mut header_cursor = std::io::Cursor::new(&bytes);
        let header = FileHeader::read(&mut header_cursor).map_err(decode_err_to_io)?;
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
            dirty: false,
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
            }
        }

        Ok(db)
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

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;

        // Reserve space for header
        let placeholder = FileHeader {
            version: crate::storage::layout::VERSION,
            section_count: segments.len() as u16,
            directory_offset: 0,
        };
        placeholder.write(&mut file)?;

        let mut entries = Vec::new();
        let mut offset = FileHeader::SIZE as u64;
        for (kind, data) in &segments {
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(data)?;
            let mut entry = SectionEntry::new(*kind, offset, data.len() as u64);
            offset += data.len() as u64;

            let metadata_pairs = self.segment_metadata(*kind);
            let metadata_bytes = SegmentMetadata::encode(&metadata_pairs);
            if !metadata_bytes.is_empty() {
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&metadata_bytes)?;
                entry.metadata_offset = offset;
                entry.metadata_length = metadata_bytes.len() as u64;
                entry.flags.insert(SegmentFlags::HAS_METADATA);
                offset += metadata_bytes.len() as u64;
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
        };
        header.write(&mut file)?;
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
        }
    }
}

fn decode_err_to_io(err: DecodeError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.0)
}
