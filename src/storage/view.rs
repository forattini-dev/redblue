use std::fs;
use std::io::{self, Cursor};
use std::path::Path;
use std::sync::Arc;

use crate::storage::encoding::DecodeError;
use crate::storage::layout::{FileHeader, SectionEntry, SegmentKind};
use crate::storage::segments::dns::DnsSegmentView;
use crate::storage::segments::hosts::HostSegmentView;
use crate::storage::segments::http::HttpSegmentView;
use crate::storage::segments::iocs::IocSegmentView;
use crate::storage::segments::mitre::MitreSegmentView;
use crate::storage::segments::playbooks::PlaybookSegmentView;
use crate::storage::segments::ports::PortSegmentView;
use crate::storage::segments::proxy::ProxySegmentView;
use crate::storage::segments::sessions::SessionSegmentView; // Import
use crate::storage::segments::subdomains::SubdomainSegmentView;
use crate::storage::segments::tls::TlsSegmentView;
use crate::storage::segments::vuln::VulnSegmentView;
use crate::storage::segments::whois::WhoisSegmentView; // Import

pub struct RedDbView {
    subdomains: Option<SubdomainSegmentView>,
    ports: Option<PortSegmentView>,
    dns: Option<DnsSegmentView>,
    http: Option<HttpSegmentView>,
    tls: Option<TlsSegmentView>,
    whois: Option<WhoisSegmentView>,
    hosts: Option<HostSegmentView>,
    proxy: Option<ProxySegmentView>,
    mitre: Option<MitreSegmentView>,
    iocs: Option<IocSegmentView>,
    vulns: Option<VulnSegmentView>,
    sessions: Option<SessionSegmentView>,   // New field
    playbooks: Option<PlaybookSegmentView>, // New field
}

impl RedDbView {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let data = Arc::new(fs::read(path)?);
        if data.len() < FileHeader::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rdb file too small",
            ));
        }

        let header = FileHeader::read(Cursor::new(&data[..])).map_err(decode_err_to_io)?;
        let dir_start = header.directory_offset as usize;
        let dir_len =
            header.section_count as usize * SectionEntry::size_for_version(header.version);
        if dir_start + dir_len > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rdb directory out of bounds",
            ));
        }

        let directory = SectionEntry::read_all(
            &data[dir_start..dir_start + dir_len],
            header.section_count as usize,
            header.version,
        )
        .map_err(decode_err_to_io)?;

        let mut subdomains = None;
        let mut ports = None;
        let mut dns = None;
        let mut http = None;
        let mut tls = None;
        let mut whois = None;
        let mut hosts_view = None;
        let mut proxy_view = None;
        let mut mitre_view = None;
        let mut iocs_view = None;
        let mut vulns_view = None;
        let mut sessions_view = None; // New
        let mut playbooks_view = None; // New

        for entry in directory {
            let start = entry.offset as usize;
            if entry.length > usize::MAX as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "segment length exceeds platform limits",
                ));
            }
            let seg_len = entry.length as usize;
            let end = start + seg_len;
            if end > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "segment out of bounds",
                ));
            }
            let segment_data = Arc::clone(&data); // Access the segment data

            match entry.kind {
                SegmentKind::Subdomains => {
                    let view = SubdomainSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    subdomains = Some(view);
                }
                SegmentKind::Ports => {
                    let view = PortSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    ports = Some(view);
                }
                SegmentKind::Dns => {
                    let view = DnsSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    dns = Some(view);
                }
                SegmentKind::Http => {
                    let view = HttpSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    http = Some(view);
                }
                SegmentKind::Tls => {
                    let view = TlsSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    tls = Some(view);
                }
                SegmentKind::Host => {
                    let view = HostSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    hosts_view = Some(view);
                }
                SegmentKind::Whois => {
                    let view = WhoisSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    whois = Some(view);
                }
                SegmentKind::Proxy => {
                    let view = ProxySegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    proxy_view = Some(view);
                }
                SegmentKind::Mitre => {
                    let view = MitreSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    mitre_view = Some(view);
                }
                SegmentKind::Ioc => {
                    let view = IocSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    iocs_view = Some(view);
                }
                SegmentKind::Vuln => {
                    let view = VulnSegmentView::from_arc(segment_data, start, seg_len)
                        .map_err(decode_err_to_io)?;
                    vulns_view = Some(view);
                }
                SegmentKind::Sessions => {
                    // TODO: Implement SessionSegmentView
                    eprintln!("Warning: SessionSegmentView not implemented for RedDbView.");
                    sessions_view = None;
                }
                SegmentKind::Playbooks => {
                    // TODO: Implement PlaybookSegmentView
                    eprintln!("Warning: PlaybookSegmentView not implemented for RedDbView.");
                    playbooks_view = None;
                }
            }
        }

        Ok(Self {
            subdomains,
            ports,
            dns,
            http,
            tls,
            whois,
            hosts: hosts_view,
            proxy: proxy_view,
            mitre: mitre_view,
            iocs: iocs_view,
            vulns: vulns_view,
            sessions: sessions_view,   // New
            playbooks: playbooks_view, // New
        })
    }

    pub fn subdomains(&self) -> Option<&SubdomainSegmentView> {
        self.subdomains.as_ref()
    }

    pub fn ports(&self) -> Option<&PortSegmentView> {
        self.ports.as_ref()
    }

    pub fn dns(&self) -> Option<&DnsSegmentView> {
        self.dns.as_ref()
    }

    pub fn http(&self) -> Option<&HttpSegmentView> {
        self.http.as_ref()
    }

    pub fn tls(&self) -> Option<&TlsSegmentView> {
        self.tls.as_ref()
    }

    pub fn whois(&self) -> Option<&WhoisSegmentView> {
        self.whois.as_ref()
    }

    pub fn hosts(&self) -> Option<&HostSegmentView> {
        self.hosts.as_ref()
    }

    pub fn proxy(&self) -> Option<&ProxySegmentView> {
        self.proxy.as_ref()
    }

    pub fn mitre(&self) -> Option<&MitreSegmentView> {
        self.mitre.as_ref()
    }

    pub fn iocs(&self) -> Option<&IocSegmentView> {
        self.iocs.as_ref()
    }

    pub fn vulns(&self) -> Option<&VulnSegmentView> {
        self.vulns.as_ref()
    }

    pub fn sessions(&self) -> Option<&SessionSegmentView> {
        self.sessions.as_ref()
    }

    pub fn playbooks(&self) -> Option<&PlaybookSegmentView> {
        self.playbooks.as_ref()
    }
}

fn decode_err_to_io(err: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::records::PortStatus;
    use crate::storage::reddb::RedDb;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    struct FileGuard {
        path: PathBuf,
    }

    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_db(name: &str) -> (FileGuard, PathBuf) {
        let path = std::env::temp_dir().join(format!("rb_view_{}_{}.db", name, std::process::id()));
        let guard = FileGuard { path: path.clone() };
        let _ = std::fs::remove_file(&path);
        (guard, path)
    }

    // ==================== Open Tests ====================

    #[test]
    fn test_open_nonexistent_file() {
        let result = RedDbView::open("/nonexistent/path/file.db");
        assert!(result.is_err());
    }

    #[test]
    fn test_open_empty_file() {
        let (_guard, path) = temp_db("empty");
        std::fs::write(&path, &[]).unwrap();

        let result = RedDbView::open(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_view_with_ports() {
        let (_guard, path) = temp_db("ports");

        // Create database with port scans
        {
            let mut db = RedDb::open(&path).unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            db.save_port_scan(ip, 22, PortStatus::Open).unwrap();
            db.save_port_scan(ip, 80, PortStatus::Open).unwrap();
            db.save_port_scan(ip, 443, PortStatus::Closed).unwrap();
            db.flush().unwrap();
        }

        // Open as view
        let view = RedDbView::open(&path).unwrap();
        assert!(view.ports().is_some());
    }

    #[test]
    fn test_view_with_subdomains() {
        let (_guard, path) = temp_db("subs");

        // Create database with subdomains
        {
            let mut db = RedDb::open(&path).unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            db.save_subdomain(
                "example.com",
                "api.example.com",
                vec![ip],
                crate::storage::records::SubdomainSource::DnsBruteforce,
            )
            .unwrap();
            db.save_subdomain(
                "example.com",
                "www.example.com",
                vec![ip],
                crate::storage::records::SubdomainSource::CertTransparency,
            )
            .unwrap();
            db.flush().unwrap();
        }

        // Open as view
        let view = RedDbView::open(&path).unwrap();
        assert!(view.subdomains().is_some());
    }

    #[test]
    fn test_view_accessors() {
        let (_guard, path) = temp_db("accessors");

        // Create database with data
        {
            let mut db = RedDb::open(&path).unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            db.save_port_scan(ip, 80, PortStatus::Open).unwrap();
            db.flush().unwrap();
        }

        // Verify accessors
        let view = RedDbView::open(&path).unwrap();

        // Some accessors may be None if no data was written for that type
        assert!(view.ports().is_some());
        // These may or may not have data depending on the flush
        let _ = view.subdomains();
        let _ = view.dns();
        let _ = view.http();
        let _ = view.tls();
        let _ = view.whois();
        let _ = view.hosts();
    }

    #[test]
    fn test_too_small_file() {
        let (_guard, path) = temp_db("small");
        // Write less than FileHeader::SIZE bytes
        std::fs::write(&path, b"tiny").unwrap();

        let result = RedDbView::open(&path);
        assert!(result.is_err());
    }
}
