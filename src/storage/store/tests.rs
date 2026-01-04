//! Tests for Database storage operations

#![cfg(test)]

use super::*;
use crate::storage::records::PortStatus;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    let path = std::env::temp_dir().join(format!("rb_store_{}_{}.db", name, std::process::id()));
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
