use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use redblue::storage::records::{
    DnsRecordData, DnsRecordType, HostIntelRecord, HttpHeadersRecord, PortScanRecord, PortStatus,
    ServiceIntelRecord, SubdomainSource, TlsCertRecord, TlsCipherRecord, TlsCipherStrength,
    TlsScanRecord, TlsSeverity, TlsVersionRecord, TlsVulnerabilityRecord,
};
use redblue::storage::store::Database;
use redblue::storage::view::RedDbView;

fn temp_db_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!(
        "rb_roundtrip_{}_{}_{}.rdb",
        name,
        std::process::id(),
        nanos
    ));
    path
}

#[test]
fn storage_roundtrip_zero_copy_views() {
    let path = temp_db_path("segments");
    let target_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));

    {
        let mut db = Database::open(&path).expect("create database");

        db.insert_port_scan(PortScanRecord {
            ip: target_ip,
            port: 443,
            status: PortStatus::Open,
            service_id: 0,
            timestamp: 1,
        });

        db.insert_subdomain(
            "example.com",
            "api.example.com",
            vec![target_ip],
            SubdomainSource::DnsBruteforce,
            2,
        );

        db.insert_whois(
            "example.com",
            "Example Registrar",
            3,
            4,
            vec!["ns1.example.com".into(), "ns2.example.com".into()],
            5,
        );

        let tls_record = TlsScanRecord {
            host: "example.com".into(),
            port: 443,
            timestamp: 6,
            negotiated_version: Some("TLS1.2".into()),
            negotiated_cipher: Some("TLS_RSA_WITH_AES_128_CBC_SHA".into()),
            negotiated_cipher_code: Some(0x002f),
            negotiated_cipher_strength: TlsCipherStrength::Strong,
            certificate_valid: true,
            versions: vec![TlsVersionRecord {
                version: "TLS1.2".into(),
                supported: true,
                error: None,
            }],
            ciphers: vec![TlsCipherRecord {
                name: "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
                code: 0x002f,
                strength: TlsCipherStrength::Strong,
            }],
            vulnerabilities: vec![TlsVulnerabilityRecord {
                name: "test_vuln".into(),
                severity: TlsSeverity::Low,
                description: "demo".into(),
            }],
            certificate_chain: vec![TlsCertRecord {
                domain: "example.com".into(),
                issuer: "Example CA".into(),
                subject: "CN=example.com".into(),
                serial_number: "01".into(),
                signature_algorithm: "sha256WithRSAEncryption".into(),
                public_key_algorithm: "rsaEncryption".into(),
                version: 3,
                not_before: 7,
                not_after: 8,
                sans: vec!["example.com".into()],
                self_signed: false,
                timestamp: 6,
            }],
            ja3: None,
            ja3s: None,
            ja3_raw: None,
            ja3s_raw: None,
            peer_fingerprints: Vec::new(),
            certificate_chain_pem: Vec::new(),
        };
        db.insert_tls_scan(tls_record);

        db.insert_dns(DnsRecordData {
            domain: "example.com".into(),
            record_type: DnsRecordType::A,
            value: "192.0.2.5".into(),
            ttl: 300,
            timestamp: 9,
        });

        db.insert_http(HttpHeadersRecord {
            host: "example.com".into(),
            url: "https://example.com/".into(),
            method: "GET".into(),
            scheme: "https".into(),
            http_version: "HTTP/1.1".into(),
            status_code: 200,
            status_text: "OK".into(),
            server: Some("nginx".into()),
            body_size: 512,
            headers: vec![("content-type".into(), "text/html".into())],
            timestamp: 10,
            tls: None,
        });

        db.insert_host(HostIntelRecord {
            ip: target_ip,
            os_family: Some("linux".into()),
            confidence: 0.9,
            last_seen: 11,
            services: vec![ServiceIntelRecord {
                port: 443,
                service_name: Some("https".into()),
                banner: Some("nginx".into()),
                os_hints: vec!["linux".into()],
            }],
        });

        db.flush().expect("flush");
    }

    let view = RedDbView::open(&path).expect("open view");

    // Ports: direct fetch + range helper
    let ports = view
        .ports()
        .expect("ports segment")
        .records_for_ip(&target_ip)
        .expect("ports for ip");
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].port, 443);

    let range_ports = view
        .ports()
        .expect("ports segment")
        .records_in_range(&target_ip, &target_ip)
        .expect("range query");
    assert_eq!(range_ports.len(), 1);

    // Subdomains prefix helper
    let sub_matches = view
        .subdomains()
        .expect("subdomain segment")
        .records_with_prefix("api.")
        .expect("subdomain prefix");
    assert_eq!(sub_matches.len(), 1);
    assert_eq!(sub_matches[0].subdomain, "api.example.com");

    // DNS prefix helper
    let dns_matches = view
        .dns()
        .expect("dns segment")
        .records_with_domain_prefix("example")
        .expect("dns prefix");
    assert_eq!(dns_matches.len(), 1);
    assert_eq!(dns_matches[0].value, "192.0.2.5");

    // HTTP records
    let http_records = view
        .http()
        .expect("http segment")
        .records_for_host("example.com")
        .expect("http records");
    assert_eq!(http_records.len(), 1);
    assert_eq!(http_records[0].status_code, 200);

    // TLS records
    let tls_records = view
        .tls()
        .expect("tls segment")
        .records_for_host("example.com")
        .expect("tls records");
    assert_eq!(tls_records.len(), 1);
    assert_eq!(
        tls_records[0].negotiated_cipher.as_deref(),
        Some("TLS_RSA_WITH_AES_128_CBC_SHA")
    );

    // WHOIS
    let whois_record = view
        .whois()
        .expect("whois segment")
        .get("example.com")
        .expect("whois lookup");
    assert!(whois_record.is_some());

    // Host intel
    let host_record = view
        .hosts()
        .expect("host segment")
        .get(target_ip)
        .expect("host lookup");
    assert!(host_record.is_some());

    std::fs::remove_file(&path).ok();
}
