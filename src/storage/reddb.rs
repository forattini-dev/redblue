use std::io;
use std::net::IpAddr;
use std::path::Path;

use crate::storage::records::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PortStatus, SubdomainSource, TlsScanRecord,
    WhoisRecord, ProxyConnectionRecord, ProxyHttpRequestRecord, ProxyHttpResponseRecord, ProxyWebSocketRecord,
};
use crate::storage::store::Database;
use crate::storage::tables::{
    DnsTable, HostIntelTable, HttpTable, PortScanTable, SubdomainTable, TlsScanTable, WhoisTable,
    ProxyTable,
};

pub struct RedDb {
    store: Database,
}

impl RedDb {
    /// Open database without encryption (plaintext)
    /// WARNING: Use `open_encrypted` for production data
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self {
            store: Database::open(path)?,
        })
    }

    /// Open database with password-based encryption
    /// Uses PBKDF2-SHA256 for key derivation and AES-256-GCM for encryption
    pub fn open_encrypted<P: AsRef<Path>>(path: P, password: &str) -> io::Result<Self> {
        Ok(Self {
            store: Database::open_encrypted(path, password)?,
        })
    }

    /// Check if a database file is encrypted
    pub fn is_encrypted_file<P: AsRef<Path>>(path: P) -> bool {
        Database::is_encrypted_file(path)
    }

    pub fn ports(&mut self) -> PortScanTable {
        PortScanTable::new(&mut self.store)
    }

    pub fn subdomains(&mut self) -> SubdomainTable {
        SubdomainTable::new(&mut self.store)
    }

    pub fn whois(&mut self) -> WhoisTable {
        WhoisTable::new(&mut self.store)
    }

    pub fn tls(&mut self) -> TlsScanTable {
        TlsScanTable::new(&mut self.store)
    }

    pub fn dns(&mut self) -> DnsTable {
        DnsTable::new(&mut self.store)
    }

    pub fn http(&mut self) -> HttpTable {
        HttpTable::new(&mut self.store)
    }

    pub fn hosts(&mut self) -> HostIntelTable {
        HostIntelTable::new(&mut self.store)
    }

    pub fn proxy(&mut self) -> ProxyTable {
        ProxyTable::new(&mut self.store)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.store.flush()
    }

    pub fn save_port_scan(&mut self, ip: IpAddr, port: u16, status: PortStatus) -> io::Result<()> {
        self.ports().insert(ip, port, status)
    }

    pub fn get_open_ports(&mut self, ip: IpAddr) -> io::Result<Vec<u16>> {
        self.ports().get_open_ports(ip)
    }

    pub fn save_subdomain(
        &mut self,
        domain: &str,
        subdomain: &str,
        ips: Vec<IpAddr>,
        source: SubdomainSource,
    ) -> io::Result<()> {
        self.subdomains().insert(domain, subdomain, ips, source)
    }

    pub fn get_subdomains(&mut self, domain: &str) -> io::Result<Vec<String>> {
        self.subdomains().get_unique(domain)
    }

    pub fn save_whois(
        &mut self,
        domain: &str,
        registrar: &str,
        created: u32,
        expires: u32,
        nameservers: Vec<String>,
    ) -> io::Result<()> {
        self.whois()
            .insert(domain, registrar, created, expires, nameservers)
    }

    pub fn get_whois(&mut self, domain: &str) -> io::Result<Option<WhoisRecord>> {
        self.whois().get(domain, 0)
    }

    pub fn save_tls_scan(&mut self, record: TlsScanRecord) -> io::Result<()> {
        self.tls().insert(record)
    }

    pub fn tls_scans_for_host(&mut self, host: &str) -> io::Result<Vec<TlsScanRecord>> {
        Ok(self.tls().for_host(host))
    }

    pub fn tls_scans(&mut self) -> io::Result<Vec<TlsScanRecord>> {
        let table = self.tls();
        Ok(table.iter().collect())
    }

    pub fn save_dns(&mut self, record: DnsRecordData) -> io::Result<()> {
        self.dns().insert(record)
    }

    pub fn get_dns_records(&mut self, domain: &str) -> io::Result<Vec<DnsRecordData>> {
        self.dns().get_by_domain(domain)
    }

    pub fn save_http(&mut self, record: HttpHeadersRecord) -> io::Result<()> {
        self.http().insert(record)
    }

    pub fn get_http_by_host(&mut self, host: &str) -> io::Result<Vec<HttpHeadersRecord>> {
        self.http().get_by_host(host)
    }

    pub fn save_host_fingerprint(&mut self, record: HostIntelRecord) -> io::Result<()> {
        self.hosts().insert(record)
    }

    pub fn get_host_fingerprint(&mut self, ip: IpAddr) -> io::Result<Option<HostIntelRecord>> {
        self.hosts().get(ip)
    }

    pub fn list_host_fingerprints(&mut self) -> io::Result<Vec<HostIntelRecord>> {
        self.hosts().all()
    }

    // ==================== Proxy Methods ====================

    pub fn save_proxy_connection(&mut self, record: ProxyConnectionRecord) -> io::Result<()> {
        self.proxy().insert_connection(record)
    }

    pub fn save_proxy_http_request(&mut self, record: ProxyHttpRequestRecord) -> io::Result<()> {
        self.proxy().insert_http_request(record)
    }

    pub fn save_proxy_http_response(&mut self, record: ProxyHttpResponseRecord) -> io::Result<()> {
        self.proxy().insert_http_response(record)
    }

    pub fn save_proxy_websocket(&mut self, record: ProxyWebSocketRecord) -> io::Result<()> {
        self.proxy().insert_websocket(record)
    }

    pub fn get_proxy_connections(&mut self) -> io::Result<Vec<ProxyConnectionRecord>> {
        Ok(self.proxy().connections())
    }

    pub fn get_proxy_connections_for_host(&mut self, host: &str) -> io::Result<Vec<ProxyConnectionRecord>> {
        self.proxy().connections_for_host(host)
    }

    pub fn get_proxy_requests(&mut self) -> io::Result<Vec<ProxyHttpRequestRecord>> {
        Ok(self.proxy().http_requests())
    }

    pub fn get_proxy_requests_for_connection(&mut self, connection_id: u64) -> io::Result<Vec<ProxyHttpRequestRecord>> {
        self.proxy().requests_for_connection(connection_id)
    }

    pub fn get_proxy_responses(&mut self) -> io::Result<Vec<ProxyHttpResponseRecord>> {
        Ok(self.proxy().http_responses())
    }

    pub fn get_proxy_responses_for_connection(&mut self, connection_id: u64) -> io::Result<Vec<ProxyHttpResponseRecord>> {
        self.proxy().responses_for_connection(connection_id)
    }

    pub fn get_proxy_websocket_messages(&mut self, connection_id: u64) -> io::Result<Vec<ProxyWebSocketRecord>> {
        Ok(self.proxy().websocket_messages(connection_id))
    }

    pub fn proxy_connection_count(&mut self) -> io::Result<usize> {
        self.proxy().connection_count()
    }

    pub fn proxy_request_count(&mut self) -> io::Result<usize> {
        self.proxy().request_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::records::{DnsRecordType, TlsCipherStrength};
    use std::net::Ipv4Addr;

    struct FileGuard {
        path: std::path::PathBuf,
    }

    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_db(name: &str) -> (FileGuard, RedDb) {
        let path = std::env::temp_dir().join(format!("rb_reddb_{}_{}.db", name, std::process::id()));
        let guard = FileGuard { path: path.clone() };
        let _ = std::fs::remove_file(&guard.path);
        let db = RedDb::open(&guard.path).unwrap();
        (guard, db)
    }

    // ==================== Basic Operations Tests ====================

    #[test]
    fn smoke_test() {
        let (_guard, mut db) = temp_db("smoke");

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        db.save_port_scan(ip, 443, PortStatus::Open).unwrap();
        db.save_port_scan(ip, 22, PortStatus::Closed).unwrap();

        let opens = db.get_open_ports(ip).unwrap();
        assert_eq!(opens, vec![443]);

        db.save_subdomain(
            "example.com",
            "api.example.com",
            vec![ip],
            SubdomainSource::DnsBruteforce,
        )
        .unwrap();

        assert_eq!(db.get_subdomains("example.com").unwrap().len(), 1);

        db.flush().unwrap();
    }

    #[test]
    fn test_open_creates_file() {
        let (_guard, mut db) = temp_db("create");
        // File is created on first flush with data
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        db.save_port_scan(ip, 80, PortStatus::Open).unwrap();
        db.flush().unwrap();
        assert!(_guard.path.exists());
    }

    #[test]
    fn test_reopen_database() {
        let path = std::env::temp_dir().join(format!("rb_reddb_reopen_{}.db", std::process::id()));
        let guard = FileGuard { path: path.clone() };
        let _ = std::fs::remove_file(&guard.path);

        // Create and write
        {
            let mut db = RedDb::open(&guard.path).unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            db.save_port_scan(ip, 80, PortStatus::Open).unwrap();
            db.flush().unwrap();
        }

        // Reopen and read
        {
            let mut db = RedDb::open(&guard.path).unwrap();
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let ports = db.get_open_ports(ip).unwrap();
            assert_eq!(ports, vec![80]);
        }
    }

    // ==================== Port Scan Tests ====================

    #[test]
    fn test_port_scan_multiple() {
        let (_guard, mut db) = temp_db("ports");
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        db.save_port_scan(ip, 22, PortStatus::Open).unwrap();
        db.save_port_scan(ip, 80, PortStatus::Open).unwrap();
        db.save_port_scan(ip, 443, PortStatus::Open).unwrap();
        db.save_port_scan(ip, 3306, PortStatus::Closed).unwrap();
        db.save_port_scan(ip, 5432, PortStatus::Filtered).unwrap();

        let opens = db.get_open_ports(ip).unwrap();
        assert_eq!(opens.len(), 3);
        assert!(opens.contains(&22));
        assert!(opens.contains(&80));
        assert!(opens.contains(&443));
    }

    #[test]
    fn test_port_scan_different_hosts() {
        let (_guard, mut db) = temp_db("ports_multi");

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        db.save_port_scan(ip1, 22, PortStatus::Open).unwrap();
        db.save_port_scan(ip1, 80, PortStatus::Closed).unwrap();
        db.save_port_scan(ip2, 443, PortStatus::Open).unwrap();

        assert_eq!(db.get_open_ports(ip1).unwrap(), vec![22]);
        assert_eq!(db.get_open_ports(ip2).unwrap(), vec![443]);
    }

    // ==================== Subdomain Tests ====================

    #[test]
    fn test_subdomain_multiple() {
        let (_guard, mut db) = temp_db("subdomains");
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        db.save_subdomain("example.com", "www.example.com", vec![ip], SubdomainSource::DnsBruteforce).unwrap();
        db.save_subdomain("example.com", "api.example.com", vec![ip], SubdomainSource::CertTransparency).unwrap();
        db.save_subdomain("example.com", "mail.example.com", vec![], SubdomainSource::WebCrawl).unwrap();

        let subs = db.get_subdomains("example.com").unwrap();
        assert_eq!(subs.len(), 3);
    }

    #[test]
    fn test_subdomain_different_domains() {
        let (_guard, mut db) = temp_db("subdomains_multi");
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        db.save_subdomain("example.com", "www.example.com", vec![ip], SubdomainSource::DnsBruteforce).unwrap();
        db.save_subdomain("test.org", "api.test.org", vec![ip], SubdomainSource::DnsBruteforce).unwrap();

        assert_eq!(db.get_subdomains("example.com").unwrap().len(), 1);
        assert_eq!(db.get_subdomains("test.org").unwrap().len(), 1);
        assert!(db.get_subdomains("notfound.net").unwrap().is_empty());
    }

    // ==================== WHOIS Tests ====================

    #[test]
    fn test_whois_save_get() {
        let (_guard, mut db) = temp_db("whois");

        db.save_whois(
            "example.com",
            "Example Registrar",
            1234567890,
            1888888888,
            vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
        ).unwrap();

        let whois = db.get_whois("example.com").unwrap();
        assert!(whois.is_some());

        let record = whois.unwrap();
        assert_eq!(record.domain, "example.com");
        assert_eq!(record.registrar, "Example Registrar");
        assert_eq!(record.nameservers.len(), 2);
    }

    #[test]
    fn test_whois_not_found() {
        let (_guard, mut db) = temp_db("whois_notfound");
        assert!(db.get_whois("nonexistent.com").unwrap().is_none());
    }

    // ==================== DNS Tests ====================

    #[test]
    fn test_dns_save_get() {
        let (_guard, mut db) = temp_db("dns");

        db.save_dns(DnsRecordData {
            domain: "example.com".to_string(),
            record_type: DnsRecordType::A,
            value: "93.184.216.34".to_string(),
            ttl: 3600,
            timestamp: 1700000000,
        }).unwrap();

        db.save_dns(DnsRecordData {
            domain: "example.com".to_string(),
            record_type: DnsRecordType::MX,
            value: "mail.example.com".to_string(),
            ttl: 7200,
            timestamp: 1700000000,
        }).unwrap();

        let records = db.get_dns_records("example.com").unwrap();
        assert_eq!(records.len(), 2);
    }

    // ==================== TLS Tests ====================

    #[test]
    fn test_tls_save_get() {
        let (_guard, mut db) = temp_db("tls");

        let record = TlsScanRecord {
            host: "example.com".to_string(),
            port: 443,
            timestamp: 1700000000,
            negotiated_version: Some("TLSv1.3".to_string()),
            negotiated_cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
            negotiated_cipher_code: Some(0x1302),
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

        db.save_tls_scan(record).unwrap();

        let scans = db.tls_scans_for_host("example.com").unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].negotiated_version, Some("TLSv1.3".to_string()));
    }

    #[test]
    fn test_tls_all_scans() {
        let (_guard, mut db) = temp_db("tls_all");

        for host in ["a.com", "b.com", "c.com"] {
            db.save_tls_scan(TlsScanRecord {
                host: host.to_string(),
                port: 443,
                timestamp: 1700000000,
                negotiated_version: None,
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
            }).unwrap();
        }

        let all = db.tls_scans().unwrap();
        assert_eq!(all.len(), 3);
    }

    // ==================== HTTP Tests ====================

    #[test]
    fn test_http_save_get() {
        let (_guard, mut db) = temp_db("http");

        let record = HttpHeadersRecord {
            host: "example.com".to_string(),
            url: "https://example.com/".to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            http_version: "HTTP/1.1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            server: Some("nginx".to_string()),
            body_size: 1234,
            headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("X-Frame-Options".to_string(), "DENY".to_string()),
            ],
            timestamp: 1700000000,
            tls: None,
        };

        db.save_http(record).unwrap();

        let records = db.get_http_by_host("example.com").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status_code, 200);
    }

    // ==================== Host Fingerprint Tests ====================

    #[test]
    fn test_host_fingerprint() {
        let (_guard, mut db) = temp_db("fingerprint");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let record = HostIntelRecord {
            ip,
            os_family: Some("Linux".to_string()),
            confidence: 0.9,
            last_seen: 1700000000,
            services: vec![],
        };

        db.save_host_fingerprint(record).unwrap();

        let result = db.get_host_fingerprint(ip).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().os_family, Some("Linux".to_string()));
    }

    #[test]
    fn test_host_fingerprint_list() {
        let (_guard, mut db) = temp_db("fingerprint_list");

        for i in 1..=5 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            db.save_host_fingerprint(HostIntelRecord {
                ip,
                os_family: Some(format!("OS{}", i)),
                confidence: 0.5,
                last_seen: 1700000000,
                services: vec![],
            }).unwrap();
        }

        let all = db.list_host_fingerprints().unwrap();
        assert_eq!(all.len(), 5);
    }

    // ==================== Table Access Tests ====================

    #[test]
    fn test_table_accessors() {
        let (_guard, mut db) = temp_db("tables");

        // Just verify that all table accessors compile and return something
        let _ports = db.ports();
        let _subs = db.subdomains();
        let _whois = db.whois();
        let _tls = db.tls();
        let _dns = db.dns();
        let _http = db.http();
        let _hosts = db.hosts();
    }

    #[test]
    fn test_flush() {
        let (_guard, mut db) = temp_db("flush");
        db.flush().unwrap();
    }
}
