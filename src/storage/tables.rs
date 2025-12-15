use std::io;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::records::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PlaybookRunRecord, PortScanRecord,
    PortStatus, ProxyConnectionRecord, ProxyHttpRequestRecord, ProxyHttpResponseRecord,
    ProxyWebSocketRecord, SessionRecord, SubdomainRecord, SubdomainSource, TlsScanRecord,
    WhoisRecord,
};
use crate::storage::store::Database;

pub struct PortScanTable<'a> {
    db: &'a mut Database,
}

impl<'a> PortScanTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, ip: IpAddr, port: u16, status: PortStatus) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.db.insert_port_scan(PortScanRecord {
            ip,
            port,
            status,
            service_id: 0,
            timestamp,
        });
        Ok(())
    }

    pub fn get(&mut self, ip: IpAddr, port: u16) -> io::Result<Option<PortScanRecord>> {
        Ok(self.db.find_port(ip, port))
    }

    pub fn get_by_ip(&mut self, ip: IpAddr) -> io::Result<Vec<PortScanRecord>> {
        Ok(self.db.ports_for_ip(ip))
    }

    pub fn get_open_ports(&mut self, ip: IpAddr) -> io::Result<Vec<u16>> {
        Ok(self.db.open_ports(ip))
    }

    pub fn count(&mut self) -> io::Result<usize> {
        Ok(self.db.port_count())
    }

    pub fn get_all(&mut self) -> io::Result<Vec<PortScanRecord>> {
        Ok(self.db.all_ports())
    }
}

pub struct SubdomainTable<'a> {
    db: &'a mut Database,
}

impl<'a> SubdomainTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(
        &mut self,
        domain: &str,
        subdomain: &str,
        ips: Vec<IpAddr>,
        source: SubdomainSource,
    ) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.db
            .insert_subdomain(domain, subdomain, ips, source, timestamp);
        Ok(())
    }

    pub fn get_by_domain(&mut self, domain: &str) -> io::Result<Vec<SubdomainRecord>> {
        Ok(self.db.subdomains_of(domain))
    }

    pub fn get_by_source(
        &mut self,
        domain: &str,
        source: SubdomainSource,
    ) -> io::Result<Vec<String>> {
        let records = self.db.subdomains_of(domain);
        Ok(records
            .into_iter()
            .filter(|r| r.source as u8 == source as u8)
            .map(|r| r.subdomain)
            .collect())
    }

    pub fn get_unique(&mut self, domain: &str) -> io::Result<Vec<String>> {
        let mut records = self.db.subdomains_of(domain);
        records.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
        records.dedup_by(|a, b| a.subdomain == b.subdomain);
        Ok(records.into_iter().map(|r| r.subdomain).collect())
    }

    pub fn get_all(&mut self) -> io::Result<Vec<SubdomainRecord>> {
        Ok(self.db.all_subdomains())
    }
}

pub struct WhoisTable<'a> {
    db: &'a mut Database,
}

impl<'a> WhoisTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(
        &mut self,
        domain: &str,
        registrar: &str,
        created: u32,
        expires: u32,
        nameservers: Vec<String>,
    ) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.db
            .insert_whois(domain, registrar, created, expires, nameservers, timestamp);
        Ok(())
    }

    pub fn get(&self, domain: &str, _max_age_secs: u32) -> io::Result<Option<WhoisRecord>> {
        Ok(self.db.get_whois(domain))
    }
}

pub struct TlsScanTable<'a> {
    db: &'a mut Database,
}

impl<'a> TlsScanTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, mut record: TlsScanRecord) -> io::Result<()> {
        if record.timestamp == 0 {
            record.timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
        }
        self.db.insert_tls_scan(record);
        Ok(())
    }

    pub fn for_host(&self, host: &str) -> Vec<TlsScanRecord> {
        self.db.tls_scans_for_host(host)
    }

    pub fn iter(&self) -> impl Iterator<Item = TlsScanRecord> + '_ {
        self.db.tls_scans()
    }
}

pub struct DnsTable<'a> {
    db: &'a mut Database,
}

impl<'a> DnsTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: DnsRecordData) -> io::Result<()> {
        self.db.insert_dns(record);
        Ok(())
    }

    pub fn iter(&mut self) -> impl Iterator<Item = DnsRecordData> + '_ {
        self.db.dns_records()
    }

    pub fn get_by_domain(&mut self, domain: &str) -> io::Result<Vec<DnsRecordData>> {
        Ok(self.db.dns_for_domain(domain))
    }
}

pub struct HttpTable<'a> {
    db: &'a mut Database,
}

impl<'a> HttpTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: HttpHeadersRecord) -> io::Result<()> {
        self.db.insert_http(record);
        Ok(())
    }

    pub fn iter(&mut self) -> impl Iterator<Item = HttpHeadersRecord> + '_ {
        self.db.http_records()
    }

    pub fn get_by_host(&mut self, host: &str) -> io::Result<Vec<HttpHeadersRecord>> {
        Ok(self.db.http_for_host(host))
    }
}

pub struct HostIntelTable<'a> {
    db: &'a mut Database,
}

impl<'a> HostIntelTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: HostIntelRecord) -> io::Result<()> {
        self.db.insert_host(record);
        Ok(())
    }

    pub fn get(&mut self, ip: IpAddr) -> io::Result<Option<HostIntelRecord>> {
        Ok(self.db.host_record(ip))
    }

    pub fn all(&mut self) -> io::Result<Vec<HostIntelRecord>> {
        Ok(self.db.all_hosts())
    }
}

pub struct ProxyTable<'a> {
    db: &'a mut Database,
}

impl<'a> ProxyTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert_connection(&mut self, record: ProxyConnectionRecord) -> io::Result<()> {
        self.db.insert_proxy_connection(record);
        Ok(())
    }

    pub fn insert_http_request(&mut self, record: ProxyHttpRequestRecord) -> io::Result<()> {
        self.db.insert_proxy_http_request(record);
        Ok(())
    }

    pub fn insert_http_response(&mut self, record: ProxyHttpResponseRecord) -> io::Result<()> {
        self.db.insert_proxy_http_response(record);
        Ok(())
    }

    pub fn insert_websocket(&mut self, record: ProxyWebSocketRecord) -> io::Result<()> {
        self.db.insert_proxy_websocket(record);
        Ok(())
    }

    pub fn connections(&mut self) -> Vec<ProxyConnectionRecord> {
        self.db.proxy_connections()
    }

    pub fn http_requests(&mut self) -> Vec<ProxyHttpRequestRecord> {
        self.db.proxy_http_requests()
    }

    pub fn http_responses(&mut self) -> Vec<ProxyHttpResponseRecord> {
        self.db.proxy_http_responses()
    }

    pub fn websocket_messages(&mut self, connection_id: u64) -> Vec<ProxyWebSocketRecord> {
        self.db
            .proxy_websocket_messages(connection_id)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn connections_for_host(&mut self, host: &str) -> io::Result<Vec<ProxyConnectionRecord>> {
        Ok(self.db.proxy_connections_for_host(host))
    }

    pub fn requests_for_connection(
        &mut self,
        connection_id: u64,
    ) -> io::Result<Vec<ProxyHttpRequestRecord>> {
        Ok(self.db.proxy_requests_for_connection(connection_id))
    }

    pub fn responses_for_connection(
        &mut self,
        connection_id: u64,
    ) -> io::Result<Vec<ProxyHttpResponseRecord>> {
        Ok(self.db.proxy_responses_for_connection(connection_id))
    }

    pub fn connection_count(&self) -> io::Result<usize> {
        Ok(self.db.proxy_connection_count())
    }

    pub fn request_count(&self) -> io::Result<usize> {
        Ok(self.db.proxy_request_count())
    }
}

pub struct MitreTable<'a> {
    db: &'a mut Database,
}

impl<'a> MitreTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: crate::storage::records::MitreAttackRecord) -> io::Result<()> {
        self.db.insert_mitre_record(record);
        Ok(())
    }

    pub fn get_by_technique(
        &mut self,
        technique_id: &str,
    ) -> io::Result<Vec<crate::storage::records::MitreAttackRecord>> {
        Ok(self.db.mitre_records_by_technique(technique_id))
    }

    pub fn all(&mut self) -> io::Result<Vec<crate::storage::records::MitreAttackRecord>> {
        Ok(self.db.mitre_records().clone())
    }
}

pub struct IocTable<'a> {
    db: &'a mut Database,
}

impl<'a> IocTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: crate::storage::records::IocRecord) -> io::Result<()> {
        self.db.insert_ioc_record(record);
        Ok(())
    }

    pub fn get_by_type(
        &mut self,
        ioc_type: crate::storage::records::IocType,
    ) -> io::Result<Vec<crate::storage::records::IocRecord>> {
        Ok(self.db.ioc_records_by_type(ioc_type))
    }

    pub fn all(&mut self) -> io::Result<Vec<crate::storage::records::IocRecord>> {
        Ok(self.db.ioc_records().clone())
    }
}

pub struct VulnTable<'a> {
    db: &'a mut Database,
}

impl<'a> VulnTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(
        &mut self,
        record: crate::storage::records::VulnerabilityRecord,
    ) -> io::Result<()> {
        self.db.insert_vulnerability(record);
        Ok(())
    }

    pub fn all(&mut self) -> io::Result<Vec<crate::storage::records::VulnerabilityRecord>> {
        Ok(self.db.vulnerability_records())
    }
}

pub struct SessionTable<'a> {
    db: &'a mut Database,
}

impl<'a> SessionTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: SessionRecord) -> io::Result<()> {
        self.db.insert_session(record);
        Ok(())
    }

    pub fn update(&mut self, record: SessionRecord) -> io::Result<()> {
        self.db.update_session(record);
        Ok(())
    }

    pub fn get(&self, id: &str) -> io::Result<Option<SessionRecord>> {
        Ok(self.db.get_session(id))
    }

    pub fn for_target(&self, target: &str) -> io::Result<Vec<SessionRecord>> {
        Ok(self.db.sessions_for_target(target))
    }

    pub fn active(&self) -> io::Result<Vec<SessionRecord>> {
        Ok(self.db.active_sessions())
    }

    pub fn all(&self) -> io::Result<Vec<SessionRecord>> {
        Ok(self.db.all_sessions())
    }
}

pub struct PlaybookTable<'a> {
    db: &'a mut Database,
}

impl<'a> PlaybookTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(&mut self, record: PlaybookRunRecord) -> io::Result<()> {
        self.db.insert_playbook_run(record);
        Ok(())
    }

    pub fn for_playbook(&self, name: &str) -> io::Result<Vec<PlaybookRunRecord>> {
        Ok(self.db.playbook_runs(name))
    }

    pub fn for_target(&self, target: &str) -> io::Result<Vec<PlaybookRunRecord>> {
        Ok(self.db.playbook_runs_for_target(target))
    }

    pub fn all(&self) -> io::Result<Vec<PlaybookRunRecord>> {
        Ok(self.db.all_playbook_runs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::records::{DnsRecordType, TlsCipherStrength};
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
        let path =
            std::env::temp_dir().join(format!("rb_tables_{}_{}.db", name, std::process::id()));
        let guard = FileGuard { path: path.clone() };
        let _ = std::fs::remove_file(&path);
        (guard, path)
    }

    // ==================== PortScanTable Tests ====================

    #[test]
    fn test_port_scan_table_insert() {
        let (_guard, path) = temp_db("port_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        table.insert(ip, 80, PortStatus::Open).unwrap();

        assert_eq!(table.count().unwrap(), 1);
    }

    #[test]
    fn test_port_scan_table_get() {
        let (_guard, path) = temp_db("port_get");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        table.insert(ip, 22, PortStatus::Open).unwrap();

        let result = table.get(ip, 22).unwrap();
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.port, 22);
        assert_eq!(record.status, PortStatus::Open);
    }

    #[test]
    fn test_port_scan_table_get_nonexistent() {
        let (_guard, path) = temp_db("port_noexist");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = table.get(ip, 9999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_port_scan_table_get_by_ip() {
        let (_guard, path) = temp_db("port_byip");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        table.insert(ip, 22, PortStatus::Open).unwrap();
        table.insert(ip, 80, PortStatus::Open).unwrap();
        table.insert(ip, 443, PortStatus::Closed).unwrap();

        let results = table.get_by_ip(ip).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_port_scan_table_get_open_ports() {
        let (_guard, path) = temp_db("port_open");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        table.insert(ip, 22, PortStatus::Open).unwrap();
        table.insert(ip, 23, PortStatus::Closed).unwrap();
        table.insert(ip, 80, PortStatus::Open).unwrap();
        table.insert(ip, 443, PortStatus::Filtered).unwrap();

        let open = table.get_open_ports(ip).unwrap();
        assert_eq!(open.len(), 2);
        assert!(open.contains(&22));
        assert!(open.contains(&80));
    }

    #[test]
    fn test_port_scan_table_count() {
        let (_guard, path) = temp_db("port_count");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        assert_eq!(table.count().unwrap(), 0);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        table.insert(ip, 80, PortStatus::Open).unwrap();
        assert_eq!(table.count().unwrap(), 1);

        table.insert(ip, 443, PortStatus::Open).unwrap();
        assert_eq!(table.count().unwrap(), 2);
    }

    #[test]
    fn test_port_scan_table_get_all() {
        let (_guard, path) = temp_db("port_all");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.insert(ip1, 22, PortStatus::Open).unwrap();
        table.insert(ip1, 80, PortStatus::Open).unwrap();
        table.insert(ip2, 443, PortStatus::Closed).unwrap();

        let all = table.get_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_port_scan_table_ipv6() {
        let (_guard, path) = temp_db("port_ipv6");
        let mut db = Database::open(&path).unwrap();
        let mut table = PortScanTable::new(&mut db);

        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        table.insert(ip, 443, PortStatus::Open).unwrap();

        let result = table.get(ip, 443).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().ip, ip);
    }

    // ==================== SubdomainTable Tests ====================

    #[test]
    fn test_subdomain_table_insert() {
        let (_guard, path) = temp_db("sub_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = SubdomainTable::new(&mut db);

        let ips = vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        table
            .insert(
                "example.com",
                "www.example.com",
                ips,
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();

        let all = table.get_all().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_subdomain_table_get_by_domain() {
        let (_guard, path) = temp_db("sub_bydomain");
        let mut db = Database::open(&path).unwrap();
        let mut table = SubdomainTable::new(&mut db);

        let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        table
            .insert(
                "example.com",
                "api.example.com",
                ips.clone(),
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();
        table
            .insert(
                "example.com",
                "www.example.com",
                ips.clone(),
                SubdomainSource::CertTransparency,
            )
            .unwrap();
        table
            .insert(
                "other.com",
                "www.other.com",
                ips,
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();

        let results = table.get_by_domain("example.com").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_subdomain_table_get_by_source() {
        let (_guard, path) = temp_db("sub_bysource");
        let mut db = Database::open(&path).unwrap();
        let mut table = SubdomainTable::new(&mut db);

        let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        table
            .insert(
                "example.com",
                "dns.example.com",
                ips.clone(),
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();
        table
            .insert(
                "example.com",
                "ct.example.com",
                ips.clone(),
                SubdomainSource::CertTransparency,
            )
            .unwrap();
        table
            .insert(
                "example.com",
                "dns2.example.com",
                ips,
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();

        let bruteforce = table
            .get_by_source("example.com", SubdomainSource::DnsBruteforce)
            .unwrap();
        assert_eq!(bruteforce.len(), 2);

        let ct = table
            .get_by_source("example.com", SubdomainSource::CertTransparency)
            .unwrap();
        assert_eq!(ct.len(), 1);
    }

    #[test]
    fn test_subdomain_table_get_unique() {
        let (_guard, path) = temp_db("sub_unique");
        let mut db = Database::open(&path).unwrap();
        let mut table = SubdomainTable::new(&mut db);

        let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        table
            .insert(
                "example.com",
                "www.example.com",
                ips.clone(),
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();
        table
            .insert(
                "example.com",
                "www.example.com",
                ips.clone(),
                SubdomainSource::CertTransparency,
            )
            .unwrap();
        table
            .insert(
                "example.com",
                "api.example.com",
                ips,
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();

        let unique = table.get_unique("example.com").unwrap();
        assert_eq!(unique.len(), 2);
        assert!(unique.contains(&"api.example.com".to_string()));
        assert!(unique.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn test_subdomain_table_get_all() {
        let (_guard, path) = temp_db("sub_all");
        let mut db = Database::open(&path).unwrap();
        let mut table = SubdomainTable::new(&mut db);

        let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        table
            .insert(
                "example.com",
                "a.example.com",
                ips.clone(),
                SubdomainSource::DnsBruteforce,
            )
            .unwrap();
        table
            .insert(
                "test.com",
                "b.test.com",
                ips,
                SubdomainSource::CertTransparency,
            )
            .unwrap();

        let all = table.get_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    // ==================== WhoisTable Tests ====================

    #[test]
    fn test_whois_table_insert() {
        let (_guard, path) = temp_db("whois_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = WhoisTable::new(&mut db);

        table
            .insert(
                "example.com",
                "MarkMonitor Inc.",
                1234567890,
                1734567890,
                vec!["ns1.example.com".to_string()],
            )
            .unwrap();

        let result = table.get("example.com", 86400).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_whois_table_get() {
        let (_guard, path) = temp_db("whois_get");
        let mut db = Database::open(&path).unwrap();
        let mut table = WhoisTable::new(&mut db);

        let nameservers = vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()];
        table
            .insert(
                "test.io",
                "GoDaddy",
                1600000000,
                1700000000,
                nameservers.clone(),
            )
            .unwrap();

        let result = table.get("test.io", 0).unwrap().unwrap();
        assert_eq!(result.domain, "test.io");
        assert_eq!(result.registrar, "GoDaddy");
        assert_eq!(result.nameservers.len(), 2);
    }

    #[test]
    fn test_whois_table_get_nonexistent() {
        let (_guard, path) = temp_db("whois_noexist");
        let mut db = Database::open(&path).unwrap();
        let table = WhoisTable::new(&mut db);

        let result = table.get("nonexistent.xyz", 86400).unwrap();
        assert!(result.is_none());
    }

    // ==================== TlsScanTable Tests ====================

    fn make_tls_record(host: &str, port: u16) -> TlsScanRecord {
        TlsScanRecord {
            host: host.to_string(),
            port,
            timestamp: 0,
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
        }
    }

    #[test]
    fn test_tls_scan_table_insert() {
        let (_guard, path) = temp_db("tls_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = TlsScanTable::new(&mut db);

        let record = make_tls_record("example.com", 443);
        table.insert(record).unwrap();

        let results = table.for_host("example.com");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_tls_scan_table_for_host() {
        let (_guard, path) = temp_db("tls_forhost");
        let mut db = Database::open(&path).unwrap();
        let mut table = TlsScanTable::new(&mut db);

        table.insert(make_tls_record("example.com", 443)).unwrap();
        table.insert(make_tls_record("example.com", 8443)).unwrap();
        table.insert(make_tls_record("other.com", 443)).unwrap();

        let example = table.for_host("example.com");
        assert_eq!(example.len(), 2);

        let other = table.for_host("other.com");
        assert_eq!(other.len(), 1);
    }

    #[test]
    fn test_tls_scan_table_iter() {
        let (_guard, path) = temp_db("tls_iter");
        let mut db = Database::open(&path).unwrap();
        let mut table = TlsScanTable::new(&mut db);

        table.insert(make_tls_record("a.com", 443)).unwrap();
        table.insert(make_tls_record("b.com", 443)).unwrap();
        table.insert(make_tls_record("c.com", 443)).unwrap();

        let count = table.iter().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_tls_scan_table_timestamp_auto() {
        let (_guard, path) = temp_db("tls_ts");
        let mut db = Database::open(&path).unwrap();
        let mut table = TlsScanTable::new(&mut db);

        let mut record = make_tls_record("test.com", 443);
        record.timestamp = 0;
        table.insert(record).unwrap();

        let results = table.for_host("test.com");
        assert_eq!(results.len(), 1);
        // Timestamp should be auto-set to non-zero
        assert!(results[0].timestamp > 0);
    }

    // ==================== DnsTable Tests ====================

    fn make_dns_record(domain: &str, record_type: DnsRecordType, value: &str) -> DnsRecordData {
        DnsRecordData {
            domain: domain.to_string(),
            record_type,
            value: value.to_string(),
            ttl: 300,
            timestamp: 1000,
        }
    }

    #[test]
    fn test_dns_table_insert() {
        let (_guard, path) = temp_db("dns_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = DnsTable::new(&mut db);

        let record = make_dns_record("example.com", DnsRecordType::A, "93.184.216.34");
        table.insert(record).unwrap();

        let count = table.iter().count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_dns_table_get_by_domain() {
        let (_guard, path) = temp_db("dns_bydomain");
        let mut db = Database::open(&path).unwrap();
        let mut table = DnsTable::new(&mut db);

        table
            .insert(make_dns_record("example.com", DnsRecordType::A, "1.2.3.4"))
            .unwrap();
        table
            .insert(make_dns_record(
                "example.com",
                DnsRecordType::MX,
                "mail.example.com",
            ))
            .unwrap();
        table
            .insert(make_dns_record("other.com", DnsRecordType::A, "5.6.7.8"))
            .unwrap();

        let results = table.get_by_domain("example.com").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_dns_table_iter() {
        let (_guard, path) = temp_db("dns_iter");
        let mut db = Database::open(&path).unwrap();
        let mut table = DnsTable::new(&mut db);

        table
            .insert(make_dns_record("a.com", DnsRecordType::A, "1.1.1.1"))
            .unwrap();
        table
            .insert(make_dns_record("b.com", DnsRecordType::AAAA, "::1"))
            .unwrap();
        table
            .insert(make_dns_record("c.com", DnsRecordType::NS, "ns1.c.com"))
            .unwrap();

        let count = table.iter().count();
        assert_eq!(count, 3);
    }

    // ==================== HttpTable Tests ====================

    fn make_http_record(host: &str, url: &str, status_code: u16) -> HttpHeadersRecord {
        HttpHeadersRecord {
            host: host.to_string(),
            url: url.to_string(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            http_version: "HTTP/1.1".to_string(),
            status_code,
            status_text: if status_code == 200 {
                "OK".to_string()
            } else {
                "Not Found".to_string()
            },
            server: Some("nginx".to_string()),
            body_size: 1024,
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            timestamp: 1000,
            tls: None,
        }
    }

    #[test]
    fn test_http_table_insert() {
        let (_guard, path) = temp_db("http_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = HttpTable::new(&mut db);

        let record = make_http_record("example.com", "https://example.com/", 200);
        table.insert(record).unwrap();

        let count = table.iter().count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_http_table_get_by_host() {
        let (_guard, path) = temp_db("http_byhost");
        let mut db = Database::open(&path).unwrap();
        let mut table = HttpTable::new(&mut db);

        table
            .insert(make_http_record("example.com", "https://example.com/", 200))
            .unwrap();
        table
            .insert(make_http_record(
                "example.com",
                "https://example.com/api",
                200,
            ))
            .unwrap();
        table
            .insert(make_http_record("other.com", "https://other.com/", 404))
            .unwrap();

        let results = table.get_by_host("example.com").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_http_table_iter() {
        let (_guard, path) = temp_db("http_iter");
        let mut db = Database::open(&path).unwrap();
        let mut table = HttpTable::new(&mut db);

        table
            .insert(make_http_record("a.com", "https://a.com/", 200))
            .unwrap();
        table
            .insert(make_http_record("b.com", "https://b.com/", 301))
            .unwrap();
        table
            .insert(make_http_record("c.com", "https://c.com/", 404))
            .unwrap();

        let count = table.iter().count();
        assert_eq!(count, 3);
    }

    // ==================== HostIntelTable Tests ====================

    fn make_host_record(ip: IpAddr) -> HostIntelRecord {
        HostIntelRecord {
            ip,
            os_family: Some("Linux".to_string()),
            confidence: 0.85,
            last_seen: 1000,
            services: vec![],
        }
    }

    #[test]
    fn test_host_intel_table_insert() {
        let (_guard, path) = temp_db("host_insert");
        let mut db = Database::open(&path).unwrap();
        let mut table = HostIntelTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let record = make_host_record(ip);
        table.insert(record).unwrap();

        let all = table.all().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_host_intel_table_get() {
        let (_guard, path) = temp_db("host_get");
        let mut db = Database::open(&path).unwrap();
        let mut table = HostIntelTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        table.insert(make_host_record(ip)).unwrap();

        let result = table.get(ip).unwrap();
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.ip, ip);
        assert_eq!(record.os_family, Some("Linux".to_string()));
    }

    #[test]
    fn test_host_intel_table_get_nonexistent() {
        let (_guard, path) = temp_db("host_noexist");
        let mut db = Database::open(&path).unwrap();
        let mut table = HostIntelTable::new(&mut db);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let result = table.get(ip).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_host_intel_table_all() {
        let (_guard, path) = temp_db("host_all");
        let mut db = Database::open(&path).unwrap();
        let mut table = HostIntelTable::new(&mut db);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        table.insert(make_host_record(ip1)).unwrap();
        table.insert(make_host_record(ip2)).unwrap();
        table.insert(make_host_record(ip3)).unwrap();

        let all = table.all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_host_intel_table_ipv6() {
        let (_guard, path) = temp_db("host_ipv6");
        let mut db = Database::open(&path).unwrap();
        let mut table = HostIntelTable::new(&mut db);

        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        table.insert(make_host_record(ip)).unwrap();

        let result = table.get(ip).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().ip, ip);
    }
}
