use std::io;
use std::net::IpAddr;
use std::path::Path;

use crate::storage::schema::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PortStatus, SubdomainSource, TlsScanRecord,
    WhoisRecord,
};
use crate::storage::store::Database;
use crate::storage::tables::{
    DnsTable, HostIntelTable, HttpTable, PortScanTable, SubdomainTable, TlsScanTable, WhoisTable,
};

pub struct RedDb {
    store: Database,
}

impl RedDb {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self {
            store: Database::open(path)?,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn smoke_test() {
        struct FileGuard {
            path: std::path::PathBuf,
        }

        impl Drop for FileGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        let path = std::env::temp_dir().join(format!("rb_reddb_smoke_{}.db", std::process::id()));
        let guard = FileGuard { path: path.clone() };
        let _ = std::fs::remove_file(&guard.path);
        let mut db = RedDb::open(&guard.path).unwrap();

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

        let mut reopened = RedDb::open(&guard.path).unwrap();
        assert_eq!(reopened.get_open_ports(ip).unwrap(), vec![443]);
    }
}
