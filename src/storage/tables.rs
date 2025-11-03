use std::io;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::schema::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PortScanRecord, PortStatus, SubdomainRecord,
    SubdomainSource, TlsCertRecord, WhoisRecord,
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

pub struct TlsCertTable<'a> {
    db: &'a mut Database,
}

impl<'a> TlsCertTable<'a> {
    pub fn new(db: &'a mut Database) -> Self {
        Self { db }
    }

    pub fn insert(
        &mut self,
        domain: &str,
        issuer: &str,
        subject: &str,
        not_before: u32,
        not_after: u32,
        sans: Vec<String>,
        self_signed: bool,
    ) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        self.db.insert_tls(
            domain,
            issuer,
            subject,
            not_before,
            not_after,
            sans,
            self_signed,
            timestamp,
        );
        Ok(())
    }

    pub fn get(&self, domain: &str) -> io::Result<Option<TlsCertRecord>> {
        Ok(self.db.get_tls(domain))
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

    pub fn get(&self, ip: IpAddr) -> io::Result<Option<HostIntelRecord>> {
        Ok(self.db.host_record(ip))
    }

    pub fn all(&self) -> io::Result<Vec<HostIntelRecord>> {
        Ok(self.db.all_hosts())
    }
}
