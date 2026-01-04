//! Database storage for security scan results
//!
//! Provides persistent storage for port scans, hosts, subdomains, WHOIS records,
//! TLS scans, DNS records, HTTP headers, proxy data, threat intelligence, and more.

mod encryption;
mod flush;
mod open;
mod tests;

use std::net::IpAddr;
use std::path::PathBuf;

use crate::storage::layout::SegmentKind;
use crate::storage::records::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, IocRecord, MitreAttackRecord,
    PlaybookRunRecord, PortScanRecord, ProxyConnectionRecord, ProxyHttpRequestRecord,
    ProxyHttpResponseRecord, ProxyWebSocketRecord, SessionRecord, SubdomainRecord, SubdomainSource,
    TlsScanRecord, VulnerabilityRecord, WhoisRecord,
};
use crate::storage::segments::actions::{ActionRecord, ActionSegment, ActionType, Target};
use crate::storage::segments::actions::{ActionTrace, TraceSegment};
use crate::storage::segments::dns::DnsSegment;
use crate::storage::segments::hosts::HostSegment;
use crate::storage::segments::http::HttpSegment;
use crate::storage::segments::iocs::IocSegment;
use crate::storage::segments::loot::{LootCategory, LootEntry, LootSegment};
use crate::storage::segments::mitre::MitreSegment;
use crate::storage::segments::playbooks::PlaybookSegment;
use crate::storage::segments::ports::PortSegment;
use crate::storage::segments::proxy::ProxySegment;
use crate::storage::segments::sessions::SessionSegment;
use crate::storage::segments::subdomains::SubdomainSegment;
use crate::storage::segments::tls::TlsSegment;
use crate::storage::segments::vuln::VulnSegment;
use crate::storage::segments::whois::WhoisSegment;

pub use encryption::EncryptionState;

/// Security scan database with 16 segment types
#[derive(Debug)]
pub struct Database {
    pub(crate) path: PathBuf,
    pub(crate) ports: PortSegment,
    pub(crate) subdomains: SubdomainSegment,
    pub(crate) whois: WhoisSegment,
    pub(crate) tls: TlsSegment,
    pub(crate) dns: DnsSegment,
    pub(crate) http: HttpSegment,
    pub(crate) hosts: HostSegment,
    pub(crate) proxy: ProxySegment,
    pub(crate) mitre: MitreSegment,
    pub(crate) iocs: IocSegment,
    pub(crate) vulns: VulnSegment,
    pub(crate) sessions: SessionSegment,
    pub(crate) playbooks: PlaybookSegment,
    pub(crate) actions: ActionSegment,
    pub(crate) traces: TraceSegment,
    pub(crate) loot: LootSegment,
    pub(crate) dirty: bool,
    /// Encryption state - Some = encrypted database
    #[allow(dead_code)]
    pub(crate) encryption: Option<EncryptionState>,
}

impl Database {
    /// Create a new empty database at the given path (not persisted until flush)
    pub(crate) fn new_empty(path: PathBuf) -> Self {
        Self {
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
            encryption: None,
        }
    }

    // ==================== Port Methods ====================

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

    // ==================== Host Methods ====================

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

    // ==================== Subdomain Methods ====================

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

    // ==================== WHOIS Methods ====================

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

    pub fn whois_records(&self) -> impl Iterator<Item = WhoisRecord> + '_ {
        self.whois.iter()
    }

    // ==================== TLS Methods ====================

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

    // ==================== DNS Methods ====================

    pub fn insert_dns(&mut self, record: DnsRecordData) {
        self.dns.insert(record);
        self.dirty = true;
    }

    pub fn dns_records(&mut self) -> impl Iterator<Item = DnsRecordData> + '_ {
        self.dns.iter_mut()
    }

    pub fn dns_for_domain(&mut self, domain: &str) -> Vec<DnsRecordData> {
        self.dns.records_for_domain(domain)
    }

    // ==================== HTTP Methods ====================

    pub fn insert_http(&mut self, record: HttpHeadersRecord) {
        self.http.insert(record);
        self.dirty = true;
    }

    pub fn http_records(&mut self) -> impl Iterator<Item = HttpHeadersRecord> + '_ {
        self.http.iter()
    }

    pub fn http_for_host(&mut self, host: &str) -> Vec<HttpHeadersRecord> {
        self.http.records_for_host(host)
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

    // ==================== Action Methods ====================

    pub fn insert_action(&mut self, record: ActionRecord) {
        self.actions.add(record);
        self.dirty = true;
    }

    pub fn action_by_id(&self, id: [u8; 16]) -> Option<&ActionRecord> {
        self.actions.by_id(&id)
    }

    pub fn actions_by_target(&self, target: &Target) -> Vec<&ActionRecord> {
        self.actions.by_target(target)
    }

    pub fn actions_by_type(&self, action_type: ActionType) -> Vec<&ActionRecord> {
        self.actions.by_type(action_type)
    }

    pub fn successful_actions(&self) -> Vec<&ActionRecord> {
        self.actions.successes()
    }

    pub fn failed_actions(&self) -> Vec<&ActionRecord> {
        self.actions.failures()
    }

    pub fn all_actions(&self) -> &[ActionRecord] {
        self.actions.all()
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    // ==================== Trace Methods ====================

    pub fn insert_trace(&mut self, trace: ActionTrace) {
        self.traces.add(trace);
        self.dirty = true;
    }

    pub fn trace_for_action(&self, action_id: [u8; 16]) -> Option<&ActionTrace> {
        self.traces.for_action(&action_id)
    }

    pub fn all_traces(&self) -> &[ActionTrace] {
        self.traces.all()
    }

    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }

    // ==================== Loot Methods ====================

    /// Insert or update a loot entry by key
    pub fn insert_loot(&mut self, entry: LootEntry) {
        self.loot.insert(entry);
        self.dirty = true;
    }

    /// Get a loot entry by key
    pub fn loot_by_key(&mut self, key: &str) -> Option<LootEntry> {
        self.loot.get(key)
    }

    /// Get all loot entries of a specific category
    pub fn loot_by_category(&mut self, category: LootCategory) -> Vec<LootEntry> {
        self.loot.by_category(category)
    }

    /// Get all loot entries
    pub fn all_loot(&mut self) -> Vec<LootEntry> {
        self.loot.all()
    }

    /// Get the number of loot entries
    pub fn loot_count(&self) -> usize {
        self.loot.len()
    }

    /// Delete a loot entry by key
    pub fn delete_loot(&mut self, key: &str) -> Option<LootEntry> {
        let entry = self.loot.delete(key);
        if entry.is_some() {
            self.dirty = true;
        }
        entry
    }

    // ==================== Metadata Methods ====================

    pub(crate) fn segment_metadata(&self, kind: SegmentKind) -> Vec<(String, String)> {
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
            SegmentKind::Actions => self.actions.len(),
            SegmentKind::Traces => self.traces.len(),
            SegmentKind::Loot => self.loot.len(),
        };
        pairs.push(("record_count".to_string(), record_count.to_string()));
        pairs
    }

    pub(crate) fn segment_label(kind: SegmentKind) -> &'static str {
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
            SegmentKind::Actions => "actions",
            SegmentKind::Traces => "traces",
            SegmentKind::Loot => "loot",
        }
    }
}
