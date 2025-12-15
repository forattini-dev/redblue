//! IOC (Indicators of Compromise) Extraction Engine
//!
//! Extracts Indicators of Compromise from various scan data sources:
//! - Port scans (target IPs)
//! - DNS queries (domains, resolved IPs, MX hosts)
//! - TLS certificates (SANs, issuer domains, fingerprints)
//! - Subdomains (discovered subdomains)
//! - WHOIS lookups (registrant emails, nameservers)
//! - HTTP responses (URLs, redirect targets, CSP domains)
//!
//! Each IOC can be linked to relevant MITRE ATT&CK techniques.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Type of Indicator of Compromise
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IocType {
    /// IPv4 address
    IPv4,
    /// IPv6 address
    IPv6,
    /// Domain name
    Domain,
    /// Full URL
    Url,
    /// Email address
    Email,
    /// MD5 hash
    HashMD5,
    /// SHA1 hash
    HashSHA1,
    /// SHA256 hash
    HashSHA256,
    /// Certificate fingerprint (SHA256)
    Certificate,
    /// JA3 fingerprint (TLS client fingerprint)
    JA3,
    /// JA3S fingerprint (TLS server fingerprint)
    JA3S,
    /// User agent string
    UserAgent,
    /// ASN (Autonomous System Number)
    ASN,
    /// CIDR range
    CIDR,
    /// File name
    FileName,
    /// File path
    FilePath,
    /// Registry key (Windows)
    RegistryKey,
    /// Mutex name
    Mutex,
    /// Named pipe
    NamedPipe,
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IocType::IPv4 => write!(f, "ipv4"),
            IocType::IPv6 => write!(f, "ipv6"),
            IocType::Domain => write!(f, "domain"),
            IocType::Url => write!(f, "url"),
            IocType::Email => write!(f, "email"),
            IocType::HashMD5 => write!(f, "md5"),
            IocType::HashSHA1 => write!(f, "sha1"),
            IocType::HashSHA256 => write!(f, "sha256"),
            IocType::Certificate => write!(f, "certificate"),
            IocType::JA3 => write!(f, "ja3"),
            IocType::JA3S => write!(f, "ja3s"),
            IocType::UserAgent => write!(f, "user-agent"),
            IocType::ASN => write!(f, "asn"),
            IocType::CIDR => write!(f, "cidr"),
            IocType::FileName => write!(f, "filename"),
            IocType::FilePath => write!(f, "filepath"),
            IocType::RegistryKey => write!(f, "registry"),
            IocType::Mutex => write!(f, "mutex"),
            IocType::NamedPipe => write!(f, "namedpipe"),
        }
    }
}

impl IocType {
    /// Get STIX pattern prefix for this IOC type
    pub fn stix_pattern_prefix(&self) -> &'static str {
        match self {
            IocType::IPv4 => "ipv4-addr:value",
            IocType::IPv6 => "ipv6-addr:value",
            IocType::Domain => "domain-name:value",
            IocType::Url => "url:value",
            IocType::Email => "email-addr:value",
            IocType::HashMD5 => "file:hashes.MD5",
            IocType::HashSHA1 => "file:hashes.SHA-1",
            IocType::HashSHA256 => "file:hashes.SHA-256",
            IocType::Certificate => "x509-certificate:hashes.SHA-256",
            IocType::JA3 => "x509-certificate:extensions.'x-ja3-fingerprint'",
            IocType::JA3S => "x509-certificate:extensions.'x-ja3s-fingerprint'",
            IocType::UserAgent => "http-request-ext:request_header.'User-Agent'",
            IocType::ASN => "autonomous-system:number",
            IocType::CIDR => "ipv4-addr:value",
            IocType::FileName => "file:name",
            IocType::FilePath => "file:path",
            IocType::RegistryKey => "windows-registry-key:key",
            IocType::Mutex => "mutex:name",
            IocType::NamedPipe => "windows-pebinary-ext:sections[0].name",
        }
    }
}

/// Source of the IOC extraction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IocSource {
    /// Extracted from port scan results
    PortScan,
    /// Extracted from DNS query results
    DnsQuery,
    /// Extracted from TLS certificate
    TlsCertificate,
    /// Extracted from subdomain enumeration
    SubdomainEnum,
    /// Extracted from WHOIS lookup
    WhoisLookup,
    /// Extracted from HTTP response
    HttpResponse,
    /// Extracted from HTTP headers
    HttpHeaders,
    /// Extracted from HTML content
    HtmlContent,
    /// Extracted from JavaScript code
    JavaScript,
    /// Manually added
    Manual,
    /// Imported from external source
    External(String),
}

impl fmt::Display for IocSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IocSource::PortScan => write!(f, "port_scan"),
            IocSource::DnsQuery => write!(f, "dns_query"),
            IocSource::TlsCertificate => write!(f, "tls_cert"),
            IocSource::SubdomainEnum => write!(f, "subdomain_enum"),
            IocSource::WhoisLookup => write!(f, "whois"),
            IocSource::HttpResponse => write!(f, "http_response"),
            IocSource::HttpHeaders => write!(f, "http_headers"),
            IocSource::HtmlContent => write!(f, "html_content"),
            IocSource::JavaScript => write!(f, "javascript"),
            IocSource::Manual => write!(f, "manual"),
            IocSource::External(name) => write!(f, "external:{}", name),
        }
    }
}

/// Confidence level for IOC accuracy
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IocConfidence {
    /// Low confidence (0-33)
    Low,
    /// Medium confidence (34-66)
    Medium,
    /// High confidence (67-100)
    High,
}

impl IocConfidence {
    /// Create from numeric score (0-100)
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=33 => IocConfidence::Low,
            34..=66 => IocConfidence::Medium,
            _ => IocConfidence::High,
        }
    }

    /// Convert to numeric score
    pub fn to_score(&self) -> u8 {
        match self {
            IocConfidence::Low => 25,
            IocConfidence::Medium => 50,
            IocConfidence::High => 85,
        }
    }
}

impl fmt::Display for IocConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IocConfidence::Low => write!(f, "low"),
            IocConfidence::Medium => write!(f, "medium"),
            IocConfidence::High => write!(f, "high"),
        }
    }
}

/// An Indicator of Compromise
#[derive(Debug, Clone)]
pub struct Ioc {
    /// Type of IOC
    pub ioc_type: IocType,
    /// The actual value (IP, domain, hash, etc.)
    pub value: String,
    /// Where this IOC was extracted from
    pub source: IocSource,
    /// Confidence level
    pub confidence: IocConfidence,
    /// Numeric confidence score (0-100)
    pub confidence_score: u8,
    /// Associated MITRE ATT&CK technique IDs
    pub mitre_techniques: Vec<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Target this IOC was found during scan of
    pub target: String,
    /// First time this IOC was seen (Unix timestamp)
    pub first_seen: u64,
    /// Last time this IOC was seen (Unix timestamp)
    pub last_seen: u64,
    /// Additional context/notes
    pub context: Option<String>,
    /// Related IOCs (by value)
    pub related: Vec<String>,
}

impl Ioc {
    /// Create a new IOC
    pub fn new(
        ioc_type: IocType,
        value: impl Into<String>,
        source: IocSource,
        confidence_score: u8,
        target: impl Into<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ioc_type,
            value: value.into(),
            source,
            confidence: IocConfidence::from_score(confidence_score),
            confidence_score,
            mitre_techniques: Vec::new(),
            tags: Vec::new(),
            target: target.into(),
            first_seen: now,
            last_seen: now,
            context: None,
            related: Vec::new(),
        }
    }

    /// Add a MITRE ATT&CK technique ID
    pub fn with_technique(mut self, technique_id: impl Into<String>) -> Self {
        self.mitre_techniques.push(technique_id.into());
        self
    }

    /// Add multiple MITRE ATT&CK technique IDs
    pub fn with_techniques(mut self, techniques: &[&str]) -> Self {
        self.mitre_techniques
            .extend(techniques.iter().map(|s| s.to_string()));
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add context information
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Add related IOC
    pub fn with_related(mut self, related: impl Into<String>) -> Self {
        self.related.push(related.into());
        self
    }

    /// Generate STIX 2.1 pattern for this IOC
    pub fn to_stix_pattern(&self) -> String {
        format!(
            "[{} = '{}']",
            self.ioc_type.stix_pattern_prefix(),
            self.value.replace('\'', "\\'")
        )
    }

    /// Unique key for deduplication (type + value)
    pub fn dedup_key(&self) -> String {
        format!("{}:{}", self.ioc_type, self.value)
    }
}

/// Collection of IOCs with deduplication
#[derive(Debug, Default)]
pub struct IocCollection {
    /// IOCs indexed by dedup key
    iocs: HashMap<String, Ioc>,
    /// Index by type
    by_type: HashMap<IocType, Vec<String>>,
    /// Index by target
    by_target: HashMap<String, Vec<String>>,
    /// Index by MITRE technique
    by_technique: HashMap<String, Vec<String>>,
}

impl IocCollection {
    /// Create new empty collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an IOC to the collection (deduplicates)
    pub fn add(&mut self, ioc: Ioc) {
        let key = ioc.dedup_key();

        // Update indexes
        self.by_type
            .entry(ioc.ioc_type.clone())
            .or_default()
            .push(key.clone());

        self.by_target
            .entry(ioc.target.clone())
            .or_default()
            .push(key.clone());

        for tech in &ioc.mitre_techniques {
            self.by_technique
                .entry(tech.clone())
                .or_default()
                .push(key.clone());
        }

        // Merge or insert
        if let Some(existing) = self.iocs.get_mut(&key) {
            // Update last_seen and merge data
            existing.last_seen = ioc.last_seen;

            // Merge techniques
            for tech in ioc.mitre_techniques {
                if !existing.mitre_techniques.contains(&tech) {
                    existing.mitre_techniques.push(tech);
                }
            }

            // Merge tags
            for tag in ioc.tags {
                if !existing.tags.contains(&tag) {
                    existing.tags.push(tag);
                }
            }

            // Merge related
            for related in ioc.related {
                if !existing.related.contains(&related) {
                    existing.related.push(related);
                }
            }

            // Keep higher confidence
            if ioc.confidence_score > existing.confidence_score {
                existing.confidence_score = ioc.confidence_score;
                existing.confidence = ioc.confidence;
            }
        } else {
            self.iocs.insert(key, ioc);
        }
    }

    /// Get all IOCs
    pub fn all(&self) -> Vec<&Ioc> {
        self.iocs.values().collect()
    }

    /// Get IOCs by type
    pub fn by_type(&self, ioc_type: &IocType) -> Vec<&Ioc> {
        self.by_type
            .get(ioc_type)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.iocs.get(k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get IOCs by target
    pub fn by_target(&self, target: &str) -> Vec<&Ioc> {
        self.by_target
            .get(target)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.iocs.get(k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get IOCs by MITRE technique
    pub fn by_technique(&self, technique_id: &str) -> Vec<&Ioc> {
        self.by_technique
            .get(technique_id)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.iocs.get(k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Search IOCs by value (substring match)
    pub fn search(&self, query: &str) -> Vec<&Ioc> {
        let query_lower = query.to_lowercase();
        self.iocs
            .values()
            .filter(|ioc| ioc.value.to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Get total count
    pub fn len(&self) -> usize {
        self.iocs.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    /// Get count by type
    pub fn count_by_type(&self) -> HashMap<IocType, usize> {
        let mut counts = HashMap::new();
        for ioc in self.iocs.values() {
            *counts.entry(ioc.ioc_type.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Get count by confidence
    pub fn count_by_confidence(&self) -> HashMap<IocConfidence, usize> {
        let mut counts = HashMap::new();
        for ioc in self.iocs.values() {
            *counts.entry(ioc.confidence).or_insert(0) += 1;
        }
        counts
    }

    /// Export to JSON format
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n  \"iocs\": [\n");
        let iocs: Vec<_> = self.iocs.values().collect();

        for (i, ioc) in iocs.iter().enumerate() {
            json.push_str(&format!(
                "    {{\n      \"type\": \"{}\",\n      \"value\": \"{}\",\n      \"source\": \"{}\",\n      \"confidence\": {},\n      \"target\": \"{}\",\n      \"mitre_techniques\": [{}],\n      \"tags\": [{}],\n      \"first_seen\": {},\n      \"last_seen\": {}\n    }}",
                ioc.ioc_type,
                ioc.value.replace('\\', "\\\\").replace('"', "\\\""),
                ioc.source,
                ioc.confidence_score,
                ioc.target.replace('\\', "\\\\").replace('"', "\\\""),
                ioc.mitre_techniques.iter().map(|t| format!("\"{}\"", t)).collect::<Vec<_>>().join(", "),
                ioc.tags.iter().map(|t| format!("\"{}\"", t)).collect::<Vec<_>>().join(", "),
                ioc.first_seen,
                ioc.last_seen,
            ));
            if i < iocs.len() - 1 {
                json.push_str(",\n");
            } else {
                json.push('\n');
            }
        }

        json.push_str("  ],\n");
        json.push_str(&format!("  \"total\": {},\n", self.len()));
        json.push_str(&format!(
            "  \"types\": {{\n{}\n  }}\n",
            self.count_by_type()
                .iter()
                .map(|(t, c)| format!("    \"{}\": {}", t, c))
                .collect::<Vec<_>>()
                .join(",\n")
        ));
        json.push('}');

        json
    }

    /// Export to CSV format
    pub fn to_csv(&self) -> String {
        let mut csv = String::from("type,value,source,confidence,target,mitre_techniques,tags,first_seen,last_seen\n");

        for ioc in self.iocs.values() {
            csv.push_str(&format!(
                "{},\"{}\",{},{},{},\"{}\",\"{}\",{},{}\n",
                ioc.ioc_type,
                ioc.value.replace('"', "\"\""),
                ioc.source,
                ioc.confidence_score,
                ioc.target,
                ioc.mitre_techniques.join(";"),
                ioc.tags.join(";"),
                ioc.first_seen,
                ioc.last_seen,
            ));
        }

        csv
    }
}

/// IOC Extractor - extracts IOCs from various data sources
pub struct IocExtractor {
    target: String,
}

impl IocExtractor {
    /// Create a new extractor for a target
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
        }
    }

    /// Extract IOCs from port scan results
    ///
    /// Input: target IP/hostname and list of open ports
    pub fn extract_from_port_scan(
        &self,
        target_ip: &str,
        open_ports: &[u16],
    ) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // Extract target IP as IOC
        if let Ok(ip) = target_ip.parse::<IpAddr>() {
            let ioc_type = match ip {
                IpAddr::V4(_) => IocType::IPv4,
                IpAddr::V6(_) => IocType::IPv6,
            };

            let mut ioc = Ioc::new(
                ioc_type,
                target_ip,
                IocSource::PortScan,
                80,
                &self.target,
            );

            // Add techniques based on open ports
            let techniques = self.ports_to_techniques(open_ports);
            for tech in techniques {
                ioc = ioc.with_technique(tech);
            }

            // Add port tags
            for port in open_ports {
                ioc = ioc.with_tag(format!("port:{}", port));
            }

            ioc = ioc.with_context(format!(
                "Scanned host with {} open ports",
                open_ports.len()
            ));

            iocs.push(ioc);
        }

        iocs
    }

    /// Extract IOCs from DNS query results
    ///
    /// Input: domain and resolved records
    pub fn extract_from_dns(
        &self,
        domain: &str,
        a_records: &[Ipv4Addr],
        aaaa_records: &[Ipv6Addr],
        mx_records: &[String],
        ns_records: &[String],
        cname_records: &[String],
    ) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // Domain itself
        iocs.push(
            Ioc::new(
                IocType::Domain,
                domain,
                IocSource::DnsQuery,
                90,
                &self.target,
            )
            .with_technique("T1071.004") // DNS protocol
            .with_tag("primary_domain")
        );

        // A records (IPv4)
        for ip in a_records {
            iocs.push(
                Ioc::new(
                    IocType::IPv4,
                    ip.to_string(),
                    IocSource::DnsQuery,
                    85,
                    &self.target,
                )
                .with_technique("T1071.004")
                .with_tag("dns_resolved")
                .with_related(domain)
            );
        }

        // AAAA records (IPv6)
        for ip in aaaa_records {
            iocs.push(
                Ioc::new(
                    IocType::IPv6,
                    ip.to_string(),
                    IocSource::DnsQuery,
                    85,
                    &self.target,
                )
                .with_technique("T1071.004")
                .with_tag("dns_resolved")
                .with_related(domain)
            );
        }

        // MX records
        for mx in mx_records {
            // Extract hostname from MX record (strip priority if present)
            let mx_host = mx.split_whitespace().last().unwrap_or(mx);
            iocs.push(
                Ioc::new(
                    IocType::Domain,
                    mx_host.trim_end_matches('.'),
                    IocSource::DnsQuery,
                    80,
                    &self.target,
                )
                .with_technique("T1071.003") // SMTP protocol
                .with_tag("mail_server")
                .with_related(domain)
            );
        }

        // NS records
        for ns in ns_records {
            let ns_host = ns.trim_end_matches('.');
            iocs.push(
                Ioc::new(
                    IocType::Domain,
                    ns_host,
                    IocSource::DnsQuery,
                    85,
                    &self.target,
                )
                .with_technique("T1071.004")
                .with_tag("nameserver")
                .with_related(domain)
            );
        }

        // CNAME records
        for cname in cname_records {
            let cname_host = cname.trim_end_matches('.');
            iocs.push(
                Ioc::new(
                    IocType::Domain,
                    cname_host,
                    IocSource::DnsQuery,
                    75,
                    &self.target,
                )
                .with_technique("T1071.004")
                .with_tag("cname_target")
                .with_related(domain)
            );
        }

        iocs
    }

    /// Extract IOCs from TLS certificate
    ///
    /// Input: certificate details
    pub fn extract_from_tls(
        &self,
        common_name: &str,
        sans: &[String],
        issuer: &str,
        fingerprint_sha256: &str,
        serial: &str,
    ) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // Common Name
        if !common_name.is_empty() && !common_name.contains('*') {
            iocs.push(
                Ioc::new(
                    IocType::Domain,
                    common_name,
                    IocSource::TlsCertificate,
                    90,
                    &self.target,
                )
                .with_technique("T1573.002") // Encrypted channel
                .with_tag("tls_cn")
                .with_context(format!("TLS certificate CN, issuer: {}", issuer))
            );
        }

        // Subject Alternative Names
        for san in sans {
            // Skip wildcards
            if san.starts_with('*') {
                continue;
            }

            // Check if IP or domain
            if let Ok(ip) = san.parse::<IpAddr>() {
                let ioc_type = match ip {
                    IpAddr::V4(_) => IocType::IPv4,
                    IpAddr::V6(_) => IocType::IPv6,
                };
                iocs.push(
                    Ioc::new(
                        ioc_type,
                        san,
                        IocSource::TlsCertificate,
                        85,
                        &self.target,
                    )
                    .with_technique("T1573.002")
                    .with_tag("tls_san")
                );
            } else {
                iocs.push(
                    Ioc::new(
                        IocType::Domain,
                        san,
                        IocSource::TlsCertificate,
                        85,
                        &self.target,
                    )
                    .with_technique("T1573.002")
                    .with_tag("tls_san")
                );
            }
        }

        // Certificate fingerprint
        if !fingerprint_sha256.is_empty() {
            iocs.push(
                Ioc::new(
                    IocType::Certificate,
                    fingerprint_sha256,
                    IocSource::TlsCertificate,
                    95,
                    &self.target,
                )
                .with_technique("T1573.002")
                .with_tag("cert_fingerprint")
                .with_context(format!("Serial: {}", serial))
            );
        }

        // Issuer domain (extract from issuer CN if present)
        if let Some(issuer_cn) = Self::extract_cn_from_issuer(issuer) {
            // Only add if it looks like a domain
            if issuer_cn.contains('.') && !issuer_cn.contains(' ') {
                iocs.push(
                    Ioc::new(
                        IocType::Domain,
                        &issuer_cn,
                        IocSource::TlsCertificate,
                        70,
                        &self.target,
                    )
                    .with_technique("T1573.002")
                    .with_tag("ca_domain")
                );
            }
        }

        iocs
    }

    /// Extract IOCs from discovered subdomains
    pub fn extract_from_subdomains(&self, subdomains: &[String]) -> Vec<Ioc> {
        subdomains
            .iter()
            .map(|subdomain| {
                Ioc::new(
                    IocType::Domain,
                    subdomain,
                    IocSource::SubdomainEnum,
                    75,
                    &self.target,
                )
                .with_technique("T1596") // Search open technical databases
                .with_tag("subdomain")
            })
            .collect()
    }

    /// Extract IOCs from WHOIS lookup
    pub fn extract_from_whois(
        &self,
        domain: &str,
        registrant_email: Option<&str>,
        admin_email: Option<&str>,
        tech_email: Option<&str>,
        nameservers: &[String],
        registrar: Option<&str>,
    ) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // Registrant email
        if let Some(email) = registrant_email {
            if !email.is_empty() && email.contains('@') && !Self::is_privacy_protected(email) {
                iocs.push(
                    Ioc::new(
                        IocType::Email,
                        email,
                        IocSource::WhoisLookup,
                        80,
                        &self.target,
                    )
                    .with_technique("T1589.002") // Gather victim identity info: Email
                    .with_tag("registrant_email")
                    .with_related(domain)
                );
            }
        }

        // Admin email
        if let Some(email) = admin_email {
            if !email.is_empty()
                && email.contains('@')
                && !Self::is_privacy_protected(email)
                && Some(email) != registrant_email
            {
                iocs.push(
                    Ioc::new(
                        IocType::Email,
                        email,
                        IocSource::WhoisLookup,
                        75,
                        &self.target,
                    )
                    .with_technique("T1589.002")
                    .with_tag("admin_email")
                    .with_related(domain)
                );
            }
        }

        // Tech email
        if let Some(email) = tech_email {
            if !email.is_empty()
                && email.contains('@')
                && !Self::is_privacy_protected(email)
                && Some(email) != registrant_email
                && Some(email) != admin_email
            {
                iocs.push(
                    Ioc::new(
                        IocType::Email,
                        email,
                        IocSource::WhoisLookup,
                        70,
                        &self.target,
                    )
                    .with_technique("T1589.002")
                    .with_tag("tech_email")
                    .with_related(domain)
                );
            }
        }

        // Nameservers
        for ns in nameservers {
            let ns_clean = ns.trim_end_matches('.');
            iocs.push(
                Ioc::new(
                    IocType::Domain,
                    ns_clean,
                    IocSource::WhoisLookup,
                    80,
                    &self.target,
                )
                .with_technique("T1071.004")
                .with_tag("whois_nameserver")
                .with_related(domain)
            );
        }

        // Registrar domain (if extractable)
        if let Some(registrar_domain) = registrar.and_then(Self::extract_registrar_domain) {
            iocs.push(
                Ioc::new(
                    IocType::Domain,
                    &registrar_domain,
                    IocSource::WhoisLookup,
                    60,
                    &self.target,
                )
                .with_tag("registrar")
                .with_related(domain)
            );
        }

        iocs
    }

    /// Extract IOCs from HTTP response
    pub fn extract_from_http(
        &self,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
    ) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // The URL itself
        iocs.push(
            Ioc::new(
                IocType::Url,
                url,
                IocSource::HttpResponse,
                85,
                &self.target,
            )
            .with_technique("T1071.001") // Web protocols
            .with_tag("scanned_url")
        );

        // Extract from headers
        iocs.extend(self.extract_from_headers(headers));

        // Extract from body if provided
        if let Some(body) = body {
            iocs.extend(self.extract_from_html(body));
        }

        iocs
    }

    /// Extract IOCs from HTTP headers
    pub fn extract_from_headers(&self, headers: &HashMap<String, String>) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // Location header (redirects)
        if let Some(location) = headers.get("location").or_else(|| headers.get("Location")) {
            if location.starts_with("http://") || location.starts_with("https://") {
                iocs.push(
                    Ioc::new(
                        IocType::Url,
                        location,
                        IocSource::HttpHeaders,
                        80,
                        &self.target,
                    )
                    .with_technique("T1071.001")
                    .with_tag("redirect_target")
                );
            }
        }

        // Content-Security-Policy - extract domains
        if let Some(csp) = headers
            .get("content-security-policy")
            .or_else(|| headers.get("Content-Security-Policy"))
        {
            for domain in Self::extract_domains_from_csp(csp) {
                iocs.push(
                    Ioc::new(
                        IocType::Domain,
                        &domain,
                        IocSource::HttpHeaders,
                        70,
                        &self.target,
                    )
                    .with_tag("csp_domain")
                );
            }
        }

        // X-Forwarded-For - proxy chain IPs
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .or_else(|| headers.get("X-Forwarded-For"))
        {
            for ip_str in xff.split(',') {
                let ip_str = ip_str.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let ioc_type = match ip {
                        IpAddr::V4(_) => IocType::IPv4,
                        IpAddr::V6(_) => IocType::IPv6,
                    };
                    iocs.push(
                        Ioc::new(
                            ioc_type,
                            ip_str,
                            IocSource::HttpHeaders,
                            65,
                            &self.target,
                        )
                        .with_tag("proxy_chain")
                    );
                }
            }
        }

        // Set-Cookie - extract domains from cookie
        for (key, value) in headers {
            if key.to_lowercase() == "set-cookie" {
                if let Some(domain) = Self::extract_cookie_domain(value) {
                    iocs.push(
                        Ioc::new(
                            IocType::Domain,
                            &domain,
                            IocSource::HttpHeaders,
                            70,
                            &self.target,
                        )
                        .with_tag("cookie_domain")
                    );
                }
            }
        }

        iocs
    }

    /// Extract IOCs from HTML content
    pub fn extract_from_html(&self, html: &str) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        // Extract URLs from href and src attributes
        for url in Self::extract_urls_from_html(html) {
            // Only external URLs
            if url.starts_with("http://") || url.starts_with("https://") {
                iocs.push(
                    Ioc::new(
                        IocType::Url,
                        &url,
                        IocSource::HtmlContent,
                        65,
                        &self.target,
                    )
                    .with_technique("T1071.001")
                    .with_tag("html_link")
                );
            }
        }

        // Extract emails
        for email in Self::extract_emails_from_text(html) {
            if !Self::is_privacy_protected(&email) {
                iocs.push(
                    Ioc::new(
                        IocType::Email,
                        &email,
                        IocSource::HtmlContent,
                        60,
                        &self.target,
                    )
                    .with_technique("T1589.002")
                    .with_tag("html_email")
                );
            }
        }

        iocs
    }

    // Helper methods

    fn ports_to_techniques(&self, ports: &[u16]) -> Vec<&'static str> {
        let mut techniques = Vec::new();

        for port in ports {
            match port {
                21 => techniques.push("T1071.002"), // FTP
                22 => {
                    techniques.push("T1021.004"); // SSH
                    techniques.push("T1110.001"); // Brute force
                }
                23 => techniques.push("T1021"), // Telnet
                25 | 465 | 587 => techniques.push("T1071.003"), // SMTP
                53 => techniques.push("T1071.004"), // DNS
                80 | 443 | 8080 | 8443 => techniques.push("T1071.001"), // HTTP
                110 | 995 => techniques.push("T1071.003"), // POP3
                143 | 993 => techniques.push("T1071.003"), // IMAP
                139 | 445 => {
                    techniques.push("T1021.002"); // SMB
                    techniques.push("T1135"); // Network share discovery
                }
                389 | 636 => techniques.push("T1087.002"), // LDAP
                1433 | 1521 | 3306 | 5432 => techniques.push("T1505.001"), // SQL
                3389 => {
                    techniques.push("T1021.001"); // RDP
                    techniques.push("T1563.002"); // RDP hijacking
                }
                5985 | 5986 => techniques.push("T1021.006"), // WinRM
                6379 => techniques.push("T1190"), // Redis
                27017 => techniques.push("T1190"), // MongoDB
                _ => {}
            }
        }

        techniques.sort();
        techniques.dedup();
        techniques
    }

    fn extract_cn_from_issuer(issuer: &str) -> Option<String> {
        // Parse "CN=Name, O=Org" format
        for part in issuer.split(',') {
            let part = part.trim();
            if part.starts_with("CN=") || part.starts_with("cn=") {
                return Some(part[3..].to_string());
            }
        }
        None
    }

    fn is_privacy_protected(email: &str) -> bool {
        let email_lower = email.to_lowercase();
        email_lower.contains("privacy")
            || email_lower.contains("redacted")
            || email_lower.contains("whoisguard")
            || email_lower.contains("proxy")
            || email_lower.contains("protection")
            || email_lower.contains("private")
            || email_lower.contains("domainproxy")
    }

    fn extract_registrar_domain(registrar: &str) -> Option<String> {
        // Try to extract domain from registrar name
        let registrar_lower = registrar.to_lowercase();

        // Common patterns
        if registrar_lower.contains("godaddy") {
            return Some("godaddy.com".to_string());
        }
        if registrar_lower.contains("namecheap") {
            return Some("namecheap.com".to_string());
        }
        if registrar_lower.contains("cloudflare") {
            return Some("cloudflare.com".to_string());
        }
        if registrar_lower.contains("google") {
            return Some("domains.google".to_string());
        }

        // Try to extract URL/domain from text
        for word in registrar.split_whitespace() {
            if word.contains('.') && !word.contains('@') {
                let domain = word
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .trim_start_matches("www.")
                    .trim_end_matches('/')
                    .to_lowercase();

                if domain.len() > 3 && domain.contains('.') {
                    return Some(domain);
                }
            }
        }

        None
    }

    fn extract_domains_from_csp(csp: &str) -> Vec<String> {
        let mut domains = Vec::new();

        for part in csp.split(';') {
            for word in part.split_whitespace() {
                // Skip directives and special values
                if word.ends_with(':')
                    || word.starts_with('\'')
                    || word == "self"
                    || word == "none"
                    || word == "*"
                    || word.starts_with("data:")
                    || word.starts_with("blob:")
                {
                    continue;
                }

                // Extract domain from URL or bare domain
                let domain = word
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .split('/')
                    .next()
                    .unwrap_or("");

                // Must have a dot and not be an IP
                if domain.contains('.') && !domain.parse::<IpAddr>().is_ok() && domain.len() > 3 {
                    domains.push(domain.to_string());
                }
            }
        }

        domains.sort();
        domains.dedup();
        domains
    }

    fn extract_cookie_domain(cookie: &str) -> Option<String> {
        for part in cookie.split(';') {
            let part = part.trim();
            if part.to_lowercase().starts_with("domain=") {
                let domain = part[7..].trim_start_matches('.');
                if domain.contains('.') {
                    return Some(domain.to_string());
                }
            }
        }
        None
    }

    fn extract_urls_from_html(html: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // Simple regex-like extraction for href="..." and src="..."
        let patterns = ["href=\"", "href='", "src=\"", "src='", "action=\"", "action='"];

        for pattern in patterns {
            let quote = if pattern.ends_with('"') { '"' } else { '\'' };
            let mut search_start = 0;

            while let Some(start) = html[search_start..].find(pattern) {
                let abs_start = search_start + start + pattern.len();
                if abs_start >= html.len() {
                    break;
                }

                if let Some(end) = html[abs_start..].find(quote) {
                    let url = &html[abs_start..abs_start + end];
                    if !url.is_empty() && !url.starts_with('#') && !url.starts_with("javascript:") {
                        urls.push(url.to_string());
                    }
                    search_start = abs_start + end + 1;
                } else {
                    break;
                }
            }
        }

        urls.sort();
        urls.dedup();
        urls
    }

    fn extract_emails_from_text(text: &str) -> Vec<String> {
        let mut emails = Vec::new();

        // Simple email pattern extraction
        let mut in_word = false;
        let mut current_word = String::new();

        for ch in text.chars() {
            if ch.is_alphanumeric() || ch == '@' || ch == '.' || ch == '_' || ch == '-' || ch == '+' {
                current_word.push(ch);
                in_word = true;
            } else if in_word {
                // Check if it looks like an email
                if current_word.contains('@')
                    && current_word.len() > 5
                    && !current_word.starts_with('@')
                    && !current_word.ends_with('@')
                {
                    // Basic validation
                    let parts: Vec<&str> = current_word.split('@').collect();
                    if parts.len() == 2 && parts[1].contains('.') && !parts[1].starts_with('.') {
                        emails.push(current_word.to_lowercase());
                    }
                }
                current_word.clear();
                in_word = false;
            }
        }

        // Check last word
        if current_word.contains('@') && current_word.len() > 5 {
            let parts: Vec<&str> = current_word.split('@').collect();
            if parts.len() == 2 && parts[1].contains('.') {
                emails.push(current_word.to_lowercase());
            }
        }

        emails.sort();
        emails.dedup();
        emails
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_creation() {
        let ioc = Ioc::new(
            IocType::IPv4,
            "192.168.1.1",
            IocSource::PortScan,
            85,
            "example.com",
        )
        .with_technique("T1021.001")
        .with_tag("rdp_open");

        assert_eq!(ioc.ioc_type, IocType::IPv4);
        assert_eq!(ioc.value, "192.168.1.1");
        assert_eq!(ioc.confidence, IocConfidence::High);
        assert!(ioc.mitre_techniques.contains(&"T1021.001".to_string()));
        assert!(ioc.tags.contains(&"rdp_open".to_string()));
    }

    #[test]
    fn test_ioc_stix_pattern() {
        let ioc = Ioc::new(
            IocType::Domain,
            "malicious.example.com",
            IocSource::DnsQuery,
            90,
            "target",
        );

        assert_eq!(
            ioc.to_stix_pattern(),
            "[domain-name:value = 'malicious.example.com']"
        );
    }

    #[test]
    fn test_collection_deduplication() {
        let mut collection = IocCollection::new();

        collection.add(Ioc::new(
            IocType::IPv4,
            "192.168.1.1",
            IocSource::PortScan,
            70,
            "target",
        ));

        collection.add(
            Ioc::new(
                IocType::IPv4,
                "192.168.1.1",
                IocSource::DnsQuery,
                85,
                "target",
            )
            .with_technique("T1071.004"),
        );

        assert_eq!(collection.len(), 1);

        let iocs = collection.all();
        assert_eq!(iocs[0].confidence_score, 85); // Higher confidence kept
        assert!(iocs[0].mitre_techniques.contains(&"T1071.004".to_string()));
    }

    #[test]
    fn test_extract_emails_from_text() {
        let emails = IocExtractor::extract_emails_from_text(
            "Contact us at admin@example.com or support@test.org",
        );

        assert_eq!(emails.len(), 2);
        assert!(emails.contains(&"admin@example.com".to_string()));
        assert!(emails.contains(&"support@test.org".to_string()));
    }

    #[test]
    fn test_extract_domains_from_csp() {
        let csp = "default-src 'self'; script-src https://cdn.example.com https://api.test.org; img-src *";
        let domains = IocExtractor::extract_domains_from_csp(csp);

        assert!(domains.contains(&"cdn.example.com".to_string()));
        assert!(domains.contains(&"api.test.org".to_string()));
    }

    #[test]
    fn test_confidence_levels() {
        assert_eq!(IocConfidence::from_score(20), IocConfidence::Low);
        assert_eq!(IocConfidence::from_score(50), IocConfidence::Medium);
        assert_eq!(IocConfidence::from_score(80), IocConfidence::High);
    }

    #[test]
    fn test_extract_from_port_scan() {
        let extractor = IocExtractor::new("example.com");
        let iocs = extractor.extract_from_port_scan("192.168.1.100", &[22, 80, 443, 3389]);

        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].ioc_type, IocType::IPv4);
        assert_eq!(iocs[0].value, "192.168.1.100");
        assert!(iocs[0].mitre_techniques.contains(&"T1021.004".to_string())); // SSH
        assert!(iocs[0].mitre_techniques.contains(&"T1071.001".to_string())); // HTTP
        assert!(iocs[0].mitre_techniques.contains(&"T1021.001".to_string())); // RDP
    }

    #[test]
    fn test_extract_from_dns() {
        use std::net::Ipv4Addr;

        let extractor = IocExtractor::new("example.com");
        let iocs = extractor.extract_from_dns(
            "example.com",
            &[Ipv4Addr::new(93, 184, 216, 34)],
            &[],
            &["10 mail.example.com".to_string()],
            &["ns1.example.com".to_string()],
            &[],
        );

        assert!(iocs.len() >= 3);

        // Check domain IOC
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Domain && i.value == "example.com"));

        // Check IP IOC
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::IPv4 && i.value == "93.184.216.34"));

        // Check MX host IOC
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Domain
            && i.value == "mail.example.com"
            && i.tags.contains(&"mail_server".to_string())));
    }

    #[test]
    fn test_collection_to_json() {
        let mut collection = IocCollection::new();
        collection.add(
            Ioc::new(
                IocType::Domain,
                "test.example.com",
                IocSource::SubdomainEnum,
                75,
                "example.com",
            )
            .with_tag("subdomain"),
        );

        let json = collection.to_json();
        assert!(json.contains("\"type\": \"domain\""));
        assert!(json.contains("\"value\": \"test.example.com\""));
        assert!(json.contains("\"total\": 1"));
    }

    #[test]
    fn test_collection_to_csv() {
        let mut collection = IocCollection::new();
        collection.add(Ioc::new(
            IocType::IPv4,
            "10.0.0.1",
            IocSource::PortScan,
            80,
            "target",
        ));

        let csv = collection.to_csv();
        assert!(csv.contains("type,value,source"));
        assert!(csv.contains("ipv4,\"10.0.0.1\",port_scan"));
    }
}
