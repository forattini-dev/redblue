//! MITRE ATT&CK Technique Mapping Engine
//!
//! Maps security findings (open ports, CVEs, fingerprints) to MITRE ATT&CK techniques.
//!
//! ## Port Mapping
//!
//! Open ports indicate potential attack vectors:
//! - SSH (22) → T1021.004 Remote Services: SSH
//! - RDP (3389) → T1021.001 Remote Services: RDP
//! - SMB (445) → T1021.002 Remote Services: SMB
//!
//! ## CVE Mapping
//!
//! Vulnerability types map to techniques:
//! - RCE vulnerabilities → T1203 Exploitation for Client Execution
//! - SQLi vulnerabilities → T1190 Exploit Public-Facing Application
//!
//! ## Fingerprint Mapping
//!
//! Technology fingerprints indicate attacker interest:
//! - WordPress → T1583.008 Compromise Websites
//! - Apache → T1190 Exploit Public-Facing Application

use std::collections::HashMap;

/// A mapped technique result
#[derive(Debug, Clone)]
pub struct MappedTechnique {
    /// MITRE technique ID (e.g., "T1021.004")
    pub technique_id: String,
    /// Technique name
    pub name: String,
    /// Why this was mapped
    pub reason: String,
    /// Associated tactic
    pub tactic: String,
    /// Confidence: high, medium, low
    pub confidence: Confidence,
    /// Source of the mapping (port, cve, fingerprint)
    pub source: MappingSource,
    /// Original value that triggered the mapping
    pub original_value: String,
}

/// Confidence level for technique mappings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Confidence::High => 100,
            Confidence::Medium => 70,
            Confidence::Low => 40,
        }
    }
}

/// Source of the technique mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSource {
    Port,
    Cve,
    Fingerprint,
    Banner,
}

impl MappingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            MappingSource::Port => "port",
            MappingSource::Cve => "cve",
            MappingSource::Fingerprint => "fingerprint",
            MappingSource::Banner => "banner",
        }
    }
}

/// Port to technique mapping entry
struct PortMapping {
    technique_id: &'static str,
    name: &'static str,
    tactic: &'static str,
    confidence: Confidence,
    reason: &'static str,
}

/// Technique mapper engine
pub struct TechniqueMapper {
    /// Port number to technique mappings
    port_mappings: HashMap<u16, Vec<PortMapping>>,
    /// CVE pattern to technique mappings
    cve_patterns: Vec<CvePattern>,
    /// Technology fingerprint to technique mappings
    fingerprint_mappings: HashMap<String, Vec<FingerprintMapping>>,
}

struct CvePattern {
    /// Keywords to match in CVE description
    keywords: Vec<&'static str>,
    /// Technique ID
    technique_id: &'static str,
    name: &'static str,
    tactic: &'static str,
    confidence: Confidence,
    reason: &'static str,
}

struct FingerprintMapping {
    technique_id: &'static str,
    name: &'static str,
    tactic: &'static str,
    confidence: Confidence,
    reason: &'static str,
}

impl Default for TechniqueMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl TechniqueMapper {
    /// Create a new technique mapper with built-in mappings
    pub fn new() -> Self {
        let mut mapper = TechniqueMapper {
            port_mappings: HashMap::new(),
            cve_patterns: Vec::new(),
            fingerprint_mappings: HashMap::new(),
        };

        mapper.init_port_mappings();
        mapper.init_cve_patterns();
        mapper.init_fingerprint_mappings();

        mapper
    }

    /// Initialize port-to-technique mappings
    fn init_port_mappings(&mut self) {
        // SSH (22) - Remote Services
        self.port_mappings.insert(22, vec![
            PortMapping {
                technique_id: "T1021.004",
                name: "Remote Services: SSH",
                tactic: "Lateral Movement",
                confidence: Confidence::High,
                reason: "SSH enables remote command execution and lateral movement",
            },
            PortMapping {
                technique_id: "T1110.001",
                name: "Brute Force: Password Guessing",
                tactic: "Credential Access",
                confidence: Confidence::Medium,
                reason: "SSH is commonly targeted for password attacks",
            },
        ]);

        // Telnet (23) - Remote Services
        self.port_mappings.insert(23, vec![
            PortMapping {
                technique_id: "T1021",
                name: "Remote Services",
                tactic: "Lateral Movement",
                confidence: Confidence::High,
                reason: "Telnet provides unencrypted remote access",
            },
            PortMapping {
                technique_id: "T1557",
                name: "Adversary-in-the-Middle",
                tactic: "Credential Access",
                confidence: Confidence::High,
                reason: "Telnet transmits credentials in cleartext",
            },
        ]);

        // FTP (21) - Data Transfer
        self.port_mappings.insert(21, vec![
            PortMapping {
                technique_id: "T1071.002",
                name: "Application Layer Protocol: File Transfer Protocols",
                tactic: "Command and Control",
                confidence: Confidence::Medium,
                reason: "FTP can be used for C2 and data exfiltration",
            },
            PortMapping {
                technique_id: "T1048.003",
                name: "Exfiltration Over Alternative Protocol: Unencrypted",
                tactic: "Exfiltration",
                confidence: Confidence::Medium,
                reason: "FTP enables data exfiltration over cleartext protocol",
            },
        ]);

        // SMTP (25, 587, 465) - Email
        for port in [25, 587, 465] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1071.003",
                    name: "Application Layer Protocol: Mail Protocols",
                    tactic: "Command and Control",
                    confidence: Confidence::Medium,
                    reason: "SMTP can be abused for C2 communication",
                },
                PortMapping {
                    technique_id: "T1566.001",
                    name: "Phishing: Spearphishing Attachment",
                    tactic: "Initial Access",
                    confidence: Confidence::Low,
                    reason: "Mail server may be used for phishing campaigns",
                },
            ]);
        }

        // DNS (53) - DNS
        self.port_mappings.insert(53, vec![
            PortMapping {
                technique_id: "T1071.004",
                name: "Application Layer Protocol: DNS",
                tactic: "Command and Control",
                confidence: Confidence::Medium,
                reason: "DNS is commonly used for C2 tunneling",
            },
            PortMapping {
                technique_id: "T1568.002",
                name: "Dynamic Resolution: Domain Generation Algorithms",
                tactic: "Command and Control",
                confidence: Confidence::Low,
                reason: "DNS server may resolve DGA domains",
            },
        ]);

        // HTTP (80) - Web Services
        self.port_mappings.insert(80, vec![
            PortMapping {
                technique_id: "T1071.001",
                name: "Application Layer Protocol: Web Protocols",
                tactic: "Command and Control",
                confidence: Confidence::Medium,
                reason: "HTTP is used for web-based C2",
            },
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Web applications are common attack vectors",
            },
        ]);

        // HTTPS (443) - Web Services
        self.port_mappings.insert(443, vec![
            PortMapping {
                technique_id: "T1071.001",
                name: "Application Layer Protocol: Web Protocols",
                tactic: "Command and Control",
                confidence: Confidence::Medium,
                reason: "HTTPS provides encrypted C2 channel",
            },
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "HTTPS web applications are common attack vectors",
            },
            PortMapping {
                technique_id: "T1573.002",
                name: "Encrypted Channel: Asymmetric Cryptography",
                tactic: "Command and Control",
                confidence: Confidence::Low,
                reason: "TLS provides encrypted communication channel",
            },
        ]);

        // POP3 (110, 995)
        for port in [110, 995] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1114.002",
                    name: "Email Collection: Remote Email Collection",
                    tactic: "Collection",
                    confidence: Confidence::Medium,
                    reason: "POP3 enables remote email access and collection",
                },
            ]);
        }

        // IMAP (143, 993)
        for port in [143, 993] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1114.002",
                    name: "Email Collection: Remote Email Collection",
                    tactic: "Collection",
                    confidence: Confidence::Medium,
                    reason: "IMAP enables remote email access and collection",
                },
            ]);
        }

        // NetBIOS/SMB (135, 137, 138, 139, 445)
        for port in [135, 137, 138, 139] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1021.002",
                    name: "Remote Services: SMB/Windows Admin Shares",
                    tactic: "Lateral Movement",
                    confidence: Confidence::High,
                    reason: "NetBIOS enables Windows lateral movement",
                },
            ]);
        }

        // SMB (445) - Windows File Sharing
        self.port_mappings.insert(445, vec![
            PortMapping {
                technique_id: "T1021.002",
                name: "Remote Services: SMB/Windows Admin Shares",
                tactic: "Lateral Movement",
                confidence: Confidence::High,
                reason: "SMB enables lateral movement via admin shares",
            },
            PortMapping {
                technique_id: "T1570",
                name: "Lateral Tool Transfer",
                tactic: "Lateral Movement",
                confidence: Confidence::High,
                reason: "SMB enables file transfers between systems",
            },
            PortMapping {
                technique_id: "T1187",
                name: "Forced Authentication",
                tactic: "Credential Access",
                confidence: Confidence::Medium,
                reason: "SMB can be used for NTLM relay attacks",
            },
        ]);

        // Microsoft SQL Server (1433)
        self.port_mappings.insert(1433, vec![
            PortMapping {
                technique_id: "T1059.001",
                name: "Command and Scripting Interpreter: PowerShell",
                tactic: "Execution",
                confidence: Confidence::Medium,
                reason: "SQL Server can execute OS commands via xp_cmdshell",
            },
            PortMapping {
                technique_id: "T1505.001",
                name: "Server Software Component: SQL Stored Procedures",
                tactic: "Persistence",
                confidence: Confidence::High,
                reason: "SQL stored procedures enable persistent access",
            },
        ]);

        // MySQL (3306)
        self.port_mappings.insert(3306, vec![
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "MySQL may be vulnerable to SQL injection",
            },
            PortMapping {
                technique_id: "T1505.001",
                name: "Server Software Component: SQL Stored Procedures",
                tactic: "Persistence",
                confidence: Confidence::Medium,
                reason: "MySQL stored procedures enable persistent access",
            },
        ]);

        // PostgreSQL (5432)
        self.port_mappings.insert(5432, vec![
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "PostgreSQL may be vulnerable to SQL injection",
            },
        ]);

        // Oracle (1521)
        self.port_mappings.insert(1521, vec![
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Oracle DB may be vulnerable to SQL injection",
            },
        ]);

        // RDP (3389) - Remote Desktop
        self.port_mappings.insert(3389, vec![
            PortMapping {
                technique_id: "T1021.001",
                name: "Remote Services: Remote Desktop Protocol",
                tactic: "Lateral Movement",
                confidence: Confidence::High,
                reason: "RDP enables remote desktop access",
            },
            PortMapping {
                technique_id: "T1110.001",
                name: "Brute Force: Password Guessing",
                tactic: "Credential Access",
                confidence: Confidence::Medium,
                reason: "RDP is commonly targeted for credential attacks",
            },
            PortMapping {
                technique_id: "T1563.002",
                name: "Remote Service Session Hijacking: RDP Hijacking",
                tactic: "Lateral Movement",
                confidence: Confidence::Medium,
                reason: "RDP sessions can be hijacked",
            },
        ]);

        // VNC (5900-5910)
        for port in 5900..=5910 {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1021.005",
                    name: "Remote Services: VNC",
                    tactic: "Lateral Movement",
                    confidence: Confidence::High,
                    reason: "VNC enables remote desktop access",
                },
            ]);
        }

        // WinRM (5985, 5986)
        for port in [5985, 5986] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1021.006",
                    name: "Remote Services: Windows Remote Management",
                    tactic: "Lateral Movement",
                    confidence: Confidence::High,
                    reason: "WinRM enables remote PowerShell execution",
                },
                PortMapping {
                    technique_id: "T1059.001",
                    name: "Command and Scripting Interpreter: PowerShell",
                    tactic: "Execution",
                    confidence: Confidence::High,
                    reason: "WinRM runs PowerShell commands remotely",
                },
            ]);
        }

        // LDAP (389, 636)
        for port in [389, 636] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1087.002",
                    name: "Account Discovery: Domain Account",
                    tactic: "Discovery",
                    confidence: Confidence::High,
                    reason: "LDAP enables Active Directory enumeration",
                },
                PortMapping {
                    technique_id: "T1069.002",
                    name: "Permission Groups Discovery: Domain Groups",
                    tactic: "Discovery",
                    confidence: Confidence::High,
                    reason: "LDAP reveals domain group membership",
                },
            ]);
        }

        // Kerberos (88)
        self.port_mappings.insert(88, vec![
            PortMapping {
                technique_id: "T1558.003",
                name: "Steal or Forge Kerberos Tickets: Kerberoasting",
                tactic: "Credential Access",
                confidence: Confidence::High,
                reason: "Kerberos service enables Kerberoasting attacks",
            },
            PortMapping {
                technique_id: "T1558.004",
                name: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
                tactic: "Credential Access",
                confidence: Confidence::Medium,
                reason: "Kerberos may allow AS-REP roasting",
            },
        ]);

        // SNMP (161, 162)
        for port in [161, 162] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1602.001",
                    name: "Data from Configuration Repository: SNMP",
                    tactic: "Collection",
                    confidence: Confidence::High,
                    reason: "SNMP may expose configuration data",
                },
                PortMapping {
                    technique_id: "T1018",
                    name: "Remote System Discovery",
                    tactic: "Discovery",
                    confidence: Confidence::Medium,
                    reason: "SNMP can reveal network topology",
                },
            ]);
        }

        // NFS (2049)
        self.port_mappings.insert(2049, vec![
            PortMapping {
                technique_id: "T1039",
                name: "Data from Network Shared Drive",
                tactic: "Collection",
                confidence: Confidence::High,
                reason: "NFS shares may contain sensitive data",
            },
        ]);

        // Docker (2375, 2376)
        for port in [2375, 2376] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1610",
                    name: "Deploy Container",
                    tactic: "Defense Evasion",
                    confidence: Confidence::High,
                    reason: "Docker API enables container deployment",
                },
                PortMapping {
                    technique_id: "T1613",
                    name: "Container and Resource Discovery",
                    tactic: "Discovery",
                    confidence: Confidence::High,
                    reason: "Docker API exposes container information",
                },
            ]);
        }

        // Kubernetes (6443, 8443, 10250)
        for port in [6443, 8443, 10250] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1609",
                    name: "Container Administration Command",
                    tactic: "Execution",
                    confidence: Confidence::High,
                    reason: "Kubernetes API enables container control",
                },
                PortMapping {
                    technique_id: "T1610",
                    name: "Deploy Container",
                    tactic: "Defense Evasion",
                    confidence: Confidence::High,
                    reason: "Kubernetes enables malicious container deployment",
                },
            ]);
        }

        // Redis (6379)
        self.port_mappings.insert(6379, vec![
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "Redis without auth enables RCE",
            },
            PortMapping {
                technique_id: "T1136.001",
                name: "Create Account: Local Account",
                tactic: "Persistence",
                confidence: Confidence::Medium,
                reason: "Redis can be used to write SSH keys",
            },
        ]);

        // MongoDB (27017)
        self.port_mappings.insert(27017, vec![
            PortMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "MongoDB without auth exposes data",
            },
        ]);

        // Elasticsearch (9200, 9300)
        for port in [9200, 9300] {
            self.port_mappings.insert(port, vec![
                PortMapping {
                    technique_id: "T1190",
                    name: "Exploit Public-Facing Application",
                    tactic: "Initial Access",
                    confidence: Confidence::High,
                    reason: "Elasticsearch may expose indexed data",
                },
            ]);
        }

        // Memcached (11211)
        self.port_mappings.insert(11211, vec![
            PortMapping {
                technique_id: "T1498.001",
                name: "Network Denial of Service: Direct Network Flood",
                tactic: "Impact",
                confidence: Confidence::Medium,
                reason: "Memcached can be used for DDoS amplification",
            },
        ]);

        // Rsync (873)
        self.port_mappings.insert(873, vec![
            PortMapping {
                technique_id: "T1048",
                name: "Exfiltration Over Alternative Protocol",
                tactic: "Exfiltration",
                confidence: Confidence::Medium,
                reason: "Rsync enables data exfiltration",
            },
        ]);

        // Git (9418)
        self.port_mappings.insert(9418, vec![
            PortMapping {
                technique_id: "T1213.003",
                name: "Data from Information Repositories: Code Repositories",
                tactic: "Collection",
                confidence: Confidence::High,
                reason: "Git repositories may contain secrets",
            },
        ]);

        // Jenkins (8080, 8443)
        // Note: 8080 is generic HTTP alternative, but commonly Jenkins
        // We'll add Jenkins-specific handling in fingerprint mappings

        // Proxy ports (3128, 8080, 8888)
        for port in [3128, 8080, 8888] {
            self.port_mappings.entry(port).or_insert_with(Vec::new).push(
                PortMapping {
                    technique_id: "T1090",
                    name: "Proxy",
                    tactic: "Command and Control",
                    confidence: Confidence::Low,
                    reason: "Port commonly used for proxy services",
                },
            );
        }
    }

    /// Initialize CVE pattern to technique mappings
    fn init_cve_patterns(&mut self) {
        self.cve_patterns = vec![
            // Remote Code Execution
            CvePattern {
                keywords: vec!["remote code execution", "rce", "arbitrary code", "code execution"],
                technique_id: "T1203",
                name: "Exploitation for Client Execution",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "CVE enables remote code execution",
            },
            // SQL Injection
            CvePattern {
                keywords: vec!["sql injection", "sqli", "sql query"],
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "SQL injection vulnerability",
            },
            // XSS
            CvePattern {
                keywords: vec!["cross-site scripting", "xss", "script injection"],
                technique_id: "T1189",
                name: "Drive-by Compromise",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "XSS can lead to drive-by compromise",
            },
            // Command Injection
            CvePattern {
                keywords: vec!["command injection", "os command", "shell injection"],
                technique_id: "T1059",
                name: "Command and Scripting Interpreter",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Command injection enables arbitrary command execution",
            },
            // Path Traversal
            CvePattern {
                keywords: vec!["path traversal", "directory traversal", "lfi", "local file inclusion"],
                technique_id: "T1083",
                name: "File and Directory Discovery",
                tactic: "Discovery",
                confidence: Confidence::Medium,
                reason: "Path traversal enables file system access",
            },
            // Authentication Bypass
            CvePattern {
                keywords: vec!["authentication bypass", "auth bypass", "unauthorized access"],
                technique_id: "T1078",
                name: "Valid Accounts",
                tactic: "Defense Evasion",
                confidence: Confidence::High,
                reason: "Authentication bypass enables unauthorized access",
            },
            // Privilege Escalation
            CvePattern {
                keywords: vec!["privilege escalation", "privesc", "elevation of privilege"],
                technique_id: "T1068",
                name: "Exploitation for Privilege Escalation",
                tactic: "Privilege Escalation",
                confidence: Confidence::High,
                reason: "CVE enables privilege escalation",
            },
            // Information Disclosure
            CvePattern {
                keywords: vec!["information disclosure", "data leak", "sensitive data exposure"],
                technique_id: "T1005",
                name: "Data from Local System",
                tactic: "Collection",
                confidence: Confidence::Medium,
                reason: "Information disclosure exposes sensitive data",
            },
            // Denial of Service
            CvePattern {
                keywords: vec!["denial of service", "dos", "crash", "resource exhaustion"],
                technique_id: "T1499",
                name: "Endpoint Denial of Service",
                tactic: "Impact",
                confidence: Confidence::Medium,
                reason: "CVE can cause denial of service",
            },
            // Deserialization
            CvePattern {
                keywords: vec!["deserialization", "object injection", "unserialize"],
                technique_id: "T1059",
                name: "Command and Scripting Interpreter",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Deserialization can lead to code execution",
            },
            // SSRF
            CvePattern {
                keywords: vec!["ssrf", "server-side request forgery", "internal network"],
                technique_id: "T1090.002",
                name: "Proxy: External Proxy",
                tactic: "Command and Control",
                confidence: Confidence::Medium,
                reason: "SSRF enables internal network access",
            },
            // XXE
            CvePattern {
                keywords: vec!["xxe", "xml external entity", "xml injection"],
                technique_id: "T1059",
                name: "Command and Scripting Interpreter",
                tactic: "Execution",
                confidence: Confidence::Medium,
                reason: "XXE can lead to data exfiltration or SSRF",
            },
            // Buffer Overflow
            CvePattern {
                keywords: vec!["buffer overflow", "heap overflow", "stack overflow", "memory corruption"],
                technique_id: "T1203",
                name: "Exploitation for Client Execution",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Memory corruption vulnerability",
            },
            // Use After Free
            CvePattern {
                keywords: vec!["use after free", "uaf", "double free"],
                technique_id: "T1203",
                name: "Exploitation for Client Execution",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Memory corruption vulnerability",
            },
            // CSRF
            CvePattern {
                keywords: vec!["csrf", "cross-site request forgery", "request forgery"],
                technique_id: "T1185",
                name: "Browser Session Hijacking",
                tactic: "Collection",
                confidence: Confidence::Medium,
                reason: "CSRF can hijack user sessions",
            },
        ];
    }

    /// Initialize technology fingerprint to technique mappings
    fn init_fingerprint_mappings(&mut self) {
        // WordPress
        self.fingerprint_mappings.insert("wordpress".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "WordPress is a common target for exploitation",
            },
            FingerprintMapping {
                technique_id: "T1583.008",
                name: "Acquire Infrastructure: Malvertising",
                tactic: "Resource Development",
                confidence: Confidence::Low,
                reason: "WordPress sites are often compromised for malvertising",
            },
        ]);

        // Drupal
        self.fingerprint_mappings.insert("drupal".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Drupal has known vulnerabilities (Drupalgeddon)",
            },
        ]);

        // Joomla
        self.fingerprint_mappings.insert("joomla".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Joomla has known vulnerabilities",
            },
        ]);

        // Apache HTTP Server
        self.fingerprint_mappings.insert("apache".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Low,
                reason: "Apache may have known vulnerabilities",
            },
        ]);

        // nginx
        self.fingerprint_mappings.insert("nginx".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Low,
                reason: "nginx may have known vulnerabilities",
            },
        ]);

        // IIS
        self.fingerprint_mappings.insert("iis".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "IIS may have known vulnerabilities",
            },
        ]);

        // Tomcat
        self.fingerprint_mappings.insert("tomcat".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Tomcat manager interface is often targeted",
            },
            FingerprintMapping {
                technique_id: "T1505.003",
                name: "Server Software Component: Web Shell",
                tactic: "Persistence",
                confidence: Confidence::Medium,
                reason: "Tomcat can be used to deploy malicious WAR files",
            },
        ]);

        // Jenkins
        self.fingerprint_mappings.insert("jenkins".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1059.004",
                name: "Command and Scripting Interpreter: Unix Shell",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Jenkins Script Console enables code execution",
            },
            FingerprintMapping {
                technique_id: "T1552.001",
                name: "Unsecured Credentials: Credentials In Files",
                tactic: "Credential Access",
                confidence: Confidence::Medium,
                reason: "Jenkins stores credentials that may be exposed",
            },
        ]);

        // GitLab
        self.fingerprint_mappings.insert("gitlab".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1213.003",
                name: "Data from Information Repositories: Code Repositories",
                tactic: "Collection",
                confidence: Confidence::High,
                reason: "GitLab contains source code and secrets",
            },
        ]);

        // Confluence
        self.fingerprint_mappings.insert("confluence".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1213.001",
                name: "Data from Information Repositories: Confluence",
                tactic: "Collection",
                confidence: Confidence::High,
                reason: "Confluence contains organizational knowledge",
            },
        ]);

        // Jira
        self.fingerprint_mappings.insert("jira".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1213",
                name: "Data from Information Repositories",
                tactic: "Collection",
                confidence: Confidence::Medium,
                reason: "Jira contains project and security information",
            },
        ]);

        // Exchange
        self.fingerprint_mappings.insert("exchange".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1114",
                name: "Email Collection",
                tactic: "Collection",
                confidence: Confidence::High,
                reason: "Exchange is primary target for email collection",
            },
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "Exchange has critical vulnerabilities (ProxyLogon/ProxyShell)",
            },
        ]);

        // SharePoint
        self.fingerprint_mappings.insert("sharepoint".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1213.002",
                name: "Data from Information Repositories: Sharepoint",
                tactic: "Collection",
                confidence: Confidence::High,
                reason: "SharePoint contains sensitive documents",
            },
        ]);

        // AWS
        self.fingerprint_mappings.insert("aws".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1580",
                name: "Cloud Infrastructure Discovery",
                tactic: "Discovery",
                confidence: Confidence::Medium,
                reason: "AWS infrastructure may be enumerated",
            },
        ]);

        // Azure
        self.fingerprint_mappings.insert("azure".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1580",
                name: "Cloud Infrastructure Discovery",
                tactic: "Discovery",
                confidence: Confidence::Medium,
                reason: "Azure infrastructure may be enumerated",
            },
        ]);

        // Kubernetes
        self.fingerprint_mappings.insert("kubernetes".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1609",
                name: "Container Administration Command",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Kubernetes API enables container control",
            },
        ]);

        // Docker
        self.fingerprint_mappings.insert("docker".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1610",
                name: "Deploy Container",
                tactic: "Defense Evasion",
                confidence: Confidence::High,
                reason: "Docker enables container deployment",
            },
        ]);

        // Elasticsearch
        self.fingerprint_mappings.insert("elasticsearch".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "Elasticsearch may expose indexed data",
            },
        ]);

        // Kibana
        self.fingerprint_mappings.insert("kibana".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Kibana may expose log data",
            },
        ]);

        // Grafana
        self.fingerprint_mappings.insert("grafana".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Grafana may expose metrics and dashboards",
            },
        ]);

        // phpMyAdmin
        self.fingerprint_mappings.insert("phpmyadmin".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "phpMyAdmin provides database access",
            },
        ]);

        // Webmin
        self.fingerprint_mappings.insert("webmin".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1059",
                name: "Command and Scripting Interpreter",
                tactic: "Execution",
                confidence: Confidence::High,
                reason: "Webmin enables system administration",
            },
        ]);

        // cPanel
        self.fingerprint_mappings.insert("cpanel".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1059",
                name: "Command and Scripting Interpreter",
                tactic: "Execution",
                confidence: Confidence::Medium,
                reason: "cPanel provides hosting control",
            },
        ]);

        // Plesk
        self.fingerprint_mappings.insert("plesk".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1059",
                name: "Command and Scripting Interpreter",
                tactic: "Execution",
                confidence: Confidence::Medium,
                reason: "Plesk provides hosting control",
            },
        ]);

        // PHP
        self.fingerprint_mappings.insert("php".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Low,
                reason: "PHP applications may have vulnerabilities",
            },
        ]);

        // ASP.NET
        self.fingerprint_mappings.insert("aspnet".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Low,
                reason: "ASP.NET applications may have vulnerabilities",
            },
        ]);

        // Spring
        self.fingerprint_mappings.insert("spring".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Medium,
                reason: "Spring Framework has known vulnerabilities (Spring4Shell)",
            },
        ]);

        // Struts
        self.fingerprint_mappings.insert("struts".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "Apache Struts has critical RCE vulnerabilities",
            },
        ]);

        // Log4j
        self.fingerprint_mappings.insert("log4j".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::High,
                reason: "Log4j has critical RCE vulnerability (Log4Shell)",
            },
        ]);

        // OpenSSL
        self.fingerprint_mappings.insert("openssl".to_string(), vec![
            FingerprintMapping {
                technique_id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: "Initial Access",
                confidence: Confidence::Low,
                reason: "OpenSSL may have vulnerabilities (Heartbleed)",
            },
        ]);
    }

    /// Map an open port to techniques
    pub fn map_port(&self, port: u16) -> Vec<MappedTechnique> {
        self.port_mappings
            .get(&port)
            .map(|mappings| {
                mappings
                    .iter()
                    .map(|m| MappedTechnique {
                        technique_id: m.technique_id.to_string(),
                        name: m.name.to_string(),
                        reason: m.reason.to_string(),
                        tactic: m.tactic.to_string(),
                        confidence: m.confidence,
                        source: MappingSource::Port,
                        original_value: format!("port/{}", port),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Map a CVE description to techniques
    pub fn map_cve(&self, cve_id: &str, description: &str) -> Vec<MappedTechnique> {
        let lower = description.to_lowercase();
        let mut results = Vec::new();

        for pattern in &self.cve_patterns {
            let matches = pattern.keywords.iter().any(|kw| lower.contains(kw));
            if matches {
                results.push(MappedTechnique {
                    technique_id: pattern.technique_id.to_string(),
                    name: pattern.name.to_string(),
                    reason: pattern.reason.to_string(),
                    tactic: pattern.tactic.to_string(),
                    confidence: pattern.confidence,
                    source: MappingSource::Cve,
                    original_value: cve_id.to_string(),
                });
            }
        }

        results
    }

    /// Map a technology fingerprint to techniques
    pub fn map_fingerprint(&self, technology: &str) -> Vec<MappedTechnique> {
        let lower = technology.to_lowercase();

        // Try exact match first
        if let Some(mappings) = self.fingerprint_mappings.get(&lower) {
            return mappings
                .iter()
                .map(|m| MappedTechnique {
                    technique_id: m.technique_id.to_string(),
                    name: m.name.to_string(),
                    reason: m.reason.to_string(),
                    tactic: m.tactic.to_string(),
                    confidence: m.confidence,
                    source: MappingSource::Fingerprint,
                    original_value: technology.to_string(),
                })
                .collect();
        }

        // Try partial match
        for (key, mappings) in &self.fingerprint_mappings {
            if lower.contains(key) || key.contains(&lower) {
                return mappings
                    .iter()
                    .map(|m| MappedTechnique {
                        technique_id: m.technique_id.to_string(),
                        name: m.name.to_string(),
                        reason: m.reason.to_string(),
                        tactic: m.tactic.to_string(),
                        confidence: Confidence::Low, // Lower confidence for partial match
                        source: MappingSource::Fingerprint,
                        original_value: technology.to_string(),
                    })
                    .collect();
            }
        }

        Vec::new()
    }

    /// Map a banner string to techniques
    pub fn map_banner(&self, banner: &str) -> Vec<MappedTechnique> {
        let lower = banner.to_lowercase();
        let mut results = Vec::new();

        // Extract technology from banner and map
        for (tech, mappings) in &self.fingerprint_mappings {
            if lower.contains(tech) {
                for m in mappings {
                    results.push(MappedTechnique {
                        technique_id: m.technique_id.to_string(),
                        name: m.name.to_string(),
                        reason: format!("{} (detected in banner)", m.reason),
                        tactic: m.tactic.to_string(),
                        confidence: Confidence::Medium,
                        source: MappingSource::Banner,
                        original_value: banner.to_string(),
                    });
                }
            }
        }

        results
    }

    /// Map all findings for a target
    pub fn map_findings(&self, findings: &Findings) -> MappingResult {
        let mut result = MappingResult {
            techniques: Vec::new(),
            by_tactic: HashMap::new(),
            coverage: Vec::new(),
        };

        // Map ports
        for port in &findings.ports {
            let mapped = self.map_port(*port);
            for tech in mapped {
                result.add_technique(tech);
            }
        }

        // Map CVEs
        for (cve_id, description) in &findings.cves {
            let mapped = self.map_cve(cve_id, description);
            for tech in mapped {
                result.add_technique(tech);
            }
        }

        // Map fingerprints
        for fingerprint in &findings.fingerprints {
            let mapped = self.map_fingerprint(fingerprint);
            for tech in mapped {
                result.add_technique(tech);
            }
        }

        // Map banners
        for banner in &findings.banners {
            let mapped = self.map_banner(banner);
            for tech in mapped {
                result.add_technique(tech);
            }
        }

        // Calculate tactic coverage
        result.calculate_coverage();

        result
    }

    /// Get all mapped port numbers
    pub fn mapped_ports(&self) -> Vec<u16> {
        let mut ports: Vec<_> = self.port_mappings.keys().cloned().collect();
        ports.sort();
        ports
    }

    /// Get all mapped technologies
    pub fn mapped_technologies(&self) -> Vec<&str> {
        let mut techs: Vec<_> = self.fingerprint_mappings.keys().map(|s| s.as_str()).collect();
        techs.sort();
        techs
    }
}

/// Findings to map
#[derive(Debug, Default)]
pub struct Findings {
    /// Open ports
    pub ports: Vec<u16>,
    /// CVEs (id, description)
    pub cves: Vec<(String, String)>,
    /// Technology fingerprints
    pub fingerprints: Vec<String>,
    /// Service banners
    pub banners: Vec<String>,
}

/// Mapping result
#[derive(Debug)]
pub struct MappingResult {
    /// All mapped techniques (deduplicated)
    pub techniques: Vec<MappedTechnique>,
    /// Techniques grouped by tactic
    pub by_tactic: HashMap<String, Vec<MappedTechnique>>,
    /// Tactic coverage (tactic, count, percentage)
    pub coverage: Vec<(String, usize, f32)>,
}

impl MappingResult {
    /// Add a technique (deduplicates by ID)
    fn add_technique(&mut self, tech: MappedTechnique) {
        // Check for duplicate
        if self.techniques.iter().any(|t| t.technique_id == tech.technique_id && t.original_value == tech.original_value) {
            return;
        }

        let tactic = tech.tactic.clone();
        self.by_tactic.entry(tactic).or_default().push(tech.clone());
        self.techniques.push(tech);
    }

    /// Calculate tactic coverage
    fn calculate_coverage(&mut self) {
        // Standard MITRE ATT&CK tactics in kill chain order
        let tactics = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ];

        let total = self.techniques.len();

        for tactic in tactics {
            let count = self.by_tactic.get(tactic).map(|v| v.len()).unwrap_or(0);
            let percentage = if total > 0 {
                (count as f32 / total as f32) * 100.0
            } else {
                0.0
            };
            self.coverage.push((tactic.to_string(), count, percentage));
        }
    }

    /// Get unique technique IDs
    pub fn unique_technique_ids(&self) -> Vec<&str> {
        let mut ids: Vec<_> = self.techniques.iter().map(|t| t.technique_id.as_str()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get techniques sorted by confidence
    pub fn by_confidence(&self) -> Vec<&MappedTechnique> {
        let mut sorted: Vec<_> = self.techniques.iter().collect();
        sorted.sort_by(|a, b| b.confidence.score().cmp(&a.confidence.score()));
        sorted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_mapping_ssh() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_port(22);

        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.technique_id == "T1021.004"));
    }

    #[test]
    fn test_port_mapping_rdp() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_port(3389);

        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.technique_id == "T1021.001"));
    }

    #[test]
    fn test_port_mapping_smb() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_port(445);

        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.technique_id == "T1021.002"));
    }

    #[test]
    fn test_cve_mapping_rce() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_cve(
            "CVE-2021-44228",
            "Remote code execution vulnerability in Apache Log4j",
        );

        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.technique_id == "T1203"));
    }

    #[test]
    fn test_cve_mapping_sqli() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_cve(
            "CVE-2024-1234",
            "SQL injection vulnerability allows attackers to execute arbitrary SQL queries",
        );

        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.technique_id == "T1190"));
    }

    #[test]
    fn test_fingerprint_mapping() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_fingerprint("WordPress");

        assert!(!results.is_empty());
        assert!(results.iter().any(|t| t.technique_id == "T1190"));
    }

    #[test]
    fn test_banner_mapping() {
        let mapper = TechniqueMapper::new();
        let results = mapper.map_banner("Apache/2.4.51 (Ubuntu)");

        assert!(!results.is_empty());
    }

    #[test]
    fn test_full_mapping() {
        let mapper = TechniqueMapper::new();

        let findings = Findings {
            ports: vec![22, 80, 443, 3389],
            cves: vec![
                ("CVE-2021-44228".to_string(), "Remote code execution in Log4j".to_string()),
            ],
            fingerprints: vec!["wordpress".to_string(), "nginx".to_string()],
            banners: vec!["Apache/2.4".to_string()],
        };

        let result = mapper.map_findings(&findings);

        assert!(!result.techniques.is_empty());
        assert!(!result.by_tactic.is_empty());
        assert!(!result.coverage.is_empty());
    }

    #[test]
    fn test_mapped_ports_list() {
        let mapper = TechniqueMapper::new();
        let ports = mapper.mapped_ports();

        assert!(ports.contains(&22));
        assert!(ports.contains(&445));
        assert!(ports.contains(&3389));
    }

    #[test]
    fn test_mapped_technologies_list() {
        let mapper = TechniqueMapper::new();
        let techs = mapper.mapped_technologies();

        assert!(techs.contains(&"wordpress"));
        assert!(techs.contains(&"jenkins"));
        assert!(techs.contains(&"exchange"));
    }
}
