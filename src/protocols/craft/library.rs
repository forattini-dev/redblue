//! Signature Library
//!
//! Pre-defined packet signatures for various attack patterns and testing.

use super::signature::{
    IcmpFields, PacketSignature, TcpFields, UdpFields, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
    TCP_URG,
};
use std::collections::HashMap;

/// Signature categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureCategory {
    /// TCP scanning techniques
    Scan,
    /// Denial of Service patterns
    DoS,
    /// Distributed Denial of Service patterns
    DDoS,
    /// DNS attack patterns
    Dns,
    /// ICMP utilities
    Icmp,
    /// Evasion techniques
    Evasion,
    /// Backdoor/C2 patterns
    Backdoor,
    /// Protocol anomalies
    Anomaly,
}

impl SignatureCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::DoS => "dos",
            Self::DDoS => "ddos",
            Self::Dns => "dns",
            Self::Icmp => "icmp",
            Self::Evasion => "evasion",
            Self::Backdoor => "backdoor",
            Self::Anomaly => "anomaly",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "scan" => Some(Self::Scan),
            "dos" => Some(Self::DoS),
            "ddos" => Some(Self::DDoS),
            "dns" => Some(Self::Dns),
            "icmp" => Some(Self::Icmp),
            "evasion" => Some(Self::Evasion),
            "backdoor" => Some(Self::Backdoor),
            "anomaly" => Some(Self::Anomaly),
            _ => None,
        }
    }
}

/// Signature library entry
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub name: String,
    pub description: String,
    pub category: SignatureCategory,
    pub signature: PacketSignature,
    pub references: Vec<String>,
}

/// Signature library
pub struct SignatureLibrary {
    signatures: HashMap<String, SignatureEntry>,
}

impl SignatureLibrary {
    /// Create a new library with built-in signatures
    pub fn new() -> Self {
        let mut lib = Self {
            signatures: HashMap::new(),
        };
        lib.load_builtin();
        lib
    }

    /// Get a signature by name
    pub fn get(&self, name: &str) -> Option<&SignatureEntry> {
        self.signatures.get(name)
    }

    /// List all signatures
    pub fn list(&self) -> Vec<&SignatureEntry> {
        self.signatures.values().collect()
    }

    /// List signatures by category
    pub fn list_by_category(&self, category: SignatureCategory) -> Vec<&SignatureEntry> {
        self.signatures
            .values()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Add a signature
    pub fn add(&mut self, entry: SignatureEntry) {
        self.signatures.insert(entry.name.clone(), entry);
    }

    /// Load built-in signatures
    fn load_builtin(&mut self) {
        // === Scanning Signatures ===
        self.add(SignatureEntry {
            name: "tcp-syn-scan".to_string(),
            description: "Standard TCP SYN scan packet".to_string(),
            category: SignatureCategory::Scan,
            signature: {
                let mut sig = PacketSignature::new("tcp-syn-scan");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN,
                    window: 65535,
                    ..Default::default()
                });
                sig
            },
            references: vec!["nmap -sS".to_string()],
        });

        self.add(SignatureEntry {
            name: "tcp-fin-scan".to_string(),
            description: "TCP FIN scan (stealth)".to_string(),
            category: SignatureCategory::Scan,
            signature: {
                let mut sig = PacketSignature::new("tcp-fin-scan");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_FIN,
                    window: 0,
                    ..Default::default()
                });
                sig
            },
            references: vec!["nmap -sF".to_string()],
        });

        self.add(SignatureEntry {
            name: "tcp-null-scan".to_string(),
            description: "TCP NULL scan (no flags)".to_string(),
            category: SignatureCategory::Scan,
            signature: {
                let mut sig = PacketSignature::new("tcp-null-scan");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: 0,
                    window: 0,
                    ..Default::default()
                });
                sig
            },
            references: vec!["nmap -sN".to_string()],
        });

        self.add(SignatureEntry {
            name: "tcp-xmas-scan".to_string(),
            description: "TCP XMAS scan (FIN+PSH+URG)".to_string(),
            category: SignatureCategory::Scan,
            signature: {
                let mut sig = PacketSignature::new("tcp-xmas-scan");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_FIN | TCP_PSH | TCP_URG,
                    window: 0,
                    urgent: 0xFFFF,
                    ..Default::default()
                });
                sig
            },
            references: vec!["nmap -sX".to_string()],
        });

        self.add(SignatureEntry {
            name: "tcp-ack-scan".to_string(),
            description: "TCP ACK scan (firewall mapping)".to_string(),
            category: SignatureCategory::Scan,
            signature: {
                let mut sig = PacketSignature::new("tcp-ack-scan");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_ACK,
                    window: 1024,
                    ..Default::default()
                });
                sig
            },
            references: vec!["nmap -sA".to_string()],
        });

        // === DoS Signatures ===
        self.add(SignatureEntry {
            name: "syn-flood".to_string(),
            description: "TCP SYN flood packet".to_string(),
            category: SignatureCategory::DoS,
            signature: {
                let mut sig = PacketSignature::new("syn-flood");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN,
                    window: 65535,
                    ..Default::default()
                });
                sig
            },
            references: vec!["SYN flood attack".to_string()],
        });

        self.add(SignatureEntry {
            name: "rst-flood".to_string(),
            description: "TCP RST flood packet".to_string(),
            category: SignatureCategory::DoS,
            signature: {
                let mut sig = PacketSignature::new("rst-flood");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_RST,
                    window: 0,
                    ..Default::default()
                });
                sig
            },
            references: vec!["RST flood attack".to_string()],
        });

        self.add(SignatureEntry {
            name: "land-attack".to_string(),
            description: "LAND attack (src=dst)".to_string(),
            category: SignatureCategory::DoS,
            signature: {
                let mut sig = PacketSignature::new("land-attack");
                sig.description = "Source and destination should be the same".to_string();
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN,
                    window: 65535,
                    ..Default::default()
                });
                sig
            },
            references: vec!["CVE-1999-0016".to_string()],
        });

        // === ICMP Signatures ===
        self.add(SignatureEntry {
            name: "icmp-echo".to_string(),
            description: "ICMP Echo Request (ping)".to_string(),
            category: SignatureCategory::Icmp,
            signature: {
                let mut sig = PacketSignature::new("icmp-echo");
                sig.ipv4.ttl = 64;
                sig.ipv4.protocol = 1;
                sig.icmp = Some(IcmpFields {
                    icmp_type: 8,
                    code: 0,
                    id: 1,
                    sequence: 1,
                });
                sig
            },
            references: vec!["ICMP Echo Request".to_string()],
        });

        self.add(SignatureEntry {
            name: "icmp-timestamp".to_string(),
            description: "ICMP Timestamp Request".to_string(),
            category: SignatureCategory::Icmp,
            signature: {
                let mut sig = PacketSignature::new("icmp-timestamp");
                sig.ipv4.ttl = 64;
                sig.ipv4.protocol = 1;
                sig.icmp = Some(IcmpFields {
                    icmp_type: 13,
                    code: 0,
                    id: 1,
                    sequence: 1,
                });
                sig
            },
            references: vec!["ICMP Timestamp".to_string()],
        });

        self.add(SignatureEntry {
            name: "smurf-attack".to_string(),
            description: "Smurf attack ICMP (broadcast amplification)".to_string(),
            category: SignatureCategory::DDoS,
            signature: {
                let mut sig = PacketSignature::new("smurf-attack");
                sig.description = "Spoofed source, send to broadcast address".to_string();
                sig.ipv4.ttl = 64;
                sig.ipv4.protocol = 1;
                sig.icmp = Some(IcmpFields {
                    icmp_type: 8,
                    code: 0,
                    id: 0,
                    sequence: 0,
                });
                sig
            },
            references: vec!["CVE-1999-0513".to_string()],
        });

        // === DNS Signatures ===
        self.add(SignatureEntry {
            name: "dns-query".to_string(),
            description: "DNS query packet template".to_string(),
            category: SignatureCategory::Dns,
            signature: {
                let mut sig = PacketSignature::new("dns-query");
                sig.ipv4.ttl = 64;
                sig.ipv4.protocol = 17;
                sig.udp = Some(UdpFields {
                    sport: Some(40000),
                    dport: Some(53),
                });
                // DNS header + query would be in payload
                sig
            },
            references: vec!["RFC 1035".to_string()],
        });

        self.add(SignatureEntry {
            name: "dns-amplification".to_string(),
            description: "DNS amplification attack (ANY query)".to_string(),
            category: SignatureCategory::DDoS,
            signature: {
                let mut sig = PacketSignature::new("dns-amplification");
                sig.description = "Spoofed source, ANY query for amplification".to_string();
                sig.ipv4.ttl = 64;
                sig.ipv4.protocol = 17;
                sig.udp = Some(UdpFields {
                    sport: Some(40000),
                    dport: Some(53),
                });
                sig
            },
            references: vec!["DNS amplification attack".to_string()],
        });

        // === Evasion Signatures ===
        self.add(SignatureEntry {
            name: "low-ttl".to_string(),
            description: "Low TTL packet (IDS evasion)".to_string(),
            category: SignatureCategory::Evasion,
            signature: {
                let mut sig = PacketSignature::new("low-ttl");
                sig.ipv4.ttl = 1;
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN,
                    ..Default::default()
                });
                sig
            },
            references: vec!["IDS evasion technique".to_string()],
        });

        self.add(SignatureEntry {
            name: "fragmented-syn".to_string(),
            description: "Fragmented SYN packet".to_string(),
            category: SignatureCategory::Evasion,
            signature: {
                let mut sig = PacketSignature::new("fragmented-syn");
                sig.ipv4.ttl = 64;
                sig.ipv4.flags = 0x01; // More Fragments
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN,
                    ..Default::default()
                });
                sig
            },
            references: vec!["Fragmentation evasion".to_string()],
        });

        // === Anomaly Signatures ===
        self.add(SignatureEntry {
            name: "invalid-flags".to_string(),
            description: "Invalid TCP flag combination (SYN+FIN)".to_string(),
            category: SignatureCategory::Anomaly,
            signature: {
                let mut sig = PacketSignature::new("invalid-flags");
                sig.ipv4.ttl = 64;
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN | TCP_FIN,
                    ..Default::default()
                });
                sig
            },
            references: vec!["Protocol anomaly".to_string()],
        });

        self.add(SignatureEntry {
            name: "ecn-probe".to_string(),
            description: "ECN capability probe".to_string(),
            category: SignatureCategory::Scan,
            signature: {
                let mut sig = PacketSignature::new("ecn-probe");
                sig.ipv4.ttl = 64;
                sig.ipv4.tos = 0x03; // ECT(1) + ECT(0)
                sig.tcp = Some(TcpFields {
                    flags: TCP_SYN | 0xC0, // SYN + ECE + CWR
                    ..Default::default()
                });
                sig
            },
            references: vec!["RFC 3168".to_string()],
        });
    }
}

impl Default for SignatureLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_builtin() {
        let lib = SignatureLibrary::new();

        // Check some signatures exist
        assert!(lib.get("tcp-syn-scan").is_some());
        assert!(lib.get("syn-flood").is_some());
        assert!(lib.get("icmp-echo").is_some());
    }

    #[test]
    fn test_list_by_category() {
        let lib = SignatureLibrary::new();

        let scan_sigs = lib.list_by_category(SignatureCategory::Scan);
        assert!(!scan_sigs.is_empty());

        let dos_sigs = lib.list_by_category(SignatureCategory::DoS);
        assert!(!dos_sigs.is_empty());
    }

    #[test]
    fn test_signature_content() {
        let lib = SignatureLibrary::new();

        let syn = lib.get("tcp-syn-scan").unwrap();
        assert!(syn.signature.tcp.is_some());
        assert_eq!(syn.signature.tcp.as_ref().unwrap().flags, TCP_SYN);

        let xmas = lib.get("tcp-xmas-scan").unwrap();
        assert_eq!(
            xmas.signature.tcp.as_ref().unwrap().flags,
            TCP_FIN | TCP_PSH | TCP_URG
        );
    }
}
