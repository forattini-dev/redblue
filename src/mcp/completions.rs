//! MCP Completions - Auto-complete suggestions for resources and prompts
//!
//! Completions help users discover available URIs, arguments, and values
//! by providing contextual suggestions as they type.

use std::collections::HashMap;

/// A completion suggestion
#[derive(Debug, Clone)]
pub struct Completion {
    /// The completion value
    pub value: String,
    /// Optional description
    pub description: Option<String>,
}

/// Completion reference - what we're completing
#[derive(Debug, Clone)]
pub enum CompletionRef {
    /// Completing a resource URI
    Resource { uri: String },
    /// Completing a prompt argument
    PromptArgument { name: String, argument: String },
}

/// Completion provider - handles auto-complete requests
pub struct CompletionProvider {
    /// Known resource prefixes
    resource_prefixes: Vec<ResourcePrefix>,
    /// Known prompt arguments with values
    prompt_values: HashMap<String, Vec<Completion>>,
}

struct ResourcePrefix {
    prefix: String,
    completions: Vec<Completion>,
    description: String,
}

impl CompletionProvider {
    pub fn new() -> Self {
        let mut provider = Self {
            resource_prefixes: Vec::new(),
            prompt_values: HashMap::new(),
        };
        provider.register_all();
        provider
    }

    fn register_all(&mut self) {
        self.register_resource_prefixes();
        self.register_prompt_values();
    }

    fn register_resource_prefixes(&mut self) {
        // ═══════════════════════════════════════════════════════════════════
        // INTEL RESOURCES
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://intel/".into(),
            description: "Threat intelligence resources".into(),
            completions: vec![
                Completion {
                    value: "redblue://intel/cve/".into(),
                    description: Some("CVE database queries".into()),
                },
                Completion {
                    value: "redblue://intel/mitre/".into(),
                    description: Some("MITRE ATT&CK data".into()),
                },
                Completion {
                    value: "redblue://intel/ioc".into(),
                    description: Some("Indicators of Compromise".into()),
                },
                Completion {
                    value: "redblue://intel/exploitdb/".into(),
                    description: Some("Exploit-DB queries".into()),
                },
            ],
        });

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://intel/mitre/".into(),
            description: "MITRE ATT&CK data".into(),
            completions: vec![
                Completion {
                    value: "redblue://intel/mitre/tactics".into(),
                    description: Some("All ATT&CK tactics".into()),
                },
                Completion {
                    value: "redblue://intel/mitre/techniques".into(),
                    description: Some("All techniques".into()),
                },
                Completion {
                    value: "redblue://intel/mitre/groups".into(),
                    description: Some("Threat groups".into()),
                },
                Completion {
                    value: "redblue://intel/mitre/software".into(),
                    description: Some("Malware & tools".into()),
                },
                Completion {
                    value: "redblue://intel/mitre/mitigations".into(),
                    description: Some("Defensive mitigations".into()),
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // SYSTEM RESOURCES
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://system/".into(),
            description: "System information".into(),
            completions: vec![
                Completion {
                    value: "redblue://system/info".into(),
                    description: Some("System information".into()),
                },
                Completion {
                    value: "redblue://system/config".into(),
                    description: Some("Current configuration".into()),
                },
                Completion {
                    value: "redblue://system/history".into(),
                    description: Some("Command history".into()),
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // REFERENCE DATA
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://reference/".into(),
            description: "Reference data".into(),
            completions: vec![
                Completion {
                    value: "redblue://reference/ports".into(),
                    description: Some("Common ports reference".into()),
                },
                Completion {
                    value: "redblue://reference/cwe-top25".into(),
                    description: Some("CWE Top 25 list".into()),
                },
                Completion {
                    value: "redblue://reference/owasp-top10".into(),
                    description: Some("OWASP Top 10 list".into()),
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // SCAN RESOURCES
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://scan/".into(),
            description: "Scan results and live data".into(),
            completions: vec![
                Completion {
                    value: "redblue://scan/ports/".into(),
                    description: Some("Port scan results".into()),
                },
                Completion {
                    value: "redblue://scan/dns/".into(),
                    description: Some("DNS lookup results".into()),
                },
                Completion {
                    value: "redblue://scan/tls/".into(),
                    description: Some("TLS scan results".into()),
                },
                Completion {
                    value: "redblue://scan/subdomains/".into(),
                    description: Some("Subdomain enumeration".into()),
                },
                Completion {
                    value: "redblue://scan/http/".into(),
                    description: Some("HTTP response data".into()),
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // WHOIS RESOURCES
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://whois/".into(),
            description: "WHOIS lookup data".into(),
            completions: vec![Completion {
                value: "redblue://whois/example.com".into(),
                description: Some("Lookup domain registration".into()),
            }],
        });

        // ═══════════════════════════════════════════════════════════════════
        // SESSIONS & PLAYBOOKS
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://sessions/".into(),
            description: "Session management".into(),
            completions: vec![
                Completion {
                    value: "redblue://sessions/active".into(),
                    description: Some("Currently active sessions".into()),
                },
                Completion {
                    value: "redblue://sessions/history".into(),
                    description: Some("Session history".into()),
                },
            ],
        });

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://playbooks/".into(),
            description: "Automation playbooks".into(),
            completions: vec![
                Completion {
                    value: "redblue://playbooks/index".into(),
                    description: Some("Available playbooks".into()),
                },
                Completion {
                    value: "redblue://playbooks/running".into(),
                    description: Some("Currently running playbooks".into()),
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // SIGNATURES
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://signatures/".into(),
            description: "Detection signatures".into(),
            completions: vec![
                Completion {
                    value: "redblue://signatures/services".into(),
                    description: Some("Service fingerprints".into()),
                },
                Completion {
                    value: "redblue://signatures/os".into(),
                    description: Some("OS fingerprints".into()),
                },
                Completion {
                    value: "redblue://signatures/cms".into(),
                    description: Some("CMS fingerprints".into()),
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // SEARCH
        // ═══════════════════════════════════════════════════════════════════

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://search/".into(),
            description: "Semantic search".into(),
            completions: vec![Completion {
                value: "redblue://search/index".into(),
                description: Some("Search index status".into()),
            }],
        });

        self.resource_prefixes.push(ResourcePrefix {
            prefix: "redblue://similar/".into(),
            description: "Similarity search".into(),
            completions: vec![
                Completion {
                    value: "redblue://similar/cve/".into(),
                    description: Some("Find similar CVEs".into()),
                },
                Completion {
                    value: "redblue://similar/technique/".into(),
                    description: Some("Find similar techniques".into()),
                },
            ],
        });
    }

    fn register_prompt_values(&mut self) {
        // ═══════════════════════════════════════════════════════════════════
        // COMMON VALUES
        // ═══════════════════════════════════════════════════════════════════

        // Scope values
        self.prompt_values.insert(
            "scope".into(),
            vec![
                Completion {
                    value: "passive".into(),
                    description: Some("Passive reconnaissance only".into()),
                },
                Completion {
                    value: "active".into(),
                    description: Some("Active scanning allowed".into()),
                },
                Completion {
                    value: "full".into(),
                    description: Some("Full scope - all methods".into()),
                },
                Completion {
                    value: "quick".into(),
                    description: Some("Quick scan".into()),
                },
                Completion {
                    value: "standard".into(),
                    description: Some("Standard depth".into()),
                },
                Completion {
                    value: "deep".into(),
                    description: Some("Deep enumeration".into()),
                },
            ],
        );

        // Cloud providers
        self.prompt_values.insert(
            "provider".into(),
            vec![
                Completion {
                    value: "aws".into(),
                    description: Some("Amazon Web Services".into()),
                },
                Completion {
                    value: "azure".into(),
                    description: Some("Microsoft Azure".into()),
                },
                Completion {
                    value: "gcp".into(),
                    description: Some("Google Cloud Platform".into()),
                },
                Completion {
                    value: "multi".into(),
                    description: Some("Multi-cloud environment".into()),
                },
            ],
        );

        // Compliance frameworks
        self.prompt_values.insert(
            "compliance".into(),
            vec![
                Completion {
                    value: "cis".into(),
                    description: Some("CIS Benchmarks".into()),
                },
                Completion {
                    value: "soc2".into(),
                    description: Some("SOC 2 Type II".into()),
                },
                Completion {
                    value: "hipaa".into(),
                    description: Some("HIPAA Security Rule".into()),
                },
                Completion {
                    value: "pci".into(),
                    description: Some("PCI DSS".into()),
                },
                Completion {
                    value: "nist".into(),
                    description: Some("NIST 800-53".into()),
                },
                Completion {
                    value: "iso27001".into(),
                    description: Some("ISO 27001".into()),
                },
            ],
        );

        // Platforms
        self.prompt_values.insert(
            "platform".into(),
            vec![
                Completion {
                    value: "android".into(),
                    description: Some("Android platform".into()),
                },
                Completion {
                    value: "ios".into(),
                    description: Some("iOS platform".into()),
                },
                Completion {
                    value: "both".into(),
                    description: Some("Both platforms".into()),
                },
            ],
        );

        // Auth types
        self.prompt_values.insert(
            "auth_type".into(),
            vec![
                Completion {
                    value: "oauth2".into(),
                    description: Some("OAuth 2.0".into()),
                },
                Completion {
                    value: "apikey".into(),
                    description: Some("API Key".into()),
                },
                Completion {
                    value: "jwt".into(),
                    description: Some("JSON Web Token".into()),
                },
                Completion {
                    value: "basic".into(),
                    description: Some("Basic Auth".into()),
                },
                Completion {
                    value: "bearer".into(),
                    description: Some("Bearer Token".into()),
                },
            ],
        );

        // Output formats
        self.prompt_values.insert(
            "format".into(),
            vec![
                Completion {
                    value: "json".into(),
                    description: Some("JSON format".into()),
                },
                Completion {
                    value: "markdown".into(),
                    description: Some("Markdown format".into()),
                },
                Completion {
                    value: "navigator".into(),
                    description: Some("ATT&CK Navigator".into()),
                },
                Completion {
                    value: "executive".into(),
                    description: Some("Executive summary".into()),
                },
                Completion {
                    value: "technical".into(),
                    description: Some("Technical detail".into()),
                },
                Completion {
                    value: "full".into(),
                    description: Some("Full report".into()),
                },
            ],
        );

        // Detection rule formats
        self.prompt_values.insert(
            "rule_format".into(),
            vec![
                Completion {
                    value: "sigma".into(),
                    description: Some("Sigma rules".into()),
                },
                Completion {
                    value: "yara".into(),
                    description: Some("YARA rules".into()),
                },
                Completion {
                    value: "snort".into(),
                    description: Some("Snort/Suricata".into()),
                },
                Completion {
                    value: "splunk".into(),
                    description: Some("Splunk SPL".into()),
                },
            ],
        );

        // Operating systems
        self.prompt_values.insert(
            "target_os".into(),
            vec![
                Completion {
                    value: "linux".into(),
                    description: Some("Linux systems".into()),
                },
                Completion {
                    value: "windows".into(),
                    description: Some("Windows systems".into()),
                },
                Completion {
                    value: "macos".into(),
                    description: Some("macOS systems".into()),
                },
                Completion {
                    value: "unknown".into(),
                    description: Some("Unknown OS".into()),
                },
            ],
        );

        // Access levels
        self.prompt_values.insert(
            "access_level".into(),
            vec![
                Completion {
                    value: "user".into(),
                    description: Some("Standard user".into()),
                },
                Completion {
                    value: "admin".into(),
                    description: Some("Administrator".into()),
                },
                Completion {
                    value: "root".into(),
                    description: Some("Root/SYSTEM".into()),
                },
            ],
        );

        // Stealth levels
        self.prompt_values.insert(
            "stealth".into(),
            vec![
                Completion {
                    value: "low".into(),
                    description: Some("Low stealth - fast".into()),
                },
                Completion {
                    value: "medium".into(),
                    description: Some("Balanced approach".into()),
                },
                Completion {
                    value: "high".into(),
                    description: Some("Maximum stealth".into()),
                },
            ],
        );

        // Container runtimes
        self.prompt_values.insert(
            "runtime".into(),
            vec![
                Completion {
                    value: "docker".into(),
                    description: Some("Docker runtime".into()),
                },
                Completion {
                    value: "containerd".into(),
                    description: Some("containerd runtime".into()),
                },
                Completion {
                    value: "cri-o".into(),
                    description: Some("CRI-O runtime".into()),
                },
                Completion {
                    value: "podman".into(),
                    description: Some("Podman runtime".into()),
                },
            ],
        );

        // K8s focus areas
        self.prompt_values.insert(
            "k8s_focus".into(),
            vec![
                Completion {
                    value: "rbac".into(),
                    description: Some("RBAC analysis".into()),
                },
                Completion {
                    value: "network".into(),
                    description: Some("Network policies".into()),
                },
                Completion {
                    value: "pods".into(),
                    description: Some("Pod security".into()),
                },
                Completion {
                    value: "secrets".into(),
                    description: Some("Secrets management".into()),
                },
                Completion {
                    value: "ingress".into(),
                    description: Some("Ingress configuration".into()),
                },
                Completion {
                    value: "full".into(),
                    description: Some("Full assessment".into()),
                },
            ],
        );

        // VPN protocols
        self.prompt_values.insert(
            "protocol".into(),
            vec![
                Completion {
                    value: "ipsec".into(),
                    description: Some("IPSec VPN".into()),
                },
                Completion {
                    value: "openvpn".into(),
                    description: Some("OpenVPN".into()),
                },
                Completion {
                    value: "wireguard".into(),
                    description: Some("WireGuard".into()),
                },
                Completion {
                    value: "l2tp".into(),
                    description: Some("L2TP/IPSec".into()),
                },
            ],
        );

        // Firewall vendors
        self.prompt_values.insert(
            "vendor".into(),
            vec![
                Completion {
                    value: "palo".into(),
                    description: Some("Palo Alto Networks".into()),
                },
                Completion {
                    value: "cisco".into(),
                    description: Some("Cisco ASA/FTD".into()),
                },
                Completion {
                    value: "fortinet".into(),
                    description: Some("Fortinet FortiGate".into()),
                },
                Completion {
                    value: "checkpoint".into(),
                    description: Some("Check Point".into()),
                },
                Completion {
                    value: "aws".into(),
                    description: Some("AWS Security Groups".into()),
                },
                Completion {
                    value: "azure".into(),
                    description: Some("Azure NSG".into()),
                },
            ],
        );

        // Identity providers
        self.prompt_values.insert(
            "idp".into(),
            vec![
                Completion {
                    value: "ad".into(),
                    description: Some("Active Directory".into()),
                },
                Completion {
                    value: "azure_ad".into(),
                    description: Some("Azure AD / Entra ID".into()),
                },
                Completion {
                    value: "okta".into(),
                    description: Some("Okta".into()),
                },
                Completion {
                    value: "ping".into(),
                    description: Some("Ping Identity".into()),
                },
                Completion {
                    value: "onelogin".into(),
                    description: Some("OneLogin".into()),
                },
            ],
        );

        // Zero Trust maturity
        self.prompt_values.insert(
            "maturity".into(),
            vec![
                Completion {
                    value: "initial".into(),
                    description: Some("Initial stage".into()),
                },
                Completion {
                    value: "developing".into(),
                    description: Some("Developing".into()),
                },
                Completion {
                    value: "defined".into(),
                    description: Some("Defined processes".into()),
                },
                Completion {
                    value: "managed".into(),
                    description: Some("Managed & measured".into()),
                },
                Completion {
                    value: "optimizing".into(),
                    description: Some("Continuously optimizing".into()),
                },
            ],
        );

        // Incident types
        self.prompt_values.insert(
            "incident_type".into(),
            vec![
                Completion {
                    value: "malware".into(),
                    description: Some("Malware infection".into()),
                },
                Completion {
                    value: "ransomware".into(),
                    description: Some("Ransomware attack".into()),
                },
                Completion {
                    value: "breach".into(),
                    description: Some("Data breach".into()),
                },
                Completion {
                    value: "phishing".into(),
                    description: Some("Phishing attack".into()),
                },
                Completion {
                    value: "ddos".into(),
                    description: Some("DDoS attack".into()),
                },
                Completion {
                    value: "insider".into(),
                    description: Some("Insider threat".into()),
                },
            ],
        );

        // Attack objectives
        self.prompt_values.insert(
            "objective".into(),
            vec![
                Completion {
                    value: "initial_access".into(),
                    description: Some("Gain initial access".into()),
                },
                Completion {
                    value: "persistence".into(),
                    description: Some("Establish persistence".into()),
                },
                Completion {
                    value: "privilege_escalation".into(),
                    description: Some("Escalate privileges".into()),
                },
                Completion {
                    value: "lateral_movement".into(),
                    description: Some("Move laterally".into()),
                },
                Completion {
                    value: "exfiltration".into(),
                    description: Some("Exfiltrate data".into()),
                },
                Completion {
                    value: "impact".into(),
                    description: Some("Cause impact".into()),
                },
            ],
        );
    }

    /// Get completions for a resource URI prefix
    pub fn complete_resource(&self, uri_prefix: &str) -> Vec<Completion> {
        let mut results = Vec::new();

        // If empty or just "redblue://", return top-level prefixes
        if uri_prefix.is_empty() || uri_prefix == "redblue://" {
            return vec![
                Completion {
                    value: "redblue://intel/".into(),
                    description: Some("Threat intelligence".into()),
                },
                Completion {
                    value: "redblue://system/".into(),
                    description: Some("System info".into()),
                },
                Completion {
                    value: "redblue://reference/".into(),
                    description: Some("Reference data".into()),
                },
                Completion {
                    value: "redblue://scan/".into(),
                    description: Some("Scan results".into()),
                },
                Completion {
                    value: "redblue://whois/".into(),
                    description: Some("WHOIS lookups".into()),
                },
                Completion {
                    value: "redblue://sessions/".into(),
                    description: Some("Sessions".into()),
                },
                Completion {
                    value: "redblue://playbooks/".into(),
                    description: Some("Playbooks".into()),
                },
                Completion {
                    value: "redblue://signatures/".into(),
                    description: Some("Signatures".into()),
                },
                Completion {
                    value: "redblue://search/".into(),
                    description: Some("Semantic search".into()),
                },
                Completion {
                    value: "redblue://similar/".into(),
                    description: Some("Similarity".into()),
                },
            ];
        }

        // Find matching prefixes
        for prefix in &self.resource_prefixes {
            if prefix.prefix.starts_with(uri_prefix) {
                // Prefix itself is a completion
                results.push(Completion {
                    value: prefix.prefix.clone(),
                    description: Some(prefix.description.clone()),
                });
            } else if uri_prefix.starts_with(&prefix.prefix) {
                // We're inside this prefix, return its completions
                for completion in &prefix.completions {
                    if completion.value.starts_with(uri_prefix) {
                        results.push(completion.clone());
                    }
                }
            }
        }

        results
    }

    /// Get completions for a prompt argument
    pub fn complete_prompt_argument(
        &self,
        prompt_name: &str,
        argument: &str,
        value_prefix: &str,
    ) -> Vec<Completion> {
        // Try to find known values for this argument
        if let Some(values) = self.prompt_values.get(argument) {
            return values
                .iter()
                .filter(|v| v.value.starts_with(value_prefix))
                .cloned()
                .collect();
        }

        // Prompt-specific completions
        match (prompt_name, argument) {
            ("aws-security", "services") => {
                vec![
                    Completion {
                        value: "s3".into(),
                        description: Some("S3 storage".into()),
                    },
                    Completion {
                        value: "ec2".into(),
                        description: Some("EC2 compute".into()),
                    },
                    Completion {
                        value: "iam".into(),
                        description: Some("IAM".into()),
                    },
                    Completion {
                        value: "lambda".into(),
                        description: Some("Lambda functions".into()),
                    },
                    Completion {
                        value: "rds".into(),
                        description: Some("RDS databases".into()),
                    },
                    Completion {
                        value: "all".into(),
                        description: Some("All services".into()),
                    },
                ]
            }
            ("gcp-security", "services") => {
                vec![
                    Completion {
                        value: "gcs".into(),
                        description: Some("Cloud Storage".into()),
                    },
                    Completion {
                        value: "gce".into(),
                        description: Some("Compute Engine".into()),
                    },
                    Completion {
                        value: "iam".into(),
                        description: Some("IAM".into()),
                    },
                    Completion {
                        value: "functions".into(),
                        description: Some("Cloud Functions".into()),
                    },
                    Completion {
                        value: "gke".into(),
                        description: Some("Kubernetes Engine".into()),
                    },
                    Completion {
                        value: "all".into(),
                        description: Some("All services".into()),
                    },
                ]
            }
            ("azure-security", "focus") => {
                vec![
                    Completion {
                        value: "identity".into(),
                        description: Some("Azure AD/Identity".into()),
                    },
                    Completion {
                        value: "network".into(),
                        description: Some("Networking".into()),
                    },
                    Completion {
                        value: "storage".into(),
                        description: Some("Storage accounts".into()),
                    },
                    Completion {
                        value: "compute".into(),
                        description: Some("VMs/containers".into()),
                    },
                    Completion {
                        value: "full".into(),
                        description: Some("Full assessment".into()),
                    },
                ]
            }
            ("k8s-security", "namespace") => {
                vec![
                    Completion {
                        value: "default".into(),
                        description: Some("Default namespace".into()),
                    },
                    Completion {
                        value: "kube-system".into(),
                        description: Some("System namespace".into()),
                    },
                    Completion {
                        value: "all".into(),
                        description: Some("All namespaces".into()),
                    },
                ]
            }
            ("oauth-audit", "flows") => {
                vec![
                    Completion {
                        value: "authorization_code".into(),
                        description: Some("Auth code flow".into()),
                    },
                    Completion {
                        value: "implicit".into(),
                        description: Some("Implicit flow".into()),
                    },
                    Completion {
                        value: "client_credentials".into(),
                        description: Some("Client credentials".into()),
                    },
                    Completion {
                        value: "device_code".into(),
                        description: Some("Device code flow".into()),
                    },
                    Completion {
                        value: "pkce".into(),
                        description: Some("PKCE enhanced".into()),
                    },
                ]
            }
            _ => {
                // No specific completions available
                Vec::new()
            }
        }
    }

    /// Handle MCP completion/complete request
    pub fn complete(&self, reference: &CompletionRef) -> Vec<Completion> {
        match reference {
            CompletionRef::Resource { uri } => self.complete_resource(uri),
            CompletionRef::PromptArgument { name, argument } => {
                self.complete_prompt_argument(name, argument, "")
            }
        }
    }
}

impl Default for CompletionProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_completions() {
        let provider = CompletionProvider::new();

        // Top-level completions
        let completions = provider.complete_resource("");
        assert!(!completions.is_empty());
        assert!(completions.iter().any(|c| c.value.contains("intel")));

        // Intel completions
        let completions = provider.complete_resource("redblue://intel/");
        assert!(!completions.is_empty());
        assert!(completions.iter().any(|c| c.value.contains("mitre")));

        // MITRE completions
        let completions = provider.complete_resource("redblue://intel/mitre/");
        assert!(!completions.is_empty());
        assert!(completions.iter().any(|c| c.value.contains("tactics")));
    }

    #[test]
    fn test_prompt_argument_completions() {
        let provider = CompletionProvider::new();

        // Provider completions
        let completions = provider.complete_prompt_argument("cloud-audit", "provider", "");
        assert!(!completions.is_empty());
        assert!(completions.iter().any(|c| c.value == "aws"));
        assert!(completions.iter().any(|c| c.value == "azure"));
        assert!(completions.iter().any(|c| c.value == "gcp"));

        // Compliance completions
        let completions = provider.complete_prompt_argument("", "compliance", "");
        assert!(completions.iter().any(|c| c.value == "cis"));
        assert!(completions.iter().any(|c| c.value == "soc2"));
    }
}
