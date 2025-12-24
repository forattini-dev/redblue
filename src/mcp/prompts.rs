//! MCP Prompts - Pre-built security prompt templates
//!
//! Prompts provide structured templates for common security tasks
//! that can be invoked by LLMs with optional arguments.

/// A prompt template definition
#[derive(Debug, Clone)]
pub struct Prompt {
    /// Unique identifier for the prompt
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Arguments the prompt accepts
    pub arguments: Vec<PromptArgument>,
}

/// An argument for a prompt
#[derive(Debug, Clone)]
pub struct PromptArgument {
    /// Argument name
    pub name: String,
    /// Description of the argument
    pub description: String,
    /// Whether this argument is required
    pub required: bool,
}

/// A message in a prompt response
#[derive(Debug, Clone)]
pub struct PromptMessage {
    /// Role: "user" or "assistant"
    pub role: String,
    /// Content of the message
    pub content: String,
}

/// Result of getting a prompt
#[derive(Debug, Clone)]
pub struct PromptResult {
    /// Description of the prompt
    pub description: String,
    /// Messages to send
    pub messages: Vec<PromptMessage>,
}

/// Prompt registry - manages all available prompts
pub struct PromptRegistry {
    prompts: Vec<Prompt>,
}

impl PromptRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            prompts: Vec::new(),
        };
        registry.register_all();
        registry
    }

    fn register_all(&mut self) {
        // ═══════════════════════════════════════════════════════════════════
        // RECONNAISSANCE PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "recon-strategy".into(),
            description: "Plan a comprehensive reconnaissance strategy for a target".into(),
            arguments: vec![
                PromptArgument {
                    name: "target".into(),
                    description: "Target domain, IP, or organization name".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Scope: passive, active, or full".into(),
                    required: false,
                },
                PromptArgument {
                    name: "time_limit".into(),
                    description: "Time limit for the engagement".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "subdomain-hunt".into(),
            description: "Enumerate and analyze subdomains for a target domain".into(),
            arguments: vec![
                PromptArgument {
                    name: "domain".into(),
                    description: "Target domain to enumerate".into(),
                    required: true,
                },
                PromptArgument {
                    name: "depth".into(),
                    description: "Enumeration depth: quick, standard, or deep".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // VULNERABILITY ASSESSMENT PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "vuln-assessment".into(),
            description: "Perform vulnerability assessment and prioritization".into(),
            arguments: vec![
                PromptArgument {
                    name: "target".into(),
                    description: "Target to assess (URL, IP, or domain)".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scan_data".into(),
                    description: "Previous scan results to analyze".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "cve-analysis".into(),
            description: "Deep analysis of a specific CVE and its impact".into(),
            arguments: vec![
                PromptArgument {
                    name: "cve_id".into(),
                    description: "CVE identifier (e.g., CVE-2024-1234)".into(),
                    required: true,
                },
                PromptArgument {
                    name: "context".into(),
                    description: "Context about the target environment".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "patch-priority".into(),
            description: "Prioritize patches based on risk and exploitability".into(),
            arguments: vec![
                PromptArgument {
                    name: "vulns".into(),
                    description: "List of vulnerabilities to prioritize".into(),
                    required: true,
                },
                PromptArgument {
                    name: "environment".into(),
                    description: "Environment type: production, staging, dev".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // ATTACK PLANNING PROMPTS (AUTHORIZED USE ONLY)
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "attack-plan".into(),
            description: "Generate attack plan based on reconnaissance data (AUTHORIZED USE ONLY)"
                .into(),
            arguments: vec![
                PromptArgument {
                    name: "target".into(),
                    description: "Target information and scope".into(),
                    required: true,
                },
                PromptArgument {
                    name: "findings".into(),
                    description: "Reconnaissance findings (ports, services, vulns)".into(),
                    required: true,
                },
                PromptArgument {
                    name: "objective".into(),
                    description: "Attack objective: initial_access, persistence, exfil, etc."
                        .into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "exploit-suggest".into(),
            description: "Suggest exploits for identified vulnerabilities".into(),
            arguments: vec![
                PromptArgument {
                    name: "vulnerabilities".into(),
                    description: "List of CVEs or vulnerability descriptions".into(),
                    required: true,
                },
                PromptArgument {
                    name: "target_os".into(),
                    description: "Target operating system".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "lateral-movement".into(),
            description: "Plan lateral movement based on network position".into(),
            arguments: vec![
                PromptArgument {
                    name: "current_access".into(),
                    description: "Current access level and position".into(),
                    required: true,
                },
                PromptArgument {
                    name: "network_map".into(),
                    description: "Known network topology".into(),
                    required: false,
                },
                PromptArgument {
                    name: "credentials".into(),
                    description: "Available credentials".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "persistence-analysis".into(),
            description: "Analyze and suggest persistence mechanisms".into(),
            arguments: vec![
                PromptArgument {
                    name: "target_os".into(),
                    description: "Target operating system".into(),
                    required: true,
                },
                PromptArgument {
                    name: "access_level".into(),
                    description: "Current access level: user, admin, root".into(),
                    required: true,
                },
                PromptArgument {
                    name: "stealth".into(),
                    description: "Stealth requirement: low, medium, high".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // DEFENSE & BLUE TEAM PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "threat-model".into(),
            description: "Create threat model for an application or system".into(),
            arguments: vec![
                PromptArgument {
                    name: "system".into(),
                    description: "System or application description".into(),
                    required: true,
                },
                PromptArgument {
                    name: "assets".into(),
                    description: "Critical assets to protect".into(),
                    required: false,
                },
                PromptArgument {
                    name: "threat_actors".into(),
                    description: "Relevant threat actors".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "incident-response".into(),
            description: "Guide incident response for a security event".into(),
            arguments: vec![
                PromptArgument {
                    name: "incident_type".into(),
                    description: "Type: malware, ransomware, breach, phishing, etc.".into(),
                    required: true,
                },
                PromptArgument {
                    name: "indicators".into(),
                    description: "Known indicators of compromise".into(),
                    required: false,
                },
                PromptArgument {
                    name: "affected_systems".into(),
                    description: "Systems known to be affected".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "detection-rules".into(),
            description: "Generate detection rules for threats".into(),
            arguments: vec![
                PromptArgument {
                    name: "threat".into(),
                    description: "Threat to detect (technique, malware, behavior)".into(),
                    required: true,
                },
                PromptArgument {
                    name: "format".into(),
                    description: "Rule format: sigma, yara, snort, splunk".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "hardening-guide".into(),
            description: "Generate system hardening recommendations".into(),
            arguments: vec![
                PromptArgument {
                    name: "system".into(),
                    description: "System to harden (OS, service, application)".into(),
                    required: true,
                },
                PromptArgument {
                    name: "baseline".into(),
                    description: "Baseline standard: CIS, STIG, NIST".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // REPORTING PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "pentest-report".into(),
            description: "Generate penetration test report from findings".into(),
            arguments: vec![
                PromptArgument {
                    name: "findings".into(),
                    description: "All findings from the engagement".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Engagement scope and rules".into(),
                    required: true,
                },
                PromptArgument {
                    name: "format".into(),
                    description: "Report format: executive, technical, full".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "executive-summary".into(),
            description: "Create executive summary from technical findings".into(),
            arguments: vec![
                PromptArgument {
                    name: "findings".into(),
                    description: "Technical findings to summarize".into(),
                    required: true,
                },
                PromptArgument {
                    name: "audience".into(),
                    description: "Target audience: c-suite, board, technical".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "risk-matrix".into(),
            description: "Generate risk matrix from vulnerabilities".into(),
            arguments: vec![
                PromptArgument {
                    name: "vulnerabilities".into(),
                    description: "List of vulnerabilities with details".into(),
                    required: true,
                },
                PromptArgument {
                    name: "business_context".into(),
                    description: "Business context for impact assessment".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // COMPLIANCE PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "compliance-check".into(),
            description: "Check compliance against security standards".into(),
            arguments: vec![
                PromptArgument {
                    name: "standard".into(),
                    description: "Standard: PCI-DSS, HIPAA, SOC2, ISO27001, NIST".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Systems or processes to check".into(),
                    required: true,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "gap-analysis".into(),
            description: "Perform security gap analysis".into(),
            arguments: vec![
                PromptArgument {
                    name: "current_state".into(),
                    description: "Current security posture".into(),
                    required: true,
                },
                PromptArgument {
                    name: "target_state".into(),
                    description: "Desired security posture or standard".into(),
                    required: true,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // MITRE ATT&CK PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "mitre-mapping".into(),
            description: "Map findings to MITRE ATT&CK techniques".into(),
            arguments: vec![
                PromptArgument {
                    name: "findings".into(),
                    description: "Security findings to map".into(),
                    required: true,
                },
                PromptArgument {
                    name: "format".into(),
                    description: "Output format: navigator, json, markdown".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "attack-simulation".into(),
            description: "Design attack simulation based on threat actor TTPs".into(),
            arguments: vec![
                PromptArgument {
                    name: "threat_actor".into(),
                    description: "Threat actor or group to emulate".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Simulation scope and constraints".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // OSINT PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "osint-profile".into(),
            description: "Build OSINT profile for a target".into(),
            arguments: vec![
                PromptArgument {
                    name: "target".into(),
                    description: "Target: person, organization, or domain".into(),
                    required: true,
                },
                PromptArgument {
                    name: "depth".into(),
                    description: "Investigation depth: surface, moderate, deep".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "attack-surface".into(),
            description: "Map external attack surface for an organization".into(),
            arguments: vec![
                PromptArgument {
                    name: "organization".into(),
                    description: "Organization name or primary domain".into(),
                    required: true,
                },
                PromptArgument {
                    name: "include_subsidiaries".into(),
                    description: "Include subsidiaries and acquisitions".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // CLOUD SECURITY PROMPTS
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "cloud-audit".into(),
            description: "Comprehensive cloud infrastructure security audit".into(),
            arguments: vec![
                PromptArgument {
                    name: "provider".into(),
                    description: "Cloud provider: aws, azure, gcp, multi".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Audit scope: full, iam, network, storage, compute".into(),
                    required: false,
                },
                PromptArgument {
                    name: "compliance".into(),
                    description: "Compliance framework: cis, soc2, hipaa, pci".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "aws-security".into(),
            description: "AWS-specific security assessment and hardening".into(),
            arguments: vec![
                PromptArgument {
                    name: "account_id".into(),
                    description: "AWS account ID or alias".into(),
                    required: true,
                },
                PromptArgument {
                    name: "services".into(),
                    description: "Services to audit: s3, ec2, iam, lambda, rds, etc.".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "azure-security".into(),
            description: "Azure-specific security assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "subscription".into(),
                    description: "Azure subscription ID or name".into(),
                    required: true,
                },
                PromptArgument {
                    name: "focus".into(),
                    description: "Focus area: identity, network, storage, compute".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "gcp-security".into(),
            description: "GCP-specific security assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "project".into(),
                    description: "GCP project ID".into(),
                    required: true,
                },
                PromptArgument {
                    name: "services".into(),
                    description: "Services to audit: gcs, gce, iam, functions, etc.".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "s3-audit".into(),
            description: "AWS S3 bucket security audit".into(),
            arguments: vec![
                PromptArgument {
                    name: "bucket".into(),
                    description: "S3 bucket name or pattern".into(),
                    required: true,
                },
                PromptArgument {
                    name: "deep_scan".into(),
                    description: "Perform deep content analysis".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // CONTAINER & KUBERNETES SECURITY
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "container-security".into(),
            description: "Container image and runtime security assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "image".into(),
                    description: "Container image name or registry path".into(),
                    required: true,
                },
                PromptArgument {
                    name: "runtime".into(),
                    description: "Container runtime: docker, containerd, cri-o".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "k8s-security".into(),
            description: "Kubernetes cluster security assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "cluster".into(),
                    description: "Cluster name or context".into(),
                    required: true,
                },
                PromptArgument {
                    name: "namespace".into(),
                    description: "Specific namespace to audit (or 'all')".into(),
                    required: false,
                },
                PromptArgument {
                    name: "focus".into(),
                    description: "Focus: rbac, network, pods, secrets, ingress".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "dockerfile-review".into(),
            description: "Security review of Dockerfile".into(),
            arguments: vec![
                PromptArgument {
                    name: "dockerfile".into(),
                    description: "Dockerfile content or path".into(),
                    required: true,
                },
                PromptArgument {
                    name: "base_image".into(),
                    description: "Base image being used".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "helm-security".into(),
            description: "Helm chart security review".into(),
            arguments: vec![
                PromptArgument {
                    name: "chart".into(),
                    description: "Helm chart name or path".into(),
                    required: true,
                },
                PromptArgument {
                    name: "values".into(),
                    description: "Values file content".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // API SECURITY TESTING
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "api-security".into(),
            description: "API security assessment and testing strategy".into(),
            arguments: vec![
                PromptArgument {
                    name: "api_spec".into(),
                    description: "OpenAPI/Swagger spec URL or content".into(),
                    required: true,
                },
                PromptArgument {
                    name: "auth_type".into(),
                    description: "Authentication: oauth2, apikey, jwt, basic".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "graphql-security".into(),
            description: "GraphQL API security testing".into(),
            arguments: vec![
                PromptArgument {
                    name: "endpoint".into(),
                    description: "GraphQL endpoint URL".into(),
                    required: true,
                },
                PromptArgument {
                    name: "schema".into(),
                    description: "GraphQL schema (if available)".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "oauth-audit".into(),
            description: "OAuth/OIDC implementation security review".into(),
            arguments: vec![
                PromptArgument {
                    name: "provider".into(),
                    description: "OAuth provider or implementation".into(),
                    required: true,
                },
                PromptArgument {
                    name: "flows".into(),
                    description:
                        "OAuth flows used: authorization_code, implicit, client_credentials".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "jwt-analysis".into(),
            description: "JWT token security analysis".into(),
            arguments: vec![
                PromptArgument {
                    name: "token".into(),
                    description: "JWT token to analyze".into(),
                    required: true,
                },
                PromptArgument {
                    name: "context".into(),
                    description: "Usage context and expected claims".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // MOBILE APPLICATION SECURITY
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "mobile-security".into(),
            description: "Mobile application security assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "platform".into(),
                    description: "Platform: android, ios, both".into(),
                    required: true,
                },
                PromptArgument {
                    name: "app_name".into(),
                    description: "Application name or package ID".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Scope: static, dynamic, full".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "android-security".into(),
            description: "Android-specific security testing".into(),
            arguments: vec![
                PromptArgument {
                    name: "apk".into(),
                    description: "APK file path or package name".into(),
                    required: true,
                },
                PromptArgument {
                    name: "manifest".into(),
                    description: "AndroidManifest.xml content".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "ios-security".into(),
            description: "iOS-specific security testing".into(),
            arguments: vec![
                PromptArgument {
                    name: "ipa".into(),
                    description: "IPA file path or bundle ID".into(),
                    required: true,
                },
                PromptArgument {
                    name: "entitlements".into(),
                    description: "App entitlements".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // NETWORK SECURITY
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "network-segmentation".into(),
            description: "Network segmentation analysis and recommendations".into(),
            arguments: vec![
                PromptArgument {
                    name: "topology".into(),
                    description: "Network topology or CIDR ranges".into(),
                    required: true,
                },
                PromptArgument {
                    name: "zones".into(),
                    description: "Security zones: dmz, internal, management, etc.".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "firewall-review".into(),
            description: "Firewall rule set security review".into(),
            arguments: vec![
                PromptArgument {
                    name: "rules".into(),
                    description: "Firewall rules or configuration".into(),
                    required: true,
                },
                PromptArgument {
                    name: "vendor".into(),
                    description: "Firewall vendor: palo, cisco, fortinet, aws, etc.".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "vpn-security".into(),
            description: "VPN configuration security assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "config".into(),
                    description: "VPN configuration or type".into(),
                    required: true,
                },
                PromptArgument {
                    name: "protocol".into(),
                    description: "VPN protocol: ipsec, openvpn, wireguard".into(),
                    required: false,
                },
            ],
        });

        // ═══════════════════════════════════════════════════════════════════
        // ZERO TRUST SECURITY
        // ═══════════════════════════════════════════════════════════════════

        self.prompts.push(Prompt {
            name: "zero-trust-assessment".into(),
            description: "Zero Trust architecture assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "current_state".into(),
                    description: "Current security architecture".into(),
                    required: true,
                },
                PromptArgument {
                    name: "maturity".into(),
                    description:
                        "Target maturity level: initial, developing, defined, managed, optimizing"
                            .into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "identity-security".into(),
            description: "Identity and access management security review".into(),
            arguments: vec![
                PromptArgument {
                    name: "provider".into(),
                    description: "Identity provider: ad, okta, azure_ad, etc.".into(),
                    required: true,
                },
                PromptArgument {
                    name: "scope".into(),
                    description: "Scope: authentication, authorization, governance".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "microsegmentation".into(),
            description: "Microsegmentation strategy and implementation".into(),
            arguments: vec![
                PromptArgument {
                    name: "environment".into(),
                    description: "Environment: cloud, datacenter, hybrid".into(),
                    required: true,
                },
                PromptArgument {
                    name: "workloads".into(),
                    description: "Workload types to segment".into(),
                    required: false,
                },
            ],
        });

        self.prompts.push(Prompt {
            name: "sase-assessment".into(),
            description: "SASE (Secure Access Service Edge) assessment".into(),
            arguments: vec![
                PromptArgument {
                    name: "current_tools".into(),
                    description: "Current security tools and infrastructure".into(),
                    required: true,
                },
                PromptArgument {
                    name: "requirements".into(),
                    description: "Business and security requirements".into(),
                    required: false,
                },
            ],
        });
    }

    /// List all available prompts
    pub fn list_prompts(&self) -> &[Prompt] {
        &self.prompts
    }

    /// Get a specific prompt by name
    pub fn get_prompt(
        &self,
        name: &str,
        args: &std::collections::HashMap<String, String>,
    ) -> Result<PromptResult, String> {
        let prompt = self
            .prompts
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| format!("Unknown prompt: {}", name))?;

        // Validate required arguments
        for arg in &prompt.arguments {
            if arg.required && !args.contains_key(&arg.name) {
                return Err(format!("Missing required argument: {}", arg.name));
            }
        }

        // Generate prompt content
        let content = self.generate_prompt_content(name, args)?;

        Ok(PromptResult {
            description: prompt.description.clone(),
            messages: vec![PromptMessage {
                role: "user".into(),
                content,
            }],
        })
    }

    fn generate_prompt_content(
        &self,
        name: &str,
        args: &std::collections::HashMap<String, String>,
    ) -> Result<String, String> {
        match name {
            "recon-strategy" => Ok(self.gen_recon_strategy(args)),
            "subdomain-hunt" => Ok(self.gen_subdomain_hunt(args)),
            "vuln-assessment" => Ok(self.gen_vuln_assessment(args)),
            "cve-analysis" => Ok(self.gen_cve_analysis(args)),
            "patch-priority" => Ok(self.gen_patch_priority(args)),
            "attack-plan" => Ok(self.gen_attack_plan(args)),
            "exploit-suggest" => Ok(self.gen_exploit_suggest(args)),
            "lateral-movement" => Ok(self.gen_lateral_movement(args)),
            "persistence-analysis" => Ok(self.gen_persistence_analysis(args)),
            "threat-model" => Ok(self.gen_threat_model(args)),
            "incident-response" => Ok(self.gen_incident_response(args)),
            "detection-rules" => Ok(self.gen_detection_rules(args)),
            "hardening-guide" => Ok(self.gen_hardening_guide(args)),
            "pentest-report" => Ok(self.gen_pentest_report(args)),
            "executive-summary" => Ok(self.gen_executive_summary(args)),
            "risk-matrix" => Ok(self.gen_risk_matrix(args)),
            "compliance-check" => Ok(self.gen_compliance_check(args)),
            "gap-analysis" => Ok(self.gen_gap_analysis(args)),
            "mitre-mapping" => Ok(self.gen_mitre_mapping(args)),
            "attack-simulation" => Ok(self.gen_attack_simulation(args)),
            "osint-profile" => Ok(self.gen_osint_profile(args)),
            "attack-surface" => Ok(self.gen_attack_surface(args)),
            // Cloud Security
            "cloud-audit" => Ok(self.gen_cloud_audit(args)),
            "aws-security" => Ok(self.gen_aws_security(args)),
            "azure-security" => Ok(self.gen_azure_security(args)),
            "gcp-security" => Ok(self.gen_gcp_security(args)),
            "s3-audit" => Ok(self.gen_s3_audit(args)),
            // Container & Kubernetes
            "container-security" => Ok(self.gen_container_security(args)),
            "k8s-security" => Ok(self.gen_k8s_security(args)),
            "dockerfile-review" => Ok(self.gen_dockerfile_review(args)),
            "helm-security" => Ok(self.gen_helm_security(args)),
            // API Security
            "api-security" => Ok(self.gen_api_security(args)),
            "graphql-security" => Ok(self.gen_graphql_security(args)),
            "oauth-audit" => Ok(self.gen_oauth_audit(args)),
            "jwt-analysis" => Ok(self.gen_jwt_analysis(args)),
            // Mobile Security
            "mobile-security" => Ok(self.gen_mobile_security(args)),
            "android-security" => Ok(self.gen_android_security(args)),
            "ios-security" => Ok(self.gen_ios_security(args)),
            // Network Security
            "network-segmentation" => Ok(self.gen_network_segmentation(args)),
            "firewall-review" => Ok(self.gen_firewall_review(args)),
            "vpn-security" => Ok(self.gen_vpn_security(args)),
            // Zero Trust
            "zero-trust-assessment" => Ok(self.gen_zero_trust_assessment(args)),
            "identity-security" => Ok(self.gen_identity_security(args)),
            "microsegmentation" => Ok(self.gen_microsegmentation(args)),
            "sase-assessment" => Ok(self.gen_sase_assessment(args)),
            _ => Err(format!("No generator for prompt: {}", name)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PROMPT GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_recon_strategy(&self, args: &std::collections::HashMap<String, String>) -> String {
        let target = args.get("target").map(|s| s.as_str()).unwrap_or("unknown");
        let scope = args.get("scope").map(|s| s.as_str()).unwrap_or("full");
        let time_limit = args
            .get("time_limit")
            .map(|s| s.as_str())
            .unwrap_or("no limit");

        format!(
            r#"# Reconnaissance Strategy Request

## Target
{target}

## Scope
{scope}

## Time Constraints
{time_limit}

---

Please create a comprehensive reconnaissance strategy for this target. Include:

1. **Passive Reconnaissance**
   - DNS enumeration approach
   - WHOIS and registration data
   - Certificate transparency logs
   - Web archives and cached data
   - Social media and OSINT sources
   - Job postings and technology indicators

2. **Active Reconnaissance** (if scope allows)
   - Port scanning strategy
   - Service enumeration
   - Web application discovery
   - Virtual host enumeration
   - Technology fingerprinting

3. **Tools & Commands**
   - Specific redblue commands to run
   - Order of operations
   - Expected outputs

4. **Risk Assessment**
   - Detection likelihood
   - Operational security considerations

Use redblue tool commands where applicable (e.g., `rb network ports scan`, `rb dns record lookup`, `rb recon domain whois`).
"#
        )
    }

    fn gen_subdomain_hunt(&self, args: &std::collections::HashMap<String, String>) -> String {
        let domain = args
            .get("domain")
            .map(|s| s.as_str())
            .unwrap_or("example.com");
        let depth = args.get("depth").map(|s| s.as_str()).unwrap_or("standard");

        format!(
            r#"# Subdomain Enumeration Request

## Target Domain
{domain}

## Enumeration Depth
{depth}

---

Please help me enumerate subdomains for this target. Provide:

1. **Enumeration Strategy**
   - Passive sources to query
   - Active brute-force approach
   - Permutation strategies

2. **Commands to Run**
   ```bash
   rb recon domain subdomains {domain}
   rb dns record lookup {domain} --type NS
   ```

3. **Analysis Framework**
   - How to prioritize interesting subdomains
   - What patterns to look for
   - Red flags and high-value targets

4. **Next Steps**
   - For each discovered subdomain type
   - Port scanning priorities
   - Technology fingerprinting

Focus on finding:
- Development/staging environments
- Admin panels
- API endpoints
- Legacy systems
- Third-party integrations
"#
        )
    }

    fn gen_vuln_assessment(&self, args: &std::collections::HashMap<String, String>) -> String {
        let target = args.get("target").map(|s| s.as_str()).unwrap_or("unknown");
        let scan_data = args
            .get("scan_data")
            .map(|s| s.as_str())
            .unwrap_or("none provided");

        format!(
            r#"# Vulnerability Assessment Request

## Target
{target}

## Previous Scan Data
{scan_data}

---

Please perform a vulnerability assessment. Include:

1. **Technology Stack Analysis**
   - Identify technologies from scan data
   - Map to CPE identifiers
   - Determine version information

2. **Vulnerability Research**
   ```bash
   rb intel vuln search <technology>
   rb intel vuln kev --vendor <vendor>
   rb intel vuln cve <CVE-ID>
   ```

3. **Risk Prioritization**
   - CVSS scores
   - Exploitability (KEV status, public exploits)
   - Business impact
   - Attack surface exposure

4. **Remediation Recommendations**
   - Quick wins
   - Critical patches
   - Configuration changes
   - Compensating controls

5. **Attack Scenarios**
   - How vulnerabilities chain together
   - Most likely attack paths
"#
        )
    }

    fn gen_cve_analysis(&self, args: &std::collections::HashMap<String, String>) -> String {
        let cve_id = args
            .get("cve_id")
            .map(|s| s.as_str())
            .unwrap_or("CVE-XXXX-XXXXX");
        let context = args.get("context").map(|s| s.as_str()).unwrap_or("general");

        format!(
            r#"# CVE Deep Analysis Request

## CVE ID
{cve_id}

## Environment Context
{context}

---

Please provide deep analysis of this CVE:

1. **Vulnerability Details**
   ```bash
   rb intel vuln cve {cve_id}
   ```
   - What is the root cause?
   - What CWE categories apply?
   - Attack vector and complexity

2. **Affected Products**
   - Exact versions affected
   - How to detect vulnerable instances
   - Configuration dependencies

3. **Exploitation Analysis**
   - Is it in CISA KEV?
   - Are public exploits available?
   - What does exploitation look like?
   - Prerequisites for exploitation

4. **Impact Assessment**
   - What can an attacker achieve?
   - Data confidentiality impact
   - System integrity impact
   - Service availability impact

5. **Detection & Response**
   - How to detect exploitation attempts
   - Log entries to look for
   - Network indicators

6. **Remediation**
   - Patches available
   - Workarounds if no patch
   - Timeline recommendations
"#
        )
    }

    fn gen_patch_priority(&self, args: &std::collections::HashMap<String, String>) -> String {
        let vulns = args
            .get("vulns")
            .map(|s| s.as_str())
            .unwrap_or("none listed");
        let environment = args
            .get("environment")
            .map(|s| s.as_str())
            .unwrap_or("production");

        format!(
            r#"# Patch Prioritization Request

## Vulnerabilities
{vulns}

## Environment
{environment}

---

Please prioritize these patches using a risk-based approach:

1. **Priority Matrix**
   | Priority | CVE | CVSS | KEV | Exploit | Exposure | Recommendation |
   |----------|-----|------|-----|---------|----------|----------------|

2. **Scoring Criteria**
   - CVSS base score (1-10)
   - Active exploitation (+3 if KEV)
   - Public exploit available (+2)
   - Internet-facing (+2)
   - Critical system (+2)

3. **Patch Groups**
   - **Emergency (48h)**: Score > 12
   - **Critical (1 week)**: Score 9-12
   - **High (2 weeks)**: Score 6-9
   - **Medium (30 days)**: Score 3-6
   - **Low (90 days)**: Score < 3

4. **Dependencies & Risks**
   - Patch dependencies
   - Reboot requirements
   - Testing recommendations
   - Rollback procedures
"#
        )
    }

    fn gen_attack_plan(&self, args: &std::collections::HashMap<String, String>) -> String {
        let target = args.get("target").map(|s| s.as_str()).unwrap_or("unknown");
        let findings = args.get("findings").map(|s| s.as_str()).unwrap_or("none");
        let objective = args
            .get("objective")
            .map(|s| s.as_str())
            .unwrap_or("initial_access");

        format!(
            r#"# Attack Plan Generation (AUTHORIZED PENTEST ONLY)

## Target
{target}

## Reconnaissance Findings
{findings}

## Objective
{objective}

---

**WARNING: This is for authorized penetration testing only.**

Generate an attack plan with:

1. **Attack Phases** (MITRE ATT&CK mapped)
   - Initial Access techniques
   - Execution methods
   - Persistence options
   - Privilege escalation paths
   - Defense evasion considerations

2. **Attack Path Options**
   | Path | Entry Point | Steps | Likelihood | Impact |
   |------|-------------|-------|------------|--------|

3. **Tool Recommendations**
   ```bash
   rb exploit payload shell <type> <lhost> <lport>
   rb exploit plan generate --target <target>
   ```

4. **Operational Security**
   - Detection risks
   - Log artifacts
   - Cleanup requirements

5. **Contingency Plans**
   - If initial access fails
   - If detected
   - Emergency extraction
"#
        )
    }

    fn gen_exploit_suggest(&self, args: &std::collections::HashMap<String, String>) -> String {
        let vulnerabilities = args
            .get("vulnerabilities")
            .map(|s| s.as_str())
            .unwrap_or("none");
        let target_os = args
            .get("target_os")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        format!(
            r#"# Exploit Suggestion Request

## Identified Vulnerabilities
{vulnerabilities}

## Target OS
{target_os}

---

Please suggest exploits for these vulnerabilities:

1. **Exploit Research**
   ```bash
   rb intel vuln exploit <CVE>
   rb intel vuln search <technology> --source all
   ```

2. **Exploit Matrix**
   | CVE | Exploit | Type | Reliability | Link |
   |-----|---------|------|-------------|------|

3. **Payload Recommendations**
   - For each viable exploit
   - Platform-specific payloads
   - Evasion considerations

4. **Alternative Approaches**
   - If no public exploit exists
   - Manual exploitation steps
   - Custom payload requirements

5. **Testing Considerations**
   - Lab environment setup
   - Safe testing procedures
   - Backup and recovery
"#
        )
    }

    fn gen_lateral_movement(&self, args: &std::collections::HashMap<String, String>) -> String {
        let current_access = args
            .get("current_access")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let network_map = args
            .get("network_map")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let credentials = args
            .get("credentials")
            .map(|s| s.as_str())
            .unwrap_or("none");

        format!(
            r#"# Lateral Movement Planning

## Current Access
{current_access}

## Network Map
{network_map}

## Available Credentials
{credentials}

---

Plan lateral movement with:

1. **Current Position Analysis**
   - What access do we have?
   - What can we reach from here?
   - What credentials are available?

2. **Target Identification**
   | Target | Reachability | Value | Method |
   |--------|--------------|-------|--------|

3. **Movement Techniques** (MITRE T1021)
   - RDP (T1021.001)
   - SMB/Admin Shares (T1021.002)
   - SSH (T1021.004)
   - WinRM (T1021.006)

4. **Credential Usage**
   - Pass-the-hash opportunities
   - Kerberos ticket usage
   - Credential reuse analysis

5. **OPSEC Considerations**
   - Log artifacts
   - Detection risks
   - Alternative paths
"#
        )
    }

    fn gen_persistence_analysis(&self, args: &std::collections::HashMap<String, String>) -> String {
        let target_os = args.get("target_os").map(|s| s.as_str()).unwrap_or("linux");
        let access_level = args
            .get("access_level")
            .map(|s| s.as_str())
            .unwrap_or("user");
        let stealth = args.get("stealth").map(|s| s.as_str()).unwrap_or("medium");

        format!(
            r#"# Persistence Mechanism Analysis

## Target OS
{target_os}

## Access Level
{access_level}

## Stealth Requirement
{stealth}

---

Analyze persistence options:

1. **Available Mechanisms** (based on access level)
   | Technique | MITRE ID | Access Needed | Detection Risk |
   |-----------|----------|---------------|----------------|

2. **Recommended Approach**
   ```bash
   rb exploit payload persist --os {target_os} --stealth {stealth}
   ```

3. **Implementation Details**
   - Exact commands/files
   - Configuration changes
   - Trigger mechanisms

4. **Detection & Cleanup**
   - How it would be detected
   - Forensic artifacts
   - Removal procedures

5. **Backup Mechanisms**
   - Secondary persistence
   - Failsafe options
"#
        )
    }

    fn gen_threat_model(&self, args: &std::collections::HashMap<String, String>) -> String {
        let system = args
            .get("system")
            .map(|s| s.as_str())
            .unwrap_or("unknown system");
        let assets = args
            .get("assets")
            .map(|s| s.as_str())
            .unwrap_or("not specified");
        let threat_actors = args
            .get("threat_actors")
            .map(|s| s.as_str())
            .unwrap_or("general");

        format!(
            r#"# Threat Modeling Request

## System Description
{system}

## Critical Assets
{assets}

## Threat Actors of Concern
{threat_actors}

---

Create a threat model using STRIDE:

1. **System Decomposition**
   - Components and boundaries
   - Data flows
   - Trust boundaries
   - Entry points

2. **STRIDE Analysis**
   | Component | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
   |-----------|----------|-----------|-------------|-----------------|-----|-----------|

3. **Threat Scenarios**
   - Most likely attacks
   - Highest impact attacks
   - Attack trees

4. **Risk Assessment**
   | Threat | Likelihood | Impact | Risk | Mitigation |
   |--------|------------|--------|------|------------|

5. **Recommendations**
   - Security controls
   - Monitoring requirements
   - Incident response considerations
"#
        )
    }

    fn gen_incident_response(&self, args: &std::collections::HashMap<String, String>) -> String {
        let incident_type = args
            .get("incident_type")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let indicators = args
            .get("indicators")
            .map(|s| s.as_str())
            .unwrap_or("none provided");
        let affected_systems = args
            .get("affected_systems")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        format!(
            r#"# Incident Response Guidance

## Incident Type
{incident_type}

## Known Indicators
{indicators}

## Affected Systems
{affected_systems}

---

Guide incident response:

1. **Immediate Actions** (First 30 minutes)
   - Containment steps
   - Evidence preservation
   - Notification requirements

2. **IOC Analysis**
   ```bash
   rb intel ioc extract <file>
   rb intel mitre map --iocs <indicators>
   ```

3. **Scope Assessment**
   - How to determine blast radius
   - Systems to investigate
   - Log sources to examine

4. **Eradication Steps**
   - Malware removal
   - Access revocation
   - Credential rotation

5. **Recovery Plan**
   - System restoration order
   - Verification steps
   - Monitoring enhancements

6. **Lessons Learned**
   - Root cause analysis
   - Gap identification
   - Improvement recommendations
"#
        )
    }

    fn gen_detection_rules(&self, args: &std::collections::HashMap<String, String>) -> String {
        let threat = args
            .get("threat")
            .map(|s| s.as_str())
            .unwrap_or("unknown threat");
        let format = args.get("format").map(|s| s.as_str()).unwrap_or("sigma");

        format!(
            r#"# Detection Rule Generation

## Threat to Detect
{threat}

## Output Format
{format}

---

Generate detection rules:

1. **Threat Analysis**
   - Behavior to detect
   - MITRE techniques involved
   - Artifacts produced

2. **Detection Logic**
   - Key indicators
   - Event sources
   - Correlation requirements

3. **{format} Rules**
   ```yaml
   # Rule content here
   ```

4. **Testing Guidance**
   - How to test the rule
   - Expected true positives
   - Known false positive scenarios

5. **Tuning Recommendations**
   - Environment-specific adjustments
   - Threshold tuning
   - Exclusion patterns
"#
        )
    }

    fn gen_hardening_guide(&self, args: &std::collections::HashMap<String, String>) -> String {
        let system = args.get("system").map(|s| s.as_str()).unwrap_or("unknown");
        let baseline = args.get("baseline").map(|s| s.as_str()).unwrap_or("CIS");

        format!(
            r#"# System Hardening Guide

## System
{system}

## Baseline Standard
{baseline}

---

Generate hardening recommendations:

1. **Configuration Hardening**
   | Setting | Current | Recommended | Priority |
   |---------|---------|-------------|----------|

2. **Network Hardening**
   - Firewall rules
   - Network segmentation
   - Service exposure

3. **Access Controls**
   - Authentication requirements
   - Authorization policies
   - Privilege restrictions

4. **Logging & Monitoring**
   - Required log sources
   - Retention policies
   - Alert thresholds

5. **Verification Commands**
   ```bash
   # Commands to verify each setting
   ```
"#
        )
    }

    fn gen_pentest_report(&self, args: &std::collections::HashMap<String, String>) -> String {
        let findings = args.get("findings").map(|s| s.as_str()).unwrap_or("none");
        let scope = args
            .get("scope")
            .map(|s| s.as_str())
            .unwrap_or("not specified");
        let format = args.get("format").map(|s| s.as_str()).unwrap_or("full");

        format!(
            r#"# Penetration Test Report Generation

## Findings
{findings}

## Engagement Scope
{scope}

## Report Format
{format}

---

Generate penetration test report:

1. **Executive Summary**
   - Overall risk rating
   - Key findings (3-5)
   - Business impact
   - Top recommendations

2. **Technical Findings**
   | ID | Title | Severity | CVSS | Status |
   |----|-------|----------|------|--------|

3. **Finding Details** (for each)
   - Description
   - Evidence
   - Impact
   - Remediation
   - References

4. **Attack Narrative**
   - Attack path used
   - Techniques employed
   - MITRE ATT&CK mapping

5. **Recommendations**
   - Prioritized action items
   - Quick wins
   - Long-term improvements

6. **Appendices**
   - Methodology
   - Tools used
   - Raw evidence
"#
        )
    }

    fn gen_executive_summary(&self, args: &std::collections::HashMap<String, String>) -> String {
        let findings = args.get("findings").map(|s| s.as_str()).unwrap_or("none");
        let audience = args
            .get("audience")
            .map(|s| s.as_str())
            .unwrap_or("c-suite");

        format!(
            r#"# Executive Summary Generation

## Technical Findings
{findings}

## Target Audience
{audience}

---

Create an executive summary:

1. **Overall Assessment**
   - Risk rating (Critical/High/Medium/Low)
   - Comparison to industry
   - Trend from previous assessments

2. **Key Findings** (non-technical language)
   - Top 3-5 issues
   - Business impact of each
   - Real-world examples/analogies

3. **Risk Visualization**
   - Risk matrix
   - Trend charts
   - Comparison metrics

4. **Investment Recommendations**
   - Cost of inaction
   - Recommended investments
   - Expected risk reduction

5. **Next Steps**
   - Immediate actions
   - Strategic initiatives
   - Timeline
"#
        )
    }

    fn gen_risk_matrix(&self, args: &std::collections::HashMap<String, String>) -> String {
        let vulnerabilities = args
            .get("vulnerabilities")
            .map(|s| s.as_str())
            .unwrap_or("none");
        let business_context = args
            .get("business_context")
            .map(|s| s.as_str())
            .unwrap_or("general");

        format!(
            r#"# Risk Matrix Generation

## Vulnerabilities
{vulnerabilities}

## Business Context
{business_context}

---

Generate a risk matrix:

1. **Likelihood Assessment**
   - Skill level required
   - Access requirements
   - Exploit availability

2. **Impact Assessment**
   - Confidentiality impact
   - Integrity impact
   - Availability impact
   - Financial impact
   - Reputational impact

3. **Risk Matrix**
   ```
                    IMPACT
             Low    Med    High   Crit
   L   High |  M  |  H  |  H  |  C  |
   I   Med  |  L  |  M  |  H  |  H  |
   K   Low  |  L  |  L  |  M  |  H  |
   E   VLow |  L  |  L  |  L  |  M  |
   ```

4. **Vulnerability Placement**
   | Vulnerability | Likelihood | Impact | Risk |
   |---------------|------------|--------|------|

5. **Prioritization**
   - Critical (immediate)
   - High (this week)
   - Medium (this month)
   - Low (this quarter)
"#
        )
    }

    fn gen_compliance_check(&self, args: &std::collections::HashMap<String, String>) -> String {
        let standard = args
            .get("standard")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let scope = args
            .get("scope")
            .map(|s| s.as_str())
            .unwrap_or("not specified");

        format!(
            r#"# Compliance Assessment

## Standard
{standard}

## Scope
{scope}

---

Perform compliance check:

1. **Applicable Requirements**
   | Req ID | Description | Applicability |
   |--------|-------------|---------------|

2. **Control Assessment**
   | Control | Status | Evidence | Gap |
   |---------|--------|----------|-----|

3. **Gap Analysis**
   - Critical gaps
   - Remediation requirements
   - Timeline to compliance

4. **Evidence Collection**
   - Required documentation
   - Technical evidence
   - Process evidence

5. **Recommendations**
   - Priority remediation
   - Compensating controls
   - Roadmap to compliance
"#
        )
    }

    fn gen_gap_analysis(&self, args: &std::collections::HashMap<String, String>) -> String {
        let current_state = args
            .get("current_state")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let target_state = args
            .get("target_state")
            .map(|s| s.as_str())
            .unwrap_or("not specified");

        format!(
            r#"# Security Gap Analysis

## Current State
{current_state}

## Target State
{target_state}

---

Perform gap analysis:

1. **Current State Assessment**
   - Existing controls
   - Current maturity level
   - Strengths

2. **Target State Requirements**
   - Required controls
   - Target maturity level
   - Compliance needs

3. **Gap Identification**
   | Domain | Current | Target | Gap | Priority |
   |--------|---------|--------|-----|----------|

4. **Remediation Roadmap**
   - Quick wins (0-3 months)
   - Medium-term (3-6 months)
   - Long-term (6-12 months)

5. **Resource Requirements**
   - Budget estimates
   - Personnel needs
   - Technology investments
"#
        )
    }

    fn gen_mitre_mapping(&self, args: &std::collections::HashMap<String, String>) -> String {
        let findings = args.get("findings").map(|s| s.as_str()).unwrap_or("none");
        let format = args
            .get("format")
            .map(|s| s.as_str())
            .unwrap_or("navigator");

        format!(
            r#"# MITRE ATT&CK Mapping

## Findings to Map
{findings}

## Output Format
{format}

---

Map findings to ATT&CK:

1. **Technique Identification**
   ```bash
   rb intel mitre map --findings <file>
   rb intel mitre technique <ID>
   ```

2. **Mapping Results**
   | Finding | Technique | Tactic | Confidence |
   |---------|-----------|--------|------------|

3. **Navigator Layer**
   - Color coding by:
     - Detection coverage
     - Observed techniques
     - Gaps in visibility

4. **Coverage Analysis**
   - Techniques detected
   - Techniques not covered
   - Priority gaps

5. **Detection Recommendations**
   - Data sources needed
   - Detection rules
   - Monitoring improvements
"#
        )
    }

    fn gen_attack_simulation(&self, args: &std::collections::HashMap<String, String>) -> String {
        let threat_actor = args
            .get("threat_actor")
            .map(|s| s.as_str())
            .unwrap_or("generic APT");
        let scope = args
            .get("scope")
            .map(|s| s.as_str())
            .unwrap_or("not specified");

        format!(
            r#"# Attack Simulation Design

## Threat Actor to Emulate
{threat_actor}

## Simulation Scope
{scope}

---

Design attack simulation:

1. **Threat Actor Profile**
   - Known TTPs
   - Target industries
   - Typical objectives
   - Tools used

2. **Simulation Scenarios**
   | Scenario | Techniques | Objective | Detection Test |
   |----------|------------|-----------|----------------|

3. **Execution Plan**
   - Phase 1: Initial Access
   - Phase 2: Execution
   - Phase 3: Persistence
   - Phase 4: Objective

4. **Success Criteria**
   - Detection metrics
   - Response time goals
   - Coverage objectives

5. **Safety Controls**
   - Boundaries
   - Emergency stop
   - Rollback procedures
"#
        )
    }

    fn gen_osint_profile(&self, args: &std::collections::HashMap<String, String>) -> String {
        let target = args.get("target").map(|s| s.as_str()).unwrap_or("unknown");
        let depth = args.get("depth").map(|s| s.as_str()).unwrap_or("moderate");

        format!(
            r#"# OSINT Profile Request

## Target
{target}

## Investigation Depth
{depth}

---

Build OSINT profile:

1. **Domain Intelligence**
   ```bash
   rb recon domain whois {target}
   rb recon domain subdomains {target}
   rb dns record lookup {target}
   ```

2. **Technical Footprint**
   - IP ranges
   - ASN information
   - Hosting providers
   - Technology stack

3. **Digital Presence**
   - Social media
   - Job postings
   - Press releases
   - Partnerships

4. **Security Posture Indicators**
   - Exposed services
   - Data leaks
   - Previous breaches
   - Security headers

5. **Key Findings Summary**
   - Attack surface highlights
   - Interesting discoveries
   - Recommended next steps
"#
        )
    }

    fn gen_attack_surface(&self, args: &std::collections::HashMap<String, String>) -> String {
        let organization = args
            .get("organization")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let include_subs = args
            .get("include_subsidiaries")
            .map(|s| s.as_str())
            .unwrap_or("false");

        format!(
            r#"# External Attack Surface Mapping

## Organization
{organization}

## Include Subsidiaries
{include_subs}

---

Map external attack surface:

1. **Domain Discovery**
   ```bash
   rb recon domain whois {organization}
   rb recon domain subdomains {organization}
   ```

2. **Asset Inventory**
   | Domain | IPs | Services | Risk |
   |--------|-----|----------|------|

3. **Service Exposure**
   - Internet-facing services
   - Administrative interfaces
   - API endpoints
   - Development/staging

4. **Risk Assessment**
   - Critical exposures
   - Outdated services
   - Missing security controls

5. **Recommendations**
   - Immediate actions
   - Services to secure
   - Monitoring requirements
"#
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CLOUD SECURITY GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_cloud_audit(&self, args: &std::collections::HashMap<String, String>) -> String {
        let provider = args.get("provider").map(|s| s.as_str()).unwrap_or("aws");
        let scope = args.get("scope").map(|s| s.as_str()).unwrap_or("full");
        let compliance = args.get("compliance").map(|s| s.as_str()).unwrap_or("cis");

        format!(
            r#"# Cloud Infrastructure Security Audit

## Cloud Provider
{provider}

## Audit Scope
{scope}

## Compliance Framework
{compliance}

---

Perform comprehensive cloud security audit:

1. **Identity & Access Management**
   - Root/admin account usage
   - MFA enforcement
   - Service account hygiene
   - Role policies (least privilege)
   - Cross-account access

2. **Network Security**
   - VPC configuration
   - Security groups / NSGs
   - Public exposure
   - Network ACLs
   - VPN/Direct Connect

3. **Data Protection**
   - Encryption at rest
   - Encryption in transit
   - Key management
   - Backup policies
   - Data classification

4. **Logging & Monitoring**
   - CloudTrail / Activity Log / Audit Log
   - Flow logs
   - Alert configuration
   - SIEM integration

5. **Compute Security**
   - Instance metadata protection
   - Patch management
   - Container security
   - Serverless security

6. **{compliance} Compliance Mapping**
   | Control | Status | Evidence | Remediation |
   |---------|--------|----------|-------------|

7. **Critical Findings**
   - High-risk misconfigurations
   - Immediate actions required
   - Remediation priority
"#
        )
    }

    fn gen_aws_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let account_id = args
            .get("account_id")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let services = args.get("services").map(|s| s.as_str()).unwrap_or("all");

        format!(
            r#"# AWS Security Assessment

## AWS Account
{account_id}

## Services to Audit
{services}

---

Perform AWS-specific security assessment:

1. **IAM Security**
   - Root account MFA
   - IAM users vs roles
   - Policy analysis (overly permissive)
   - Access keys age
   - Password policy

2. **S3 Security**
   - Public buckets
   - Bucket policies
   - ACL configuration
   - Block public access settings
   - Encryption configuration

3. **EC2 Security**
   - IMDSv2 enforcement
   - Security group rules
   - EBS encryption
   - Public IPs
   - Key pair management

4. **Lambda Security**
   - Function permissions
   - VPC configuration
   - Environment variables
   - Execution role policies

5. **RDS Security**
   - Public accessibility
   - Encryption
   - Security groups
   - IAM authentication
   - Audit logging

6. **CloudTrail & GuardDuty**
   - Multi-region trails
   - Log file validation
   - GuardDuty findings
   - S3 data events

7. **Network Security**
   - VPC flow logs
   - Default VPC usage
   - NAT gateway configuration
   - Transit Gateway

8. **Recommendations**
   | Finding | Severity | AWS Service | Remediation |
   |---------|----------|-------------|-------------|
"#
        )
    }

    fn gen_azure_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let subscription = args
            .get("subscription")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let focus = args.get("focus").map(|s| s.as_str()).unwrap_or("full");

        format!(
            r#"# Azure Security Assessment

## Azure Subscription
{subscription}

## Focus Area
{focus}

---

Perform Azure-specific security assessment:

1. **Azure AD Security**
   - Privileged Identity Management (PIM)
   - Conditional Access policies
   - MFA enforcement
   - Guest user access
   - App registrations

2. **Identity & Access**
   - RBAC assignments
   - Management groups
   - Custom roles
   - Service principals
   - Managed identities

3. **Network Security**
   - NSG rules
   - Azure Firewall
   - Application Gateway WAF
   - Private endpoints
   - VNet peering

4. **Storage Security**
   - Storage account access
   - Blob public access
   - SAS token policies
   - Encryption settings
   - Network rules

5. **Compute Security**
   - VM extensions
   - Just-in-time access
   - Update management
   - Disk encryption
   - Bastion hosts

6. **Microsoft Defender for Cloud**
   - Security posture score
   - Recommendations
   - Alert status
   - Regulatory compliance

7. **Logging & Monitoring**
   - Activity log export
   - Diagnostic settings
   - Azure Monitor
   - Log Analytics

8. **Recommendations**
   | Finding | Severity | Azure Service | Remediation |
   |---------|----------|---------------|-------------|
"#
        )
    }

    fn gen_gcp_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let project = args.get("project").map(|s| s.as_str()).unwrap_or("unknown");
        let services = args.get("services").map(|s| s.as_str()).unwrap_or("all");

        format!(
            r#"# GCP Security Assessment

## GCP Project
{project}

## Services to Audit
{services}

---

Perform GCP-specific security assessment:

1. **IAM Security**
   - Service account usage
   - Key management
   - Workload identity
   - Organization policies
   - Custom roles

2. **Cloud Storage Security**
   - Bucket ACLs
   - Uniform bucket-level access
   - Public access prevention
   - Retention policies
   - CMEK encryption

3. **Compute Engine Security**
   - VM metadata
   - Service account scopes
   - Firewall rules
   - Shielded VMs
   - OS patch management

4. **Cloud Functions Security**
   - Function permissions
   - Ingress settings
   - VPC connector
   - Environment secrets

5. **GKE Security**
   - Private clusters
   - Workload identity
   - Network policies
   - Binary authorization
   - Pod security policies

6. **BigQuery Security**
   - Dataset access
   - Column-level security
   - Audit logging
   - Data masking

7. **Security Command Center**
   - Findings status
   - Asset inventory
   - Compliance status
   - Threat detection

8. **Recommendations**
   | Finding | Severity | GCP Service | Remediation |
   |---------|----------|-------------|-------------|
"#
        )
    }

    fn gen_s3_audit(&self, args: &std::collections::HashMap<String, String>) -> String {
        let bucket = args.get("bucket").map(|s| s.as_str()).unwrap_or("*");
        let deep_scan = args.get("deep_scan").map(|s| s.as_str()).unwrap_or("false");

        format!(
            r#"# AWS S3 Bucket Security Audit

## Target Bucket(s)
{bucket}

## Deep Content Scan
{deep_scan}

---

Perform S3 bucket security audit:

1. **Access Configuration**
   - Block Public Access settings
   - Bucket policy analysis
   - ACL configuration
   - Cross-account access
   - Pre-signed URL policies

2. **Encryption**
   - Default encryption
   - SSE-S3 vs SSE-KMS vs SSE-C
   - Bucket key usage
   - In-transit encryption

3. **Logging & Monitoring**
   - Server access logging
   - CloudTrail data events
   - S3 event notifications
   - Access analyzer findings

4. **Data Protection**
   - Versioning enabled
   - MFA delete
   - Object lock
   - Lifecycle policies
   - Replication rules

5. **Access Points**
   - Access point policies
   - VPC restrictions
   - Network origin

6. **Sensitive Data Discovery**
   - PII indicators
   - Credentials/secrets
   - Backup files
   - Log files with sensitive data

7. **Findings Summary**
   | Bucket | Issue | Severity | Remediation |
   |--------|-------|----------|-------------|

8. **Remediation Commands**
   ```bash
   aws s3api put-public-access-block --bucket <bucket> ...
   aws s3api put-bucket-encryption --bucket <bucket> ...
   ```
"#
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONTAINER & KUBERNETES GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_container_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let image = args.get("image").map(|s| s.as_str()).unwrap_or("unknown");
        let runtime = args.get("runtime").map(|s| s.as_str()).unwrap_or("docker");

        format!(
            r#"# Container Security Assessment

## Container Image
{image}

## Container Runtime
{runtime}

---

Perform container security assessment:

1. **Image Security**
   - Base image analysis
   - Layer history
   - Vulnerability scanning
   - Malware detection
   - Image signing/verification

2. **Build Security**
   - Dockerfile best practices
   - Multi-stage builds
   - Secret handling
   - User permissions
   - Package sources

3. **Runtime Security**
   - Privileged mode
   - Capabilities
   - Seccomp profiles
   - AppArmor/SELinux
   - Read-only filesystem

4. **Network Security**
   - Exposed ports
   - Network mode
   - Container isolation
   - Traffic encryption

5. **Resource Limits**
   - CPU limits
   - Memory limits
   - PID limits
   - Storage limits

6. **Secrets & Configuration**
   - Environment variables
   - Mounted secrets
   - Config files
   - Sensitive data exposure

7. **Vulnerability Report**
   | Package | Version | CVE | Severity | Fixed In |
   |---------|---------|-----|----------|----------|

8. **Hardening Recommendations**
   - Critical fixes
   - Base image alternatives
   - Runtime restrictions
"#
        )
    }

    fn gen_k8s_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let cluster = args.get("cluster").map(|s| s.as_str()).unwrap_or("unknown");
        let namespace = args.get("namespace").map(|s| s.as_str()).unwrap_or("all");
        let focus = args.get("focus").map(|s| s.as_str()).unwrap_or("full");

        format!(
            r#"# Kubernetes Security Assessment

## Cluster
{cluster}

## Namespace
{namespace}

## Focus Area
{focus}

---

Perform Kubernetes security assessment:

1. **Cluster Configuration**
   - API server security
   - etcd encryption
   - Admission controllers
   - Audit logging
   - Network policies default

2. **RBAC Analysis**
   - Cluster roles
   - Role bindings
   - Service accounts
   - Privileged bindings
   - Default service accounts

3. **Pod Security**
   - Pod Security Standards/Policies
   - Privileged containers
   - Host namespaces
   - Capabilities
   - Security contexts

4. **Network Security**
   - Network policies
   - Ingress configuration
   - Service mesh
   - mTLS enforcement
   - Egress controls

5. **Secrets Management**
   - Secret encryption
   - External secrets
   - Secret access
   - Rotation policies

6. **Workload Security**
   - Image policies
   - Resource limits
   - Liveness/readiness
   - PodDisruptionBudgets

7. **Runtime Security**
   - Container runtime
   - Runtime classes
   - Falco/runtime detection
   - Pod security admission

8. **Findings Matrix**
   | Resource | Namespace | Issue | Severity | Remediation |
   |----------|-----------|-------|----------|-------------|
"#
        )
    }

    fn gen_dockerfile_review(&self, args: &std::collections::HashMap<String, String>) -> String {
        let dockerfile = args
            .get("dockerfile")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let base_image = args
            .get("base_image")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        format!(
            r#"# Dockerfile Security Review

## Dockerfile Content
```dockerfile
{dockerfile}
```

## Base Image
{base_image}

---

Review Dockerfile for security issues:

1. **Base Image Analysis**
   - Official image vs custom
   - Image tag (avoid :latest)
   - Known vulnerabilities
   - Size optimization
   - Distroless alternatives

2. **Build Security**
   - Multi-stage builds
   - Build arguments
   - Cache optimization
   - Layer ordering

3. **User Permissions**
   - Non-root user
   - USER instruction
   - File permissions
   - Capability dropping

4. **Secrets Handling**
   - No secrets in build
   - Build-time secrets
   - Multi-stage for secrets
   - .dockerignore review

5. **Package Management**
   - Package pinning
   - Vulnerability scanning
   - Unnecessary packages
   - Cache cleanup

6. **Runtime Configuration**
   - EXPOSE statements
   - ENTRYPOINT vs CMD
   - Health checks
   - Signal handling

7. **Security Checklist**
   | Check | Status | Line | Recommendation |
   |-------|--------|------|----------------|
   | Non-root user | | | |
   | Pinned versions | | | |
   | No secrets | | | |
   | Minimal base | | | |

8. **Optimized Dockerfile**
   ```dockerfile
   # Recommended changes
   ```
"#
        )
    }

    fn gen_helm_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let chart = args.get("chart").map(|s| s.as_str()).unwrap_or("unknown");
        let values = args.get("values").map(|s| s.as_str()).unwrap_or("default");

        format!(
            r#"# Helm Chart Security Review

## Chart
{chart}

## Values Configuration
{values}

---

Review Helm chart for security issues:

1. **Chart Structure**
   - Chart.yaml analysis
   - Dependencies review
   - Template security
   - NOTES.txt disclosure

2. **Security Contexts**
   - Pod security contexts
   - Container security contexts
   - RunAsNonRoot
   - ReadOnlyRootFilesystem
   - Capabilities

3. **RBAC Configuration**
   - Service accounts
   - Roles/ClusterRoles
   - Bindings
   - Least privilege

4. **Network Policies**
   - Ingress rules
   - Egress rules
   - Default deny
   - Service exposure

5. **Resource Limits**
   - CPU limits
   - Memory limits
   - Replica counts
   - HPA configuration

6. **Secrets Handling**
   - Secret references
   - External secrets
   - Sealed secrets
   - Vault integration

7. **Image Configuration**
   - Image pull policy
   - Image tags
   - Private registries
   - Image pull secrets

8. **Security Findings**
   | Template | Line | Issue | Severity | Fix |
   |----------|------|-------|----------|-----|

9. **Hardened Values**
   ```yaml
   # Security-focused values.yaml
   ```
"#
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // API SECURITY GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_api_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let api_spec = args
            .get("api_spec")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let auth_type = args
            .get("auth_type")
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        format!(
            r#"# API Security Assessment

## API Specification
{api_spec}

## Authentication Type
{auth_type}

---

Perform API security assessment:

1. **Authentication Analysis**
   - Auth mechanism review
   - Token security
   - Session management
   - Credential handling
   - Brute force protection

2. **Authorization Testing**
   - BOLA/IDOR testing
   - BFLA testing
   - Role-based access
   - Horizontal privilege escalation
   - Vertical privilege escalation

3. **Input Validation**
   - Injection points
   - Parameter tampering
   - Mass assignment
   - Type confusion
   - XXE vulnerabilities

4. **Data Exposure**
   - Excessive data exposure
   - Sensitive data in responses
   - Debug information
   - Error messages
   - Stack traces

5. **Rate Limiting**
   - Request limits
   - Resource exhaustion
   - DoS protection
   - Throttling bypass

6. **Security Headers**
   - CORS configuration
   - Content-Type validation
   - Security headers
   - Cache controls

7. **OWASP API Top 10**
   | Risk | API1:2023 | Status | Details |
   |------|-----------|--------|---------|
   | Broken Object Level Auth | | | |
   | Broken Authentication | | | |
   | Broken Object Property Auth | | | |
   | Unrestricted Resource Consumption | | | |
   | Broken Function Level Auth | | | |

8. **Test Cases**
   ```bash
   # API security testing commands
   rb web asset get <endpoint>
   ```
"#
        )
    }

    fn gen_graphql_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let endpoint = args
            .get("endpoint")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let schema = args
            .get("schema")
            .map(|s| s.as_str())
            .unwrap_or("introspection");

        format!(
            r#"# GraphQL Security Testing

## Endpoint
{endpoint}

## Schema Source
{schema}

---

Perform GraphQL security testing:

1. **Introspection Analysis**
   - Introspection enabled
   - Schema disclosure
   - Hidden fields/types
   - Deprecated fields

2. **Authentication**
   - Auth mechanism
   - Token handling
   - Session security
   - Unauthenticated access

3. **Authorization**
   - Field-level authorization
   - Type-level authorization
   - Resolver authorization
   - IDOR vulnerabilities

4. **Query Attacks**
   - Deep query attacks
   - Circular queries
   - Alias overloading
   - Directive overloading
   - Field duplication

5. **Resource Limits**
   - Query depth limits
   - Query complexity limits
   - Timeout configuration
   - Pagination limits
   - Batching limits

6. **Injection Testing**
   - SQL injection via arguments
   - NoSQL injection
   - Command injection
   - SSRF via inputs

7. **Information Disclosure**
   - Error verbosity
   - Stack traces
   - Debug mode
   - Suggestions in errors

8. **Testing Queries**
   ```graphql
   # Introspection query
   query {{ __schema {{ types {{ name }} }} }}

   # Depth test
   query {{ user {{ posts {{ comments {{ author {{ posts ... }} }} }} }} }}
   ```

9. **Findings**
   | Vulnerability | Severity | Query | Remediation |
   |---------------|----------|-------|-------------|
"#
        )
    }

    fn gen_oauth_audit(&self, args: &std::collections::HashMap<String, String>) -> String {
        let provider = args
            .get("provider")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let flows = args
            .get("flows")
            .map(|s| s.as_str())
            .unwrap_or("authorization_code");

        format!(
            r#"# OAuth/OIDC Security Audit

## OAuth Provider
{provider}

## OAuth Flows Used
{flows}

---

Perform OAuth/OIDC security audit:

1. **Flow Configuration**
   - Supported flows
   - PKCE enforcement
   - State parameter usage
   - Nonce validation
   - Response types

2. **Token Security**
   - Token storage
   - Token transmission
   - Access token lifetime
   - Refresh token rotation
   - Token revocation

3. **Client Configuration**
   - Client authentication
   - Redirect URI validation
   - Client types
   - CORS configuration
   - Origins validation

4. **Authorization Server**
   - Discovery document
   - JWKS endpoint
   - Token endpoint security
   - Consent handling
   - Scope validation

5. **Common Vulnerabilities**
   | Attack | Risk | Mitigation | Status |
   |--------|------|------------|--------|
   | Open Redirect | | | |
   | Token Leakage | | | |
   | CSRF | | | |
   | Code Injection | | | |
   | Mix-up Attack | | | |

6. **ID Token Validation**
   - Signature verification
   - Claims validation
   - Issuer validation
   - Audience validation
   - Expiration checks

7. **Best Practices Checklist**
   - [ ] PKCE for public clients
   - [ ] Short-lived access tokens
   - [ ] Refresh token rotation
   - [ ] Secure token storage
   - [ ] State parameter validation

8. **Recommendations**
   - Critical fixes
   - Configuration changes
   - Monitoring additions
"#
        )
    }

    fn gen_jwt_analysis(&self, args: &std::collections::HashMap<String, String>) -> String {
        let token = args.get("token").map(|s| s.as_str()).unwrap_or("[TOKEN]");
        let context = args.get("context").map(|s| s.as_str()).unwrap_or("general");

        format!(
            r#"# JWT Token Security Analysis

## Token
{token}

## Usage Context
{context}

---

Analyze JWT for security issues:

1. **Header Analysis**
   - Algorithm used
   - Key ID (kid)
   - Type claim
   - Custom headers

2. **Payload Analysis**
   - Standard claims (iss, sub, aud, exp, nbf, iat, jti)
   - Custom claims
   - Sensitive data exposure
   - Claim validation requirements

3. **Signature Verification**
   - Algorithm verification
   - Key/secret strength
   - None algorithm check
   - Algorithm confusion

4. **Common Vulnerabilities**
   | Attack | Risk | Details |
   |--------|------|---------|
   | None Algorithm | Critical | alg: none bypass |
   | Algorithm Confusion | Critical | RS256 to HS256 |
   | Weak Secret | High | Brute-forceable |
   | No Expiration | High | Token reuse |
   | Information Leak | Medium | Sensitive claims |

5. **Token Lifetime**
   - Expiration (exp)
   - Not Before (nbf)
   - Issued At (iat)
   - Refresh mechanism

6. **Storage & Transmission**
   - Where stored (cookie vs localStorage)
   - HttpOnly/Secure flags
   - SameSite attribute
   - Transmission security

7. **Validation Checklist**
   - [ ] Signature verified
   - [ ] Algorithm whitelisted
   - [ ] Expiration checked
   - [ ] Issuer validated
   - [ ] Audience validated

8. **Decoded Token**
   ```json
   {{
     "header": {{}},
     "payload": {{}},
     "signature": ""
   }}
   ```

9. **Recommendations**
   - Security fixes
   - Claim additions
   - Rotation strategy
"#
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MOBILE SECURITY GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_mobile_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let platform = args.get("platform").map(|s| s.as_str()).unwrap_or("both");
        let app_name = args
            .get("app_name")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let scope = args.get("scope").map(|s| s.as_str()).unwrap_or("full");

        format!(
            r#"# Mobile Application Security Assessment

## Platform
{platform}

## Application
{app_name}

## Assessment Scope
{scope}

---

Perform mobile security assessment (OWASP MASTG/MASVS):

1. **Architecture Analysis**
   - App architecture
   - Data flows
   - Backend communication
   - Third-party SDKs

2. **Data Storage**
   - Local storage security
   - Keychain/Keystore usage
   - Database encryption
   - Backup security
   - Sensitive data exposure

3. **Cryptography**
   - Crypto implementation
   - Key management
   - Random number generation
   - Crypto configuration

4. **Authentication**
   - Local authentication
   - Biometric security
   - Session management
   - Token handling

5. **Network Security**
   - TLS configuration
   - Certificate pinning
   - API security
   - Traffic analysis

6. **Platform Security**
   - Platform protections
   - Root/jailbreak detection
   - Code tampering
   - Reverse engineering

7. **Code Security**
   - Obfuscation
   - Anti-debugging
   - Integrity checks
   - Dynamic analysis detection

8. **MASVS Compliance**
   | Requirement | Level | Status | Notes |
   |-------------|-------|--------|-------|
   | MASVS-STORAGE | | | |
   | MASVS-CRYPTO | | | |
   | MASVS-AUTH | | | |
   | MASVS-NETWORK | | | |
   | MASVS-PLATFORM | | | |
   | MASVS-CODE | | | |
   | MASVS-RESILIENCE | | | |

9. **Testing Tools**
   - Frida scripts
   - objection commands
   - Static analysis findings
"#
        )
    }

    fn gen_android_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let apk = args.get("apk").map(|s| s.as_str()).unwrap_or("unknown");
        let manifest = args
            .get("manifest")
            .map(|s| s.as_str())
            .unwrap_or("not provided");

        format!(
            r#"# Android Security Testing

## APK
{apk}

## AndroidManifest.xml
{manifest}

---

Perform Android-specific security testing:

1. **Manifest Analysis**
   - Permissions review
   - Exported components
   - Debug flags
   - Backup settings
   - Network security config

2. **Component Security**
   - Activities (exported, intents)
   - Services (bound, started)
   - Broadcast receivers
   - Content providers
   - Deep link handling

3. **Data Storage**
   - SharedPreferences
   - SQLite databases
   - Internal/External storage
   - Keystore usage
   - Backup exclusions

4. **Network Security**
   - Network security config
   - Cleartext traffic
   - Certificate pinning
   - WebView security
   - API communication

5. **Code Analysis**
   - Native libraries
   - ProGuard/R8
   - Reflection usage
   - Dynamic loading
   - JNI security

6. **Root Detection**
   - Detection mechanisms
   - Bypass difficulty
   - Frida detection
   - Magisk Hide

7. **Runtime Testing**
   ```bash
   # Frida commands
   frida -U -f {apk} -l script.js

   # objection commands
   objection -g {apk} explore
   ```

8. **Findings**
   | Component | Vulnerability | Severity | PoC |
   |-----------|--------------|----------|-----|

9. **Recommendations**
   - Code fixes
   - Manifest changes
   - Storage hardening
"#
        )
    }

    fn gen_ios_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let ipa = args.get("ipa").map(|s| s.as_str()).unwrap_or("unknown");
        let entitlements = args
            .get("entitlements")
            .map(|s| s.as_str())
            .unwrap_or("not provided");

        format!(
            r#"# iOS Security Testing

## IPA/Bundle
{ipa}

## Entitlements
{entitlements}

---

Perform iOS-specific security testing:

1. **Binary Analysis**
   - PIE enabled
   - ARC usage
   - Stack canaries
   - Code signing
   - Encryption status

2. **Entitlements Review**
   - App groups
   - Keychain access
   - Background modes
   - Push notifications
   - Associated domains

3. **Data Storage**
   - Keychain items
   - NSUserDefaults
   - Core Data/SQLite
   - File protection classes
   - Data backup

4. **Network Security**
   - ATS configuration
   - Certificate pinning
   - URLSession security
   - WebView settings

5. **Authentication**
   - Local authentication
   - TouchID/FaceID
   - Keychain ACLs
   - Token storage

6. **IPC Security**
   - URL schemes
   - Universal links
   - Pasteboard
   - App extensions

7. **Runtime Testing**
   ```bash
   # Frida commands
   frida -U {ipa} -l ios-hooks.js

   # objection commands
   objection -g {ipa} explore
   ```

8. **Static Analysis**
   - Objective-C classes
   - Swift symbols
   - Hardcoded secrets
   - Debug code

9. **Findings**
   | Issue | Class/Method | Severity | PoC |
   |-------|--------------|----------|-----|

10. **Recommendations**
    - Code changes
    - Entitlement fixes
    - Keychain hardening
"#
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NETWORK SECURITY GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_network_segmentation(&self, args: &std::collections::HashMap<String, String>) -> String {
        let topology = args
            .get("topology")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let zones = args
            .get("zones")
            .map(|s| s.as_str())
            .unwrap_or("not defined");

        format!(
            r#"# Network Segmentation Analysis

## Network Topology
{topology}

## Security Zones
{zones}

---

Analyze network segmentation:

1. **Zone Inventory**
   | Zone | CIDR | Purpose | Trust Level |
   |------|------|---------|-------------|
   | DMZ | | Public services | Low |
   | Internal | | Corporate | Medium |
   | Management | | Admin | High |
   | PCI | | Cardholder data | Critical |

2. **Segmentation Controls**
   - VLAN configuration
   - Routing ACLs
   - Firewall rules
   - Micro-segmentation
   - Software-defined

3. **Inter-Zone Traffic**
   | Source Zone | Dest Zone | Allowed | Denied | Review |
   |-------------|-----------|---------|--------|--------|

4. **Critical Path Analysis**
   - Internet → DMZ → Internal
   - Internal → Database
   - Management access
   - Backup flows

5. **Compliance Mapping**
   - PCI DSS zones
   - HIPAA segments
   - Regulatory requirements

6. **Gap Analysis**
   - Missing controls
   - Overly permissive rules
   - Flat network areas
   - Legacy exceptions

7. **Recommendations**
   - Quick wins
   - Strategic changes
   - Monitoring additions

8. **Network Diagram**
   ```
   [Internet]
       │
   [Firewall]
       │
   ┌───┴───┐
   │  DMZ  │──[IDS]
   └───┬───┘
       │
   [Internal FW]
       │
   ┌───┴───────────┐
   │   Internal    │
   └───────────────┘
   ```
"#
        )
    }

    fn gen_firewall_review(&self, args: &std::collections::HashMap<String, String>) -> String {
        let rules = args
            .get("rules")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let vendor = args.get("vendor").map(|s| s.as_str()).unwrap_or("generic");

        format!(
            r#"# Firewall Rule Set Review

## Rules Configuration
{rules}

## Firewall Vendor
{vendor}

---

Review firewall rules for security issues:

1. **Rule Analysis**
   | # | Source | Dest | Service | Action | Risk | Issue |
   |---|--------|------|---------|--------|------|-------|

2. **Common Issues**
   - Any/Any rules
   - Overly broad sources
   - Unnecessary services
   - Deprecated protocols
   - Shadow rules
   - Redundant rules

3. **Best Practices Check**
   - [ ] Default deny
   - [ ] Explicit allow rules
   - [ ] Logging enabled
   - [ ] No disabled rules
   - [ ] Rule documentation
   - [ ] Regular review

4. **High-Risk Rules**
   - Rules allowing inbound from any
   - Rules to sensitive networks
   - Broad outbound access
   - Management access rules

5. **Rule Optimization**
   - Consolidation opportunities
   - Object group usage
   - Rule ordering
   - Performance impact

6. **Compliance Check**
   | Requirement | Status | Rule # | Notes |
   |-------------|--------|--------|-------|

7. **Change Recommendations**
   | Current Rule | Recommended | Priority |
   |--------------|-------------|----------|

8. **Monitoring Gaps**
   - Logging configuration
   - Alert rules
   - Baseline traffic
   - Anomaly detection
"#
        )
    }

    fn gen_vpn_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let config = args
            .get("config")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let protocol = args.get("protocol").map(|s| s.as_str()).unwrap_or("ipsec");

        format!(
            r#"# VPN Security Assessment

## VPN Configuration
{config}

## VPN Protocol
{protocol}

---

Assess VPN security configuration:

1. **Protocol Security**
   - Protocol version
   - Cipher suites
   - Key exchange
   - Authentication
   - Perfect forward secrecy

2. **Authentication**
   - Authentication method
   - Certificate validation
   - MFA enforcement
   - Pre-shared key strength
   - User management

3. **Encryption**
   | Phase | Algorithm | Key Size | Status |
   |-------|-----------|----------|--------|
   | Phase 1 | | | |
   | Phase 2 | | | |
   | Data | | | |

4. **Tunnel Security**
   - Split tunneling
   - DNS leak prevention
   - IPv6 protection
   - Kill switch
   - Reconnection behavior

5. **Access Controls**
   - User authorization
   - Group policies
   - Network access rules
   - Time-based access
   - Geo-restrictions

6. **Logging & Monitoring**
   - Connection logs
   - Authentication logs
   - Traffic analysis
   - Anomaly detection

7. **Vulnerability Check**
   - Known CVEs
   - Configuration weaknesses
   - Downgrade attacks
   - Implementation flaws

8. **Recommendations**
   | Finding | Severity | Current | Recommended |
   |---------|----------|---------|-------------|

9. **Hardened Configuration**
   ```
   # Recommended configuration
   ```
"#
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ZERO TRUST GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_zero_trust_assessment(
        &self,
        args: &std::collections::HashMap<String, String>,
    ) -> String {
        let current_state = args
            .get("current_state")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let maturity = args
            .get("maturity")
            .map(|s| s.as_str())
            .unwrap_or("developing");

        format!(
            r#"# Zero Trust Architecture Assessment

## Current State
{current_state}

## Target Maturity
{maturity}

---

Assess Zero Trust maturity and roadmap:

1. **Zero Trust Pillars Assessment**
   | Pillar | Current | Target | Gap |
   |--------|---------|--------|-----|
   | Identity | | | |
   | Devices | | | |
   | Network | | | |
   | Applications | | | |
   | Data | | | |
   | Visibility | | | |
   | Automation | | | |

2. **Identity Pillar**
   - Identity verification
   - Strong authentication (MFA)
   - Continuous validation
   - Privileged access
   - Identity governance

3. **Device Pillar**
   - Device inventory
   - Health attestation
   - Endpoint protection
   - Mobile device management
   - Compliance enforcement

4. **Network Pillar**
   - Micro-segmentation
   - Encrypted transport
   - Network visibility
   - Software-defined perimeter
   - Zero trust network access

5. **Application Pillar**
   - Application discovery
   - Secure access
   - Workload protection
   - API security
   - DevSecOps

6. **Data Pillar**
   - Data classification
   - Encryption
   - DLP controls
   - Access monitoring
   - Rights management

7. **Maturity Model**
   ```
   Traditional → Initial → Developing → Defined → Managed → Optimizing
                    ↑
               Current State
   ```

8. **Roadmap**
   | Phase | Timeline | Focus Area | Deliverables |
   |-------|----------|------------|--------------|
   | 1 | 0-3 mo | | |
   | 2 | 3-6 mo | | |
   | 3 | 6-12 mo | | |

9. **Quick Wins**
   - Immediate actions
   - Low effort/high impact
   - Foundation building
"#
        )
    }

    fn gen_identity_security(&self, args: &std::collections::HashMap<String, String>) -> String {
        let provider = args
            .get("provider")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let scope = args.get("scope").map(|s| s.as_str()).unwrap_or("full");

        format!(
            r#"# Identity & Access Management Security Review

## Identity Provider
{provider}

## Assessment Scope
{scope}

---

Review IAM security:

1. **Identity Lifecycle**
   - Provisioning process
   - Deprovisioning automation
   - Access reviews
   - Orphan accounts
   - Service accounts

2. **Authentication Security**
   - MFA coverage
   - MFA methods
   - Password policies
   - Risk-based authentication
   - Passwordless adoption

3. **Authorization Controls**
   - RBAC implementation
   - Least privilege
   - Role mining
   - Entitlement review
   - Segregation of duties

4. **Privileged Access**
   - Privileged accounts inventory
   - PAM solution
   - Just-in-time access
   - Session recording
   - Break-glass procedures

5. **Federation & SSO**
   - IdP configuration
   - SAML/OIDC security
   - Claims mapping
   - Session management
   - Conditional access

6. **Identity Governance**
   - Access certification
   - Policy enforcement
   - Compliance reporting
   - Audit trails
   - SoD violations

7. **Findings Matrix**
   | Finding | Category | Risk | Remediation |
   |---------|----------|------|-------------|

8. **Metrics**
   - MFA adoption: X%
   - Average permissions: X
   - Orphan accounts: X
   - Access review completion: X%

9. **Recommendations**
   - Critical fixes
   - Process improvements
   - Technology additions
"#
        )
    }

    fn gen_microsegmentation(&self, args: &std::collections::HashMap<String, String>) -> String {
        let environment = args
            .get("environment")
            .map(|s| s.as_str())
            .unwrap_or("hybrid");
        let workloads = args.get("workloads").map(|s| s.as_str()).unwrap_or("mixed");

        format!(
            r#"# Microsegmentation Strategy

## Environment
{environment}

## Workload Types
{workloads}

---

Design microsegmentation strategy:

1. **Current State Assessment**
   - Existing segmentation
   - Network visibility
   - Traffic patterns
   - Application dependencies

2. **Workload Discovery**
   | Workload | Location | Tier | Dependencies | Critical |
   |----------|----------|------|--------------|----------|

3. **Policy Design**
   - Default deny
   - Application-centric policies
   - Identity-based rules
   - Environment isolation
   - Exception handling

4. **Implementation Approach**
   | Phase | Workloads | Mode | Timeline |
   |-------|-----------|------|----------|
   | 1 | Critical apps | Monitor | Week 1-2 |
   | 2 | Critical apps | Enforce | Week 3-4 |
   | 3 | Standard apps | Monitor | Week 5-6 |
   | 4 | Standard apps | Enforce | Week 7-8 |

5. **Policy Examples**
   ```yaml
   # Application tier policy
   source: web-tier
   destination: app-tier
   ports: [8080, 8443]
   action: allow
   ```

6. **Technology Options**
   | Solution | Pros | Cons | Fit |
   |----------|------|------|-----|
   | Host-based | | | |
   | Network-based | | | |
   | Cloud-native | | | |

7. **Operational Model**
   - Policy management
   - Change process
   - Monitoring & alerts
   - Troubleshooting
   - Compliance reporting

8. **Success Metrics**
   - Policy coverage
   - Violation rate
   - Mean time to policy
   - Drift detection

9. **Risks & Mitigations**
   - Application breakage
   - Performance impact
   - Operational overhead
"#
        )
    }

    fn gen_sase_assessment(&self, args: &std::collections::HashMap<String, String>) -> String {
        let current_tools = args
            .get("current_tools")
            .map(|s| s.as_str())
            .unwrap_or("not provided");
        let requirements = args
            .get("requirements")
            .map(|s| s.as_str())
            .unwrap_or("general");

        format!(
            r#"# SASE (Secure Access Service Edge) Assessment

## Current Security Tools
{current_tools}

## Business Requirements
{requirements}

---

Assess SASE readiness and strategy:

1. **Current State Inventory**
   | Component | Current Tool | Location | Status |
   |-----------|--------------|----------|--------|
   | SWG | | | |
   | CASB | | | |
   | ZTNA | | | |
   | FWaaS | | | |
   | SD-WAN | | | |

2. **SASE Components Assessment**
   - Secure Web Gateway (SWG)
   - Cloud Access Security Broker (CASB)
   - Zero Trust Network Access (ZTNA)
   - Firewall as a Service (FWaaS)
   - SD-WAN integration

3. **Requirements Analysis**
   | Requirement | Priority | Current | SASE Solution |
   |-------------|----------|---------|---------------|
   | Remote access | | | |
   | Cloud security | | | |
   | Branch connectivity | | | |
   | Data protection | | | |
   | Threat protection | | | |

4. **Architecture Options**
   ```
   Option A: Single Vendor SASE
   [Users] → [SASE PoP] → [Cloud Apps]
                       → [Data Center]

   Option B: Best-of-Breed
   [Users] → [SD-WAN] → [SSE] → [Apps]
   ```

5. **Vendor Evaluation**
   | Vendor | SWG | CASB | ZTNA | FWaaS | SD-WAN | Score |
   |--------|-----|------|------|-------|--------|-------|

6. **Migration Approach**
   | Phase | Component | Timeline | Dependencies |
   |-------|-----------|----------|--------------|
   | 1 | | | |
   | 2 | | | |
   | 3 | | | |

7. **Risk Assessment**
   - Vendor lock-in
   - Performance impact
   - Integration complexity
   - Compliance gaps
   - Cost implications

8. **Business Case**
   - Current TCO
   - SASE TCO
   - Efficiency gains
   - Risk reduction

9. **Recommendations**
   - Preferred approach
   - Vendor shortlist
   - Implementation roadmap
"#
        )
    }
}

impl Default for PromptRegistry {
    fn default() -> Self {
        Self::new()
    }
}
