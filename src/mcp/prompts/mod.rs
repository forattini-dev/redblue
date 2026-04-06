//! MCP Prompts - Pre-built security prompt templates
//!
//! Prompts provide structured templates for common security tasks
//! that can be invoked by LLMs with optional arguments.
//!
//! This module is organized into:
//! - `types`: Core types for prompts (Prompt, PromptArgument, etc.)
//! - `generators`: Prompt content generators organized by security domain

pub mod generators;
pub mod types;

pub use types::{Args, ArgumentType, Prompt, PromptArgument, PromptMessage, PromptResult};

use std::collections::HashMap;

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
        PromptArgument::required("target", "Target domain, IP, or organization name")
          .with_type(ArgumentType::String)
          .with_examples(vec!["example.com", "192.168.1.1", "Acme Corp"]),
        PromptArgument::optional("scope", "Scope of reconnaissance")
          .with_enum(vec!["passive", "active", "full"]),
        PromptArgument::optional("time_limit", "Time limit for the engagement")
          .with_examples(vec!["1h", "4h", "1d"]),
      ],
    });

    self.prompts.push(Prompt {
      name: "subdomain-hunt".into(),
      description: "Enumerate and analyze subdomains for a target domain".into(),
      arguments: vec![
        PromptArgument::required("domain", "Target domain to enumerate")
          .with_type(ArgumentType::Domain)
          .with_examples(vec!["example.com", "target.org"]),
        PromptArgument::optional("depth", "Enumeration depth")
          .with_enum(vec!["quick", "standard", "deep"]),
      ],
    });

    self.prompts.push(Prompt {
      name: "osint-profile".into(),
      description: "Build comprehensive OSINT profile for a target".into(),
      arguments: vec![
        PromptArgument::required("target", "Target organization or domain")
          .with_examples(vec!["example.com", "Acme Corp"]),
        PromptArgument::optional("depth", "Investigation depth")
          .with_enum(vec!["shallow", "moderate", "deep"]),
      ],
    });

    self.prompts.push(Prompt {
      name: "attack-surface".into(),
      description: "Map external attack surface for an organization".into(),
      arguments: vec![
        PromptArgument::required("organization", "Target organization")
          .with_examples(vec!["example.com", "Acme Corp"]),
        PromptArgument::optional("include_subsidiaries", "Include subsidiaries")
          .with_enum(vec!["true", "false"]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // VULNERABILITY ASSESSMENT PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "vuln-assessment".into(),
      description: "Perform vulnerability assessment and prioritization".into(),
      arguments: vec![
        PromptArgument::required("target", "Target to assess (URL, IP, or domain)")
          .with_examples(vec!["192.168.1.1", "https://example.com", "example.com"]),
        PromptArgument::optional("scan_data", "Previous scan results to analyze"),
      ],
    });

    self.prompts.push(Prompt {
      name: "cve-analysis".into(),
      description: "Deep analysis of a specific CVE and its impact".into(),
      arguments: vec![
        PromptArgument::required("cve_id", "CVE identifier")
          .with_type(ArgumentType::CveId)
          .with_examples(vec!["CVE-2024-1234", "CVE-2021-44228"]),
        PromptArgument::optional("context", "Context about the target environment"),
      ],
    });

    self.prompts.push(Prompt {
      name: "patch-priority".into(),
      description: "Prioritize patches based on risk".into(),
      arguments: vec![
        PromptArgument::required("vulns", "List of vulnerabilities to prioritize"),
        PromptArgument::optional("environment", "Environment type").with_enum(vec![
          "production",
          "staging",
          "development",
        ]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // ATTACK PLANNING PROMPTS (AUTHORIZED USE ONLY)
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "attack-plan".into(),
      description: "Generate attack plan for authorized pentest".into(),
      arguments: vec![
        PromptArgument::required("target", "Target for the engagement"),
        PromptArgument::optional("findings", "Reconnaissance findings"),
        PromptArgument::optional("objective", "Attack objective").with_enum(vec![
          "initial_access",
          "privilege_escalation",
          "data_exfil",
        ]),
      ],
    });

    self.prompts.push(Prompt {
      name: "exploit-suggest".into(),
      description: "Suggest exploits for identified vulnerabilities".into(),
      arguments: vec![
        PromptArgument::required("vulnerabilities", "List of vulnerabilities"),
        PromptArgument::optional("target_os", "Target operating system"),
      ],
    });

    self.prompts.push(Prompt {
      name: "lateral-movement".into(),
      description: "Plan lateral movement strategies".into(),
      arguments: vec![
        PromptArgument::required("current_access", "Current access level"),
        PromptArgument::optional("network_map", "Network topology"),
        PromptArgument::optional("credentials", "Available credentials"),
      ],
    });

    self.prompts.push(Prompt {
      name: "persistence-analysis".into(),
      description: "Analyze persistence mechanism options".into(),
      arguments: vec![
        PromptArgument::optional("target_os", "Target OS")
          .with_enum(vec!["windows", "linux", "macos"]),
        PromptArgument::optional("access_level", "Current access level")
          .with_enum(vec!["user", "admin", "root"]),
        PromptArgument::optional("stealth", "Stealth requirement")
          .with_enum(vec!["low", "medium", "high"]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // THREAT & INCIDENT RESPONSE PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "threat-model".into(),
      description: "Create threat model for a system".into(),
      arguments: vec![
        PromptArgument::required("system", "System description"),
        PromptArgument::optional("assets", "Critical assets"),
        PromptArgument::optional("threat_actors", "Threat actors of concern"),
      ],
    });

    self.prompts.push(Prompt {
      name: "incident-response".into(),
      description: "Guide incident response process".into(),
      arguments: vec![
        PromptArgument::required("incident_type", "Type of incident"),
        PromptArgument::optional("indicators", "Known indicators"),
        PromptArgument::optional("affected_systems", "Affected systems"),
      ],
    });

    self.prompts.push(Prompt {
      name: "detection-rules".into(),
      description: "Generate detection rules for threats".into(),
      arguments: vec![
        PromptArgument::required("threat", "Threat to detect"),
        PromptArgument::optional("format", "Output format")
          .with_enum(vec!["sigma", "yara", "snort", "splunk"]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE & HARDENING PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "hardening-guide".into(),
      description: "Generate system hardening recommendations".into(),
      arguments: vec![
        PromptArgument::required("system", "System to harden"),
        PromptArgument::optional("baseline", "Security baseline")
          .with_enum(vec!["CIS", "STIG", "NIST", "custom"]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // REPORTING PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "pentest-report".into(),
      description: "Generate penetration test report".into(),
      arguments: vec![
        PromptArgument::required("findings", "Technical findings"),
        PromptArgument::optional("scope", "Engagement scope"),
        PromptArgument::optional("format", "Report format").with_enum(vec![
          "full",
          "executive",
          "technical",
        ]),
      ],
    });

    self.prompts.push(Prompt {
      name: "executive-summary".into(),
      description: "Generate executive summary from findings".into(),
      arguments: vec![
        PromptArgument::required("findings", "Technical findings"),
        PromptArgument::optional("audience", "Target audience").with_enum(vec![
          "c-suite",
          "board",
          "technical-leadership",
        ]),
      ],
    });

    self.prompts.push(Prompt {
      name: "risk-matrix".into(),
      description: "Generate risk matrix from vulnerabilities".into(),
      arguments: vec![
        PromptArgument::required("vulnerabilities", "List of vulnerabilities"),
        PromptArgument::optional("business_context", "Business context"),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // COMPLIANCE PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "compliance-check".into(),
      description: "Check compliance against a standard".into(),
      arguments: vec![
        PromptArgument::required("standard", "Compliance standard")
          .with_enum(vec!["PCI-DSS", "HIPAA", "SOC2", "ISO27001", "NIST"]),
        PromptArgument::optional("scope", "Assessment scope"),
      ],
    });

    self.prompts.push(Prompt {
      name: "gap-analysis".into(),
      description: "Perform security gap analysis".into(),
      arguments: vec![
        PromptArgument::required("current_state", "Current security state"),
        PromptArgument::optional("target_state", "Target security state"),
      ],
    });

    self.prompts.push(Prompt {
      name: "mitre-mapping".into(),
      description: "Map findings to MITRE ATT&CK".into(),
      arguments: vec![
        PromptArgument::required("findings", "Findings to map"),
        PromptArgument::optional("format", "Output format").with_enum(vec![
          "navigator",
          "table",
          "json",
        ]),
      ],
    });

    self.prompts.push(Prompt {
      name: "attack-simulation".into(),
      description: "Design attack simulation exercise".into(),
      arguments: vec![
        PromptArgument::optional("threat_actor", "Threat actor to emulate"),
        PromptArgument::optional("scope", "Simulation scope"),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // CLOUD SECURITY PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "cloud-audit".into(),
      description: "Audit cloud infrastructure security".into(),
      arguments: vec![
        PromptArgument::optional("provider", "Cloud provider")
          .with_enum(vec!["aws", "azure", "gcp", "multi"]),
        PromptArgument::optional("scope", "Audit scope"),
        PromptArgument::optional("compliance", "Compliance framework")
          .with_enum(vec!["cis", "soc2", "pci", "hipaa"]),
      ],
    });

    self.prompts.push(Prompt {
      name: "aws-security".into(),
      description: "AWS-specific security assessment".into(),
      arguments: vec![
        PromptArgument::optional("account_id", "AWS Account ID"),
        PromptArgument::optional("services", "Services to audit"),
      ],
    });

    self.prompts.push(Prompt {
      name: "azure-security".into(),
      description: "Azure-specific security assessment".into(),
      arguments: vec![
        PromptArgument::optional("subscription", "Azure subscription"),
        PromptArgument::optional("focus", "Focus area"),
      ],
    });

    self.prompts.push(Prompt {
      name: "gcp-security".into(),
      description: "GCP-specific security assessment".into(),
      arguments: vec![
        PromptArgument::optional("project", "GCP project"),
        PromptArgument::optional("services", "Services to audit"),
      ],
    });

    self.prompts.push(Prompt {
      name: "s3-audit".into(),
      description: "AWS S3 bucket security audit".into(),
      arguments: vec![
        PromptArgument::optional("bucket", "Bucket name or pattern"),
        PromptArgument::optional("deep_scan", "Perform deep content scan")
          .with_enum(vec!["true", "false"]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // CONTAINER & KUBERNETES PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "container-security".into(),
      description: "Container security assessment".into(),
      arguments: vec![
        PromptArgument::required("image", "Container image to assess"),
        PromptArgument::optional("runtime", "Container runtime").with_enum(vec![
          "docker",
          "containerd",
          "crio",
        ]),
      ],
    });

    self.prompts.push(Prompt {
      name: "k8s-security".into(),
      description: "Kubernetes security assessment".into(),
      arguments: vec![
        PromptArgument::optional("cluster", "Cluster name"),
        PromptArgument::optional("namespace", "Namespace to audit"),
        PromptArgument::optional("focus", "Focus area"),
      ],
    });

    self.prompts.push(Prompt {
      name: "dockerfile-review".into(),
      description: "Review Dockerfile for security issues".into(),
      arguments: vec![
        PromptArgument::optional("dockerfile", "Dockerfile content"),
        PromptArgument::optional("base_image", "Base image"),
      ],
    });

    self.prompts.push(Prompt {
      name: "helm-security".into(),
      description: "Review Helm chart security".into(),
      arguments: vec![
        PromptArgument::required("chart", "Helm chart name or path"),
        PromptArgument::optional("values", "Values configuration"),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // API SECURITY PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "api-security".into(),
      description: "API security assessment".into(),
      arguments: vec![
        PromptArgument::optional("api_spec", "API specification (OpenAPI/Swagger)"),
        PromptArgument::optional("auth_type", "Authentication type"),
      ],
    });

    self.prompts.push(Prompt {
      name: "graphql-security".into(),
      description: "GraphQL security testing".into(),
      arguments: vec![
        PromptArgument::required("endpoint", "GraphQL endpoint"),
        PromptArgument::optional("schema", "Schema source"),
      ],
    });

    self.prompts.push(Prompt {
      name: "oauth-audit".into(),
      description: "OAuth/OIDC security audit".into(),
      arguments: vec![
        PromptArgument::optional("provider", "OAuth provider"),
        PromptArgument::optional("flows", "OAuth flows used"),
      ],
    });

    self.prompts.push(Prompt {
      name: "jwt-analysis".into(),
      description: "JWT token security analysis".into(),
      arguments: vec![
        PromptArgument::optional("token", "JWT token to analyze"),
        PromptArgument::optional("context", "Usage context"),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // MOBILE SECURITY PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "mobile-security".into(),
      description: "Mobile application security assessment".into(),
      arguments: vec![
        PromptArgument::optional("platform", "Mobile platform")
          .with_enum(vec!["android", "ios", "both"]),
        PromptArgument::optional("app_name", "Application name"),
        PromptArgument::optional("scope", "Assessment scope"),
      ],
    });

    self.prompts.push(Prompt {
      name: "android-security".into(),
      description: "Android-specific security testing".into(),
      arguments: vec![
        PromptArgument::optional("apk", "APK file or package name"),
        PromptArgument::optional("manifest", "AndroidManifest.xml content"),
      ],
    });

    self.prompts.push(Prompt {
      name: "ios-security".into(),
      description: "iOS-specific security testing".into(),
      arguments: vec![
        PromptArgument::optional("ipa", "IPA file or bundle ID"),
        PromptArgument::optional("entitlements", "Entitlements content"),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // NETWORK SECURITY PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "network-segmentation".into(),
      description: "Analyze network segmentation".into(),
      arguments: vec![
        PromptArgument::optional("topology", "Network topology"),
        PromptArgument::optional("zones", "Security zones"),
      ],
    });

    self.prompts.push(Prompt {
      name: "firewall-review".into(),
      description: "Review firewall rule set".into(),
      arguments: vec![
        PromptArgument::optional("rules", "Firewall rules"),
        PromptArgument::optional("vendor", "Firewall vendor"),
      ],
    });

    self.prompts.push(Prompt {
      name: "vpn-security".into(),
      description: "Assess VPN security configuration".into(),
      arguments: vec![
        PromptArgument::optional("config", "VPN configuration"),
        PromptArgument::optional("protocol", "VPN protocol").with_enum(vec![
          "ipsec",
          "openvpn",
          "wireguard",
          "ssl",
        ]),
      ],
    });

    // ═══════════════════════════════════════════════════════════════════
    // ZERO TRUST PROMPTS
    // ═══════════════════════════════════════════════════════════════════

    self.prompts.push(Prompt {
      name: "zero-trust-assessment".into(),
      description: "Assess Zero Trust architecture maturity".into(),
      arguments: vec![
        PromptArgument::optional("current_state", "Current security state"),
        PromptArgument::optional("maturity", "Target maturity level").with_enum(vec![
          "initial",
          "developing",
          "defined",
          "managed",
          "optimizing",
        ]),
      ],
    });

    self.prompts.push(Prompt {
      name: "identity-security".into(),
      description: "Review IAM security".into(),
      arguments: vec![
        PromptArgument::optional("provider", "Identity provider"),
        PromptArgument::optional("scope", "Assessment scope"),
      ],
    });

    self.prompts.push(Prompt {
      name: "microsegmentation".into(),
      description: "Design microsegmentation strategy".into(),
      arguments: vec![
        PromptArgument::optional("environment", "Environment type")
          .with_enum(vec!["on-prem", "cloud", "hybrid"]),
        PromptArgument::optional("workloads", "Workload types"),
      ],
    });

    self.prompts.push(Prompt {
      name: "sase-assessment".into(),
      description: "Assess SASE readiness and strategy".into(),
      arguments: vec![
        PromptArgument::optional("current_tools", "Current security tools"),
        PromptArgument::optional("requirements", "Business requirements"),
      ],
    });
  }

  /// List all available prompts
  pub fn list_prompts(&self) -> Vec<&Prompt> {
    self.prompts.iter().collect()
  }

  /// Get a specific prompt by name with validated arguments
  pub fn get_prompt(
    &self,
    name: &str,
    args: &HashMap<String, String>,
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
    args: &HashMap<String, String>,
  ) -> Result<String, String> {
    match name {
      // Recon
      "recon-strategy" => Ok(generators::gen_recon_strategy(args)),
      "subdomain-hunt" => Ok(generators::gen_subdomain_hunt(args)),
      "osint-profile" => Ok(generators::gen_osint_profile(args)),
      "attack-surface" => Ok(generators::gen_attack_surface(args)),
      // Vulnerability
      "vuln-assessment" => Ok(generators::gen_vuln_assessment(args)),
      "cve-analysis" => Ok(generators::gen_cve_analysis(args)),
      "patch-priority" => Ok(generators::gen_patch_priority(args)),
      // Attack
      "attack-plan" => Ok(generators::gen_attack_plan(args)),
      "exploit-suggest" => Ok(generators::gen_exploit_suggest(args)),
      "lateral-movement" => Ok(generators::gen_lateral_movement(args)),
      "persistence-analysis" => Ok(generators::gen_persistence_analysis(args)),
      // Threat/IR
      "threat-model" => Ok(generators::gen_threat_model(args)),
      "incident-response" => Ok(generators::gen_incident_response(args)),
      "detection-rules" => Ok(generators::gen_detection_rules(args)),
      // Defense
      "hardening-guide" => Ok(generators::gen_hardening_guide(args)),
      // Reports
      "pentest-report" => Ok(generators::gen_pentest_report(args)),
      "executive-summary" => Ok(generators::gen_executive_summary(args)),
      "risk-matrix" => Ok(generators::gen_risk_matrix(args)),
      // Compliance
      "compliance-check" => Ok(generators::gen_compliance_check(args)),
      "gap-analysis" => Ok(generators::gen_gap_analysis(args)),
      "mitre-mapping" => Ok(generators::gen_mitre_mapping(args)),
      "attack-simulation" => Ok(generators::gen_attack_simulation(args)),
      // Cloud
      "cloud-audit" => Ok(generators::gen_cloud_audit(args)),
      "aws-security" => Ok(generators::gen_aws_security(args)),
      "azure-security" => Ok(generators::gen_azure_security(args)),
      "gcp-security" => Ok(generators::gen_gcp_security(args)),
      "s3-audit" => Ok(generators::gen_s3_audit(args)),
      // Container/K8s
      "container-security" => Ok(generators::gen_container_security(args)),
      "k8s-security" => Ok(generators::gen_k8s_security(args)),
      "dockerfile-review" => Ok(generators::gen_dockerfile_review(args)),
      "helm-security" => Ok(generators::gen_helm_security(args)),
      // API
      "api-security" => Ok(generators::gen_api_security(args)),
      "graphql-security" => Ok(generators::gen_graphql_security(args)),
      "oauth-audit" => Ok(generators::gen_oauth_audit(args)),
      "jwt-analysis" => Ok(generators::gen_jwt_analysis(args)),
      // Mobile
      "mobile-security" => Ok(generators::gen_mobile_security(args)),
      "android-security" => Ok(generators::gen_android_security(args)),
      "ios-security" => Ok(generators::gen_ios_security(args)),
      // Network
      "network-segmentation" => Ok(generators::gen_network_segmentation(args)),
      "firewall-review" => Ok(generators::gen_firewall_review(args)),
      "vpn-security" => Ok(generators::gen_vpn_security(args)),
      // Zero Trust
      "zero-trust-assessment" => Ok(generators::gen_zero_trust_assessment(args)),
      "identity-security" => Ok(generators::gen_identity_security(args)),
      "microsegmentation" => Ok(generators::gen_microsegmentation(args)),
      "sase-assessment" => Ok(generators::gen_sase_assessment(args)),
      _ => Err(format!("No generator for prompt: {}", name)),
    }
  }
}

impl Default for PromptRegistry {
  fn default() -> Self {
    Self::new()
  }
}
