//! MCP Sampling - Agentic capabilities for intelligent automation
//!
//! Sampling allows the server to request LLM completions for:
//! - Autonomous decision making during scans
//! - Intelligent target prioritization
//! - Adaptive reconnaissance
//! - Dynamic exploit selection

use std::collections::HashMap;

/// A sampling request from the server to the LLM
#[derive(Debug, Clone)]
pub struct SamplingRequest {
    /// Messages for the LLM
    pub messages: Vec<SamplingMessage>,
    /// Optional system prompt
    pub system_prompt: Option<String>,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Temperature for generation
    pub temperature: f32,
    /// Stop sequences
    pub stop_sequences: Vec<String>,
    /// Metadata about the request
    pub metadata: HashMap<String, String>,
}

/// A message in a sampling request
#[derive(Debug, Clone)]
pub struct SamplingMessage {
    /// Role: "user" or "assistant"
    pub role: String,
    /// Content of the message
    pub content: SamplingContent,
}

/// Content in a sampling message
#[derive(Debug, Clone)]
pub enum SamplingContent {
    /// Text content
    Text(String),
    /// Image content (base64)
    Image { data: String, mime_type: String },
    /// Resource reference
    Resource { uri: String, text: String },
}

/// Model preferences for sampling
#[derive(Debug, Clone, Default)]
pub struct ModelPreferences {
    /// Hints for model selection
    pub hints: Vec<ModelHint>,
    /// Cost priority (0.0 = quality, 1.0 = cost)
    pub cost_priority: f32,
    /// Speed priority (0.0 = quality, 1.0 = speed)
    pub speed_priority: f32,
    /// Intelligence priority (0.0 = speed/cost, 1.0 = intelligence)
    pub intelligence_priority: f32,
}

/// A hint for model selection
#[derive(Debug, Clone)]
pub struct ModelHint {
    /// Hint name
    pub name: String,
}

/// Response from a sampling request
#[derive(Debug, Clone)]
pub struct SamplingResponse {
    /// The generated content
    pub content: String,
    /// Model that was used
    pub model: String,
    /// Stop reason
    pub stop_reason: StopReason,
}

/// Reason for stopping generation
#[derive(Debug, Clone)]
pub enum StopReason {
    /// Natural end of response
    EndTurn,
    /// Hit a stop sequence
    StopSequence,
    /// Hit max tokens
    MaxTokens,
}

/// Sampling context for security operations
pub struct SamplingContext {
    /// Current operation type
    pub operation: OperationType,
    /// Target being analyzed
    pub target: Option<String>,
    /// Findings so far
    pub findings: Vec<Finding>,
    /// Decisions made
    pub decisions: Vec<Decision>,
}

/// Type of operation being performed
#[derive(Debug, Clone)]
pub enum OperationType {
    /// Reconnaissance
    Recon,
    /// Vulnerability scanning
    VulnScan,
    /// Exploitation
    Exploit,
    /// Post-exploitation
    PostExploit,
    /// Incident response
    IncidentResponse,
}

/// A finding during an operation
#[derive(Debug, Clone)]
pub struct Finding {
    /// Type of finding
    pub finding_type: FindingType,
    /// Description
    pub description: String,
    /// Severity
    pub severity: Severity,
    /// Raw data
    pub data: HashMap<String, String>,
}

/// Type of finding
#[derive(Debug, Clone)]
pub enum FindingType {
    OpenPort,
    Service,
    Vulnerability,
    Credential,
    Subdomain,
    Technology,
    Misconfiguration,
    DataExposure,
}

/// Severity level
#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A decision point requiring LLM input
#[derive(Debug, Clone)]
pub struct Decision {
    /// Decision ID
    pub id: String,
    /// Question to answer
    pub question: String,
    /// Options available
    pub options: Vec<DecisionOption>,
    /// Context for the decision
    pub context: String,
    /// The choice made (if decided)
    pub choice: Option<String>,
}

/// An option for a decision
#[derive(Debug, Clone)]
pub struct DecisionOption {
    /// Option ID
    pub id: String,
    /// Option description
    pub description: String,
    /// Risk level
    pub risk: Severity,
    /// Potential benefit
    pub benefit: String,
}

/// Sampling scenarios for security operations
pub struct SamplingScenarios;

impl SamplingScenarios {
    /// Create a sampling request for port discovery decisions
    pub fn port_discovery_decision(
        target: &str,
        open_ports: &[u16],
        services: &HashMap<u16, String>,
    ) -> SamplingRequest {
        let mut context = format!("Target: {}\n\nDiscovered open ports:\n", target);

        for port in open_ports {
            let service = services.get(port).map(|s| s.as_str()).unwrap_or("unknown");
            context.push_str(&format!("  - Port {}: {}\n", port, service));
        }

        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "{}\n\n## Decision Required\n\n\
                    Based on the discovered ports and services, which should be prioritized for deeper analysis?\n\n\
                    Consider:\n\
                    1. Ports commonly associated with vulnerabilities\n\
                    2. Services that might expose sensitive data\n\
                    3. Administrative interfaces\n\
                    4. Outdated or unusual services\n\n\
                    Respond with a JSON object:\n\
                    ```json\n\
                    {{\n\
                      \"priority_ports\": [port1, port2],\n\
                      \"reasoning\": \"explanation\",\n\
                      \"next_actions\": [\"action1\", \"action2\"]\n\
                    }}\n\
                    ```",
                    context
                )),
            }],
            system_prompt: Some(
                "You are a security assessment AI assistant helping with authorized penetration testing. \
                Analyze findings and provide strategic recommendations. Always prioritize based on risk and potential impact. \
                Respond only with the requested JSON format.".into()
            ),
            max_tokens: 500,
            temperature: 0.3,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), "port_discovery".into()),
                ("target".into(), target.into()),
            ]),
        }
    }

    /// Create a sampling request for vulnerability prioritization
    pub fn vuln_prioritization(
        target: &str,
        vulnerabilities: &[(String, String, f32)], // (CVE, description, CVSS)
    ) -> SamplingRequest {
        let mut vuln_list = String::new();
        for (cve, desc, cvss) in vulnerabilities {
            vuln_list.push_str(&format!("- {} (CVSS {}): {}\n", cve, cvss, desc));
        }

        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "## Target: {}\n\n## Identified Vulnerabilities:\n{}\n\n\
                    ## Task\n\n\
                    Prioritize these vulnerabilities for exploitation during this authorized pentest.\n\n\
                    Consider:\n\
                    1. CVSS score\n\
                    2. Exploit availability\n\
                    3. Potential for privilege escalation\n\
                    4. Data access implications\n\
                    5. Stealth requirements\n\n\
                    Respond with JSON:\n\
                    ```json\n\
                    {{\n\
                      \"priority_order\": [\"CVE-1\", \"CVE-2\"],\n\
                      \"immediate_action\": \"CVE-X\",\n\
                      \"reasoning\": \"explanation\",\n\
                      \"exploit_approach\": \"description\"\n\
                    }}\n\
                    ```",
                    target, vuln_list
                )),
            }],
            system_prompt: Some(
                "You are a security assessment AI. Help prioritize vulnerabilities for authorized testing. \
                Focus on impact and exploitability. Be concise.".into()
            ),
            max_tokens: 600,
            temperature: 0.2,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), "vuln_prioritization".into()),
                ("target".into(), target.into()),
            ]),
        }
    }

    /// Create a sampling request for subdomain analysis
    pub fn subdomain_analysis(domain: &str, subdomains: &[String]) -> SamplingRequest {
        let subdomain_list = subdomains.join("\n  - ");

        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "## Domain: {}\n\n## Discovered Subdomains:\n  - {}\n\n\
                    ## Analysis Required\n\n\
                    Analyze these subdomains and identify:\n\
                    1. High-value targets (admin panels, APIs, staging)\n\
                    2. Potentially forgotten/legacy systems\n\
                    3. Third-party integrations\n\
                    4. Development/test environments\n\n\
                    Respond with JSON:\n\
                    ```json\n\
                    {{\n\
                      \"high_value\": [\"sub1\", \"sub2\"],\n\
                      \"legacy_suspects\": [\"old1\"],\n\
                      \"investigation_priority\": [\"first\", \"second\"],\n\
                      \"reasoning\": \"explanation\"\n\
                    }}\n\
                    ```",
                    domain, subdomain_list
                )),
            }],
            system_prompt: Some(
                "You are a reconnaissance AI. Analyze subdomains for security assessment. \
                Identify high-value targets and potential weaknesses."
                    .into(),
            ),
            max_tokens: 500,
            temperature: 0.3,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), "subdomain_analysis".into()),
                ("domain".into(), domain.into()),
            ]),
        }
    }

    /// Create a sampling request for exploit selection
    pub fn exploit_selection(
        target: &str,
        vulnerability: &str,
        available_exploits: &[(String, String, bool)], // (name, type, verified)
        target_os: &str,
    ) -> SamplingRequest {
        let mut exploit_list = String::new();
        for (name, exploit_type, verified) in available_exploits {
            let verified_str = if *verified { "verified" } else { "unverified" };
            exploit_list.push_str(&format!(
                "- {} ({}, {})\n",
                name, exploit_type, verified_str
            ));
        }

        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "## Target: {} ({})\n## Vulnerability: {}\n\n\
                    ## Available Exploits:\n{}\n\n\
                    ## Selection Required\n\n\
                    Choose the best exploit for this authorized test. Consider:\n\
                    1. Reliability and verification status\n\
                    2. OS compatibility\n\
                    3. Stealth characteristics\n\
                    4. Payload flexibility\n\n\
                    Respond with JSON:\n\
                    ```json\n\
                    {{\n\
                      \"selected_exploit\": \"name\",\n\
                      \"backup_exploit\": \"name2\",\n\
                      \"payload_type\": \"reverse_shell|bind_shell|meterpreter\",\n\
                      \"considerations\": \"notes\",\n\
                      \"detection_risk\": \"low|medium|high\"\n\
                    }}\n\
                    ```",
                    target, target_os, vulnerability, exploit_list
                )),
            }],
            system_prompt: Some(
                "You are an exploitation advisor for authorized penetration testing. \
                Select the most appropriate exploit based on reliability and stealth."
                    .into(),
            ),
            max_tokens: 400,
            temperature: 0.2,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), "exploit_selection".into()),
                ("target".into(), target.into()),
                ("vulnerability".into(), vulnerability.into()),
            ]),
        }
    }

    /// Create a sampling request for next action decision
    pub fn next_action_decision(context: &SamplingContext) -> SamplingRequest {
        let mut findings_text = String::new();
        for finding in &context.findings {
            findings_text.push_str(&format!(
                "- [{:?}] {:?}: {}\n",
                finding.severity, finding.finding_type, finding.description
            ));
        }

        let operation_type = format!("{:?}", context.operation);
        let target = context.target.as_deref().unwrap_or("unknown");

        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "## Current Operation: {}\n## Target: {}\n\n\
                    ## Findings So Far:\n{}\n\n\
                    ## Decision Required\n\n\
                    What should be the next action in this security assessment?\n\n\
                    Options:\n\
                    1. Continue current phase with deeper analysis\n\
                    2. Move to next phase\n\
                    3. Investigate specific finding\n\
                    4. Pause for manual review\n\
                    5. Expand scope\n\n\
                    Respond with JSON:\n\
                    ```json\n\
                    {{\n\
                      \"action\": \"option_number\",\n\
                      \"specific_target\": \"what to focus on\",\n\
                      \"command\": \"rb command to run\",\n\
                      \"reasoning\": \"explanation\"\n\
                    }}\n\
                    ```",
                    operation_type, target, findings_text
                )),
            }],
            system_prompt: Some(
                "You are a security assessment coordinator. Guide the assessment based on findings. \
                Be strategic and thorough.".into()
            ),
            max_tokens: 400,
            temperature: 0.4,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), operation_type),
                ("target".into(), target.into()),
            ]),
        }
    }

    /// Create a sampling request for anomaly investigation
    pub fn anomaly_investigation(
        anomaly_type: &str,
        anomaly_data: &str,
        context: &str,
    ) -> SamplingRequest {
        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "## Anomaly Detected: {}\n\n## Data:\n{}\n\n## Context:\n{}\n\n\
                    ## Investigation Required\n\n\
                    Analyze this anomaly and determine:\n\
                    1. Is this a potential security issue?\n\
                    2. What additional investigation is needed?\n\
                    3. Should this be escalated?\n\n\
                    Respond with JSON:\n\
                    ```json\n\
                    {{\n\
                      \"is_security_issue\": true|false,\n\
                      \"confidence\": 0.0-1.0,\n\
                      \"severity\": \"critical|high|medium|low|info\",\n\
                      \"investigation_steps\": [\"step1\", \"step2\"],\n\
                      \"escalate\": true|false,\n\
                      \"reasoning\": \"explanation\"\n\
                    }}\n\
                    ```",
                    anomaly_type, anomaly_data, context
                )),
            }],
            system_prompt: Some(
                "You are a security analyst AI. Investigate anomalies and determine their significance. \
                Be thorough but avoid false positives.".into()
            ),
            max_tokens: 500,
            temperature: 0.3,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), "anomaly_investigation".into()),
                ("anomaly_type".into(), anomaly_type.into()),
            ]),
        }
    }

    /// Create a sampling request for attack path optimization
    pub fn attack_path_optimization(
        current_position: &str,
        available_paths: &[(String, String, String)], // (target, method, risk)
        objective: &str,
    ) -> SamplingRequest {
        let mut paths_text = String::new();
        for (i, (target, method, risk)) in available_paths.iter().enumerate() {
            paths_text.push_str(&format!(
                "{}. {} via {} (Risk: {})\n",
                i + 1,
                target,
                method,
                risk
            ));
        }

        SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: SamplingContent::Text(format!(
                    "## Current Position: {}\n## Objective: {}\n\n\
                    ## Available Attack Paths:\n{}\n\n\
                    ## Optimization Required\n\n\
                    Select the optimal attack path considering:\n\
                    1. Likelihood of success\n\
                    2. Detection risk\n\
                    3. Time to objective\n\
                    4. Value of intermediate targets\n\n\
                    Respond with JSON:\n\
                    ```json\n\
                    {{\n\
                      \"primary_path\": 1,\n\
                      \"backup_path\": 2,\n\
                      \"estimated_success\": 0.0-1.0,\n\
                      \"key_challenges\": [\"challenge1\"],\n\
                      \"reasoning\": \"explanation\"\n\
                    }}\n\
                    ```",
                    current_position, objective, paths_text
                )),
            }],
            system_prompt: Some(
                "You are an attack path optimizer for authorized security testing. \
                Select the most efficient path to the objective while managing risk."
                    .into(),
            ),
            max_tokens: 400,
            temperature: 0.3,
            stop_sequences: vec!["```".into()],
            metadata: HashMap::from([
                ("operation".into(), "path_optimization".into()),
                ("current_position".into(), current_position.into()),
                ("objective".into(), objective.into()),
            ]),
        }
    }
}

impl SamplingContext {
    /// Create a new sampling context
    pub fn new(operation: OperationType) -> Self {
        Self {
            operation,
            target: None,
            findings: Vec::new(),
            decisions: Vec::new(),
        }
    }

    /// Set the target
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add a decision
    pub fn add_decision(&mut self, decision: Decision) {
        self.decisions.push(decision);
    }

    /// Get pending decisions (no choice made yet)
    pub fn pending_decisions(&self) -> Vec<&Decision> {
        self.decisions
            .iter()
            .filter(|d| d.choice.is_none())
            .collect()
    }
}
