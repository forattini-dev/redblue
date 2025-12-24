//! MCP Autonomous Orchestrator - LLM-guided security operations
//!
//! Integrates MCP Sampling with real security tools for autonomous
//! reconnaissance, vulnerability assessment, and guided exploitation.

use crate::mcp::sampling::{
    Finding, FindingType, OperationType, SamplingContent, SamplingContext, SamplingRequest,
    SamplingResponse, SamplingScenarios, Severity,
};
use crate::modules::network::scanner::PortScanner;
use crate::protocols::dns::{DnsClient, DnsRdata, DnsRecordType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};

/// Autonomous operation state
#[derive(Debug, Clone)]
pub enum OperationState {
    /// Not started
    Idle,
    /// Running initial reconnaissance
    Reconnaissance,
    /// Analyzing findings
    Analysis,
    /// Awaiting LLM guidance
    AwaitingGuidance,
    /// Executing recommended action
    Executing,
    /// Paused for manual review
    Paused,
    /// Completed
    Completed,
    /// Failed with error
    Failed(String),
}

/// An autonomous operation session
pub struct AutonomousOperation {
    /// Operation ID
    pub id: String,
    /// Target being assessed
    pub target: String,
    /// Current state
    pub state: OperationState,
    /// Sampling context with findings
    pub context: SamplingContext,
    /// Pending sampling request
    pub pending_request: Option<SamplingRequest>,
    /// History of actions taken
    pub action_history: Vec<ActionRecord>,
    /// Maximum iterations before requiring manual review
    pub max_iterations: u32,
    /// Current iteration
    pub iteration: u32,
    /// Verbosity level
    pub verbose: bool,
}

/// Record of an action taken
#[derive(Debug, Clone)]
pub struct ActionRecord {
    /// Action description
    pub action: String,
    /// Tool/command used
    pub tool: String,
    /// Result summary
    pub result: String,
    /// Timestamp
    pub timestamp: u64,
    /// Was this LLM-recommended
    pub llm_guided: bool,
}

/// Orchestrator for autonomous operations
pub struct Orchestrator {
    /// Active operations
    operations: HashMap<String, AutonomousOperation>,
    /// Counter for operation IDs
    id_counter: u64,
    /// Channel to send sampling requests
    sampling_tx: Option<Sender<SamplingRequest>>,
    /// Channel to receive sampling responses
    sampling_rx: Option<Receiver<SamplingResponse>>,
}

impl Orchestrator {
    /// Create new orchestrator
    pub fn new() -> Self {
        Self {
            operations: HashMap::new(),
            id_counter: 0,
            sampling_tx: None,
            sampling_rx: None,
        }
    }

    /// Set up sampling channels
    pub fn with_sampling_channels(
        mut self,
        tx: Sender<SamplingRequest>,
        rx: Receiver<SamplingResponse>,
    ) -> Self {
        self.sampling_tx = Some(tx);
        self.sampling_rx = Some(rx);
        self
    }

    /// Start a new autonomous reconnaissance operation
    pub fn start_recon(&mut self, target: &str) -> String {
        self.id_counter += 1;
        let id = format!("recon-{}", self.id_counter);

        let operation = AutonomousOperation {
            id: id.clone(),
            target: target.to_string(),
            state: OperationState::Idle,
            context: SamplingContext::new(OperationType::Recon).with_target(target),
            pending_request: None,
            action_history: Vec::new(),
            max_iterations: 10,
            iteration: 0,
            verbose: true,
        };

        self.operations.insert(id.clone(), operation);
        id
    }

    /// Start a new autonomous vulnerability scan
    pub fn start_vuln_scan(&mut self, target: &str) -> String {
        self.id_counter += 1;
        let id = format!("vuln-{}", self.id_counter);

        let operation = AutonomousOperation {
            id: id.clone(),
            target: target.to_string(),
            state: OperationState::Idle,
            context: SamplingContext::new(OperationType::VulnScan).with_target(target),
            pending_request: None,
            action_history: Vec::new(),
            max_iterations: 15,
            iteration: 0,
            verbose: true,
        };

        self.operations.insert(id.clone(), operation);
        id
    }

    /// Run one step of an operation (returns the pending request if guidance needed)
    pub fn step(&mut self, op_id: &str) -> Result<StepResult, String> {
        let op = self
            .operations
            .get_mut(op_id)
            .ok_or_else(|| format!("Operation not found: {}", op_id))?;

        op.iteration += 1;

        // Check iteration limit
        if op.iteration > op.max_iterations {
            op.state = OperationState::Paused;
            return Ok(StepResult::PausedForReview {
                reason: format!(
                    "Reached maximum iterations ({}). Manual review required.",
                    op.max_iterations
                ),
            });
        }

        match &op.state {
            OperationState::Idle => {
                op.state = OperationState::Reconnaissance;
                self.run_initial_recon(op_id)
            }
            OperationState::Reconnaissance => {
                // After recon, analyze and request guidance
                op.state = OperationState::Analysis;
                self.analyze_findings(op_id)
            }
            OperationState::Analysis => {
                // Create sampling request for guidance
                op.state = OperationState::AwaitingGuidance;
                self.request_guidance(op_id)
            }
            OperationState::AwaitingGuidance => {
                // Need response from LLM
                Ok(StepResult::NeedsGuidance {
                    request: op.pending_request.clone(),
                })
            }
            OperationState::Executing => {
                // Execute the recommended action, then back to analysis
                op.state = OperationState::Analysis;
                self.analyze_findings(op_id)
            }
            OperationState::Paused => Ok(StepResult::Paused),
            OperationState::Completed => Ok(StepResult::Completed {
                findings: op.context.findings.len(),
                actions: op.action_history.len(),
            }),
            OperationState::Failed(err) => Err(err.clone()),
        }
    }

    /// Provide LLM response to a pending request
    pub fn provide_guidance(
        &mut self,
        op_id: &str,
        response: SamplingResponse,
    ) -> Result<(), String> {
        // First check state (needs immutable borrow)
        {
            let op = self
                .operations
                .get(op_id)
                .ok_or_else(|| format!("Operation not found: {}", op_id))?;

            if !matches!(op.state, OperationState::AwaitingGuidance) {
                return Err("Operation not awaiting guidance".to_string());
            }
        }

        // Parse response (no borrow needed, function doesn't use self)
        let action = parse_guidance_response(&response.content)?;

        // Now get mutable borrow and update
        {
            let op = self
                .operations
                .get_mut(op_id)
                .ok_or_else(|| format!("Operation not found: {}", op_id))?;

            // Record the action
            op.action_history.push(ActionRecord {
                action: action.description.clone(),
                tool: action.tool.clone(),
                result: "pending".to_string(),
                timestamp: current_timestamp(),
                llm_guided: true,
            });

            // Clear pending request
            op.pending_request = None;

            // Update state
            op.state = OperationState::Executing;
        }

        // Execute the action
        self.execute_action(op_id, &action)?;

        Ok(())
    }

    /// Get operation status
    pub fn get_status(&self, op_id: &str) -> Option<OperationStatus> {
        self.operations.get(op_id).map(|op| OperationStatus {
            id: op.id.clone(),
            target: op.target.clone(),
            state: format!("{:?}", op.state),
            findings: op.context.findings.len(),
            actions: op.action_history.len(),
            iteration: op.iteration,
            max_iterations: op.max_iterations,
        })
    }

    /// List all operations
    pub fn list_operations(&self) -> Vec<OperationStatus> {
        self.operations
            .values()
            .map(|op| OperationStatus {
                id: op.id.clone(),
                target: op.target.clone(),
                state: format!("{:?}", op.state),
                findings: op.context.findings.len(),
                actions: op.action_history.len(),
                iteration: op.iteration,
                max_iterations: op.max_iterations,
            })
            .collect()
    }

    /// Resume a paused operation
    pub fn resume(&mut self, op_id: &str) -> Result<(), String> {
        let op = self
            .operations
            .get_mut(op_id)
            .ok_or_else(|| format!("Operation not found: {}", op_id))?;

        if matches!(op.state, OperationState::Paused) {
            op.state = OperationState::Analysis;
            op.iteration = 0; // Reset counter
            Ok(())
        } else {
            Err("Operation is not paused".to_string())
        }
    }

    /// Stop an operation
    pub fn stop(&mut self, op_id: &str) -> Result<(), String> {
        let op = self
            .operations
            .get_mut(op_id)
            .ok_or_else(|| format!("Operation not found: {}", op_id))?;

        op.state = OperationState::Completed;
        Ok(())
    }

    // Private helper methods

    fn run_initial_recon(&mut self, op_id: &str) -> Result<StepResult, String> {
        let op = self
            .operations
            .get_mut(op_id)
            .ok_or_else(|| format!("Operation not found: {}", op_id))?;

        let target = op.target.clone();

        // 1. Quick port scan (common ports)
        let common_ports: Vec<u16> = vec![
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389,
            5432, 5900, 6379, 8080, 8443, 27017,
        ];

        let mut open_ports = Vec::new();
        let mut services: HashMap<u16, String> = HashMap::new();

        // Resolve target if it's a hostname
        let target_ip = if let Ok(ip) = target.parse::<IpAddr>() {
            ip.to_string()
        } else {
            // DNS lookup
            let dns = DnsClient::new("8.8.8.8");
            match dns.query(&target, DnsRecordType::A) {
                Ok(answers) => {
                    // Extract first IP from answers
                    answers
                        .first()
                        .and_then(|a| {
                            if let DnsRdata::A(ip) = &a.data {
                                Some(ip.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| target.clone())
                }
                Err(_) => target.clone(),
            }
        };

        // Record DNS finding
        op.context.add_finding(Finding {
            finding_type: FindingType::Service,
            description: format!("Target resolved to: {}", target_ip),
            severity: Severity::Info,
            data: HashMap::from([
                ("hostname".to_string(), target.clone()),
                ("ip".to_string(), target_ip.clone()),
            ]),
        });

        // Port scan - need to parse target IP
        let parsed_ip: IpAddr = target_ip
            .parse()
            .map_err(|_| format!("Invalid IP address: {}", target_ip))?;

        let scanner = PortScanner::new(parsed_ip)
            .with_threads(50)
            .with_timeout(1500);

        // Scan the common ports
        let scan_results = scanner.scan_ports(&common_ports);

        for result in &scan_results {
            if result.is_open {
                open_ports.push(result.port);

                // Basic service detection
                let service = detect_service(result.port);
                services.insert(result.port, service.clone());

                op.context.add_finding(Finding {
                    finding_type: FindingType::OpenPort,
                    description: format!("Open port: {} ({})", result.port, service),
                    severity: if is_high_value_port(result.port) {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                    data: HashMap::from([
                        ("port".to_string(), result.port.to_string()),
                        ("service".to_string(), service),
                    ]),
                });
            }
        }

        // Record action
        op.action_history.push(ActionRecord {
            action: format!("Initial port scan of {} common ports", common_ports.len()),
            tool: "rb.network.scan".to_string(),
            result: format!("Found {} open ports", open_ports.len()),
            timestamp: current_timestamp(),
            llm_guided: false,
        });

        Ok(StepResult::Progress {
            message: format!(
                "Initial recon complete. Found {} open ports on {}",
                open_ports.len(),
                target
            ),
            findings: open_ports.len(),
        })
    }

    fn analyze_findings(&mut self, op_id: &str) -> Result<StepResult, String> {
        let op = self.operations.get(op_id).ok_or("Operation not found")?;

        let high_severity = op
            .context
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .count();

        let medium_severity = op
            .context
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count();

        Ok(StepResult::Progress {
            message: format!(
                "Analysis: {} total findings ({} high/critical, {} medium)",
                op.context.findings.len(),
                high_severity,
                medium_severity
            ),
            findings: op.context.findings.len(),
        })
    }

    fn request_guidance(&mut self, op_id: &str) -> Result<StepResult, String> {
        let op = self
            .operations
            .get_mut(op_id)
            .ok_or_else(|| format!("Operation not found: {}", op_id))?;

        // Build sampling request based on operation type and findings
        let request = match op.context.operation {
            OperationType::Recon => {
                // Extract open ports and services
                let mut ports = Vec::new();
                let mut services = HashMap::new();

                for finding in &op.context.findings {
                    if matches!(finding.finding_type, FindingType::OpenPort) {
                        if let Some(port_str) = finding.data.get("port") {
                            if let Ok(port) = port_str.parse::<u16>() {
                                ports.push(port);
                                if let Some(svc) = finding.data.get("service") {
                                    services.insert(port, svc.clone());
                                }
                            }
                        }
                    }
                }

                SamplingScenarios::port_discovery_decision(&op.target, &ports, &services)
            }
            OperationType::VulnScan => {
                // Extract vulnerabilities
                let vulns: Vec<(String, String, f32)> = op
                    .context
                    .findings
                    .iter()
                    .filter(|f| matches!(f.finding_type, FindingType::Vulnerability))
                    .filter_map(|f| {
                        let id = f.data.get("cve_id")?.clone();
                        let desc = f.description.clone();
                        let cvss = f
                            .data
                            .get("cvss")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(5.0);
                        Some((id, desc, cvss))
                    })
                    .collect();

                if vulns.is_empty() {
                    // No vulns yet, request next action
                    SamplingScenarios::next_action_decision(&op.context)
                } else {
                    SamplingScenarios::vuln_prioritization(&op.target, &vulns)
                }
            }
            _ => SamplingScenarios::next_action_decision(&op.context),
        };

        op.pending_request = Some(request.clone());

        Ok(StepResult::NeedsGuidance {
            request: Some(request),
        })
    }

    fn execute_action(&mut self, op_id: &str, action: &RecommendedAction) -> Result<(), String> {
        let op = self
            .operations
            .get_mut(op_id)
            .ok_or_else(|| format!("Operation not found: {}", op_id))?;

        // Execute based on tool type
        match action.tool.as_str() {
            "rb.network.scan" => {
                // Additional port scanning
                if let Some(ports_str) = action.args.get("ports") {
                    let ports: Vec<u16> = ports_str
                        .split(',')
                        .filter_map(|p| p.trim().parse().ok())
                        .collect();

                    // Parse target IP
                    if let Ok(target_ip) = op.target.parse::<IpAddr>() {
                        let scanner = PortScanner::new(target_ip)
                            .with_threads(20)
                            .with_timeout(2000);
                        let scan_results = scanner.scan_ports(&ports);

                        for result in &scan_results {
                            if result.is_open {
                                let service = detect_service(result.port);
                                op.context.add_finding(Finding {
                                    finding_type: FindingType::OpenPort,
                                    description: format!(
                                        "Deep scan found: {} ({})",
                                        result.port, service
                                    ),
                                    severity: if is_high_value_port(result.port) {
                                        Severity::High
                                    } else {
                                        Severity::Medium
                                    },
                                    data: HashMap::from([
                                        ("port".to_string(), result.port.to_string()),
                                        ("service".to_string(), service),
                                        ("deep_scan".to_string(), "true".to_string()),
                                    ]),
                                });
                            }
                        }
                    }
                }
            }
            "rb.vuln.search" => {
                // Mark that we need vuln scan
                op.context.add_finding(Finding {
                    finding_type: FindingType::Technology,
                    description: "Vulnerability scan requested".to_string(),
                    severity: Severity::Info,
                    data: HashMap::from([("action".to_string(), "vuln_scan".to_string())]),
                });
            }
            "rb.recon.subdomains" => {
                // Mark subdomain enum needed
                op.context.add_finding(Finding {
                    finding_type: FindingType::Subdomain,
                    description: "Subdomain enumeration requested".to_string(),
                    severity: Severity::Info,
                    data: HashMap::from([("action".to_string(), "subdomain_enum".to_string())]),
                });
            }
            _ => {
                // Unknown tool, log it
                op.context.add_finding(Finding {
                    finding_type: FindingType::Technology,
                    description: format!("Action requested: {}", action.description),
                    severity: Severity::Info,
                    data: HashMap::from([("tool".to_string(), action.tool.clone())]),
                });
            }
        }

        // Update action history
        if let Some(last) = op.action_history.last_mut() {
            last.result = "executed".to_string();
        }

        Ok(())
    }
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a step in an operation
#[derive(Debug)]
pub enum StepResult {
    /// Operation made progress
    Progress { message: String, findings: usize },
    /// Operation needs LLM guidance
    NeedsGuidance { request: Option<SamplingRequest> },
    /// Operation paused for manual review
    PausedForReview { reason: String },
    /// Operation is paused
    Paused,
    /// Operation completed
    Completed { findings: usize, actions: usize },
}

/// Operation status summary
#[derive(Debug, Clone)]
pub struct OperationStatus {
    pub id: String,
    pub target: String,
    pub state: String,
    pub findings: usize,
    pub actions: usize,
    pub iteration: u32,
    pub max_iterations: u32,
}

/// Recommended action from LLM
#[derive(Debug, Clone)]
struct RecommendedAction {
    description: String,
    tool: String,
    args: HashMap<String, String>,
}

// Helper functions

/// Parse LLM guidance response into a recommended action
fn parse_guidance_response(response: &str) -> Result<RecommendedAction, String> {
    // Try to extract JSON from the response
    let json_start = response.find('{').unwrap_or(0);
    let json_end = response.rfind('}').map(|i| i + 1).unwrap_or(response.len());
    let json_str = &response[json_start..json_end];

    // Simple JSON parsing for our expected fields
    let mut action = RecommendedAction {
        description: "Continue analysis".to_string(),
        tool: "rb.network.scan".to_string(),
        args: HashMap::new(),
    };

    // Parse priority_ports if present
    if let Some(start) = json_str.find("\"priority_ports\"") {
        if let Some(arr_start) = json_str[start..].find('[') {
            if let Some(arr_end) = json_str[start + arr_start..].find(']') {
                let arr_content = &json_str[start + arr_start + 1..start + arr_start + arr_end];
                let ports: Vec<&str> = arr_content.split(',').collect();
                if !ports.is_empty() {
                    action.description = format!("Deep scan priority ports: {:?}", ports);
                    action.tool = "rb.network.scan".to_string();
                    action.args.insert(
                        "ports".to_string(),
                        ports.iter().map(|p| p.trim()).collect::<Vec<_>>().join(","),
                    );
                }
            }
        }
    }

    // Parse next_actions if present
    if let Some(start) = json_str.find("\"next_actions\"") {
        if let Some(arr_start) = json_str[start..].find('[') {
            if let Some(arr_end) = json_str[start + arr_start..].find(']') {
                let arr_content = &json_str[start + arr_start + 1..start + arr_start + arr_end];
                if !arr_content.is_empty() {
                    // First action suggestion
                    if arr_content.to_lowercase().contains("vuln") {
                        action.description = "Search for vulnerabilities".to_string();
                        action.tool = "rb.vuln.search".to_string();
                    } else if arr_content.to_lowercase().contains("subdomain") {
                        action.description = "Enumerate subdomains".to_string();
                        action.tool = "rb.recon.subdomains".to_string();
                    } else if arr_content.to_lowercase().contains("tls")
                        || arr_content.to_lowercase().contains("ssl")
                    {
                        action.description = "Audit TLS configuration".to_string();
                        action.tool = "rb.tls.audit".to_string();
                    }
                }
            }
        }
    }

    // Parse command if present
    if let Some(start) = json_str.find("\"command\"") {
        if let Some(cmd_start) = json_str[start..].find('"').map(|i| start + i + 1) {
            if let Some(cmd_end) = json_str[cmd_start..].find('"') {
                let cmd = &json_str[cmd_start..cmd_start + cmd_end];
                if cmd.starts_with("rb ") {
                    action.tool = cmd.to_string();
                    action.description = format!("Execute: {}", cmd);
                }
            }
        }
    }

    Ok(action)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn detect_service(port: u16) -> String {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        27017 => "MongoDB",
        _ => "Unknown",
    }
    .to_string()
}

fn is_high_value_port(port: u16) -> bool {
    matches!(
        port,
        22 | 23 | 135 | 139 | 445 | 1433 | 3306 | 3389 | 5432 | 5900 | 6379 | 27017
    )
}

/// Convert sampling request to JSON for MCP transport
pub fn sampling_request_to_json(request: &SamplingRequest) -> String {
    let mut messages_json = Vec::new();
    for msg in &request.messages {
        let content_json = match &msg.content {
            SamplingContent::Text(text) => {
                format!(r#"{{"type":"text","text":"{}"}}"#, escape_json(text))
            }
            SamplingContent::Image { data, mime_type } => {
                format!(
                    r#"{{"type":"image","data":"{}","mimeType":"{}"}}"#,
                    data, mime_type
                )
            }
            SamplingContent::Resource { uri, text } => {
                format!(
                    r#"{{"type":"resource","resource":{{"uri":"{}","text":"{}"}}}}"#,
                    uri,
                    escape_json(text)
                )
            }
        };
        messages_json.push(format!(
            r#"{{"role":"{}","content":{}}}"#,
            msg.role, content_json
        ));
    }

    let system = request
        .system_prompt
        .as_ref()
        .map(|s| format!(r#","systemPrompt":"{}""#, escape_json(s)))
        .unwrap_or_default();

    let stop_sequences = if request.stop_sequences.is_empty() {
        String::new()
    } else {
        let seqs: Vec<String> = request
            .stop_sequences
            .iter()
            .map(|s| format!(r#""{}""#, escape_json(s)))
            .collect();
        format!(r#","stopSequences":[{}]"#, seqs.join(","))
    };

    format!(
        r#"{{"messages":[{}],"maxTokens":{},"temperature":{}{}{},"includeContext":"thisServer"}}"#,
        messages_json.join(","),
        request.max_tokens,
        request.temperature,
        system,
        stop_sequences
    )
}

fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_start_recon() {
        let mut orchestrator = Orchestrator::new();
        let op_id = orchestrator.start_recon("127.0.0.1");
        assert!(op_id.starts_with("recon-"));

        let status = orchestrator.get_status(&op_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().state, "Idle");
    }

    #[test]
    fn test_detect_service() {
        assert_eq!(detect_service(22), "SSH");
        assert_eq!(detect_service(80), "HTTP");
        assert_eq!(detect_service(3306), "MySQL");
        assert_eq!(detect_service(12345), "Unknown");
    }

    #[test]
    fn test_is_high_value_port() {
        assert!(is_high_value_port(22));
        assert!(is_high_value_port(3389));
        assert!(!is_high_value_port(80));
        assert!(!is_high_value_port(443));
    }
}
