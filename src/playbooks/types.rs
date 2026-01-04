use crate::crypto::uuid::Uuid;
use crate::serde_json::{JsonDecode, JsonEncode, Map, Value};
/// Playbook Type Definitions
///
/// Intelligent security playbooks for Red Team operations.
/// MITRE ATT&CK mapping is INTERNAL ONLY - never exposed to users.
///
/// ## Design Philosophy
///
/// Playbooks follow a Red Team methodology structure:
/// - Objective: What we're trying to achieve
/// - Pre-conditions: What must be true before starting
/// - Attack Flow: Step-by-step execution phases
/// - Expected Evidence: What artifacts/findings indicate success
/// - Common Failed Controls: Defenses that often miss this attack
/// - Variations: Alternative approaches for the same objective
///
/// ## Internal MITRE Mapping
///
/// Each playbook step can be tagged with ATT&CK technique IDs internally.
/// This enables:
/// - Correlation with threat intelligence
/// - Coverage analysis
/// - Reporting (when user opts in)
///
/// Users see: "Establish Reverse Shell"
/// Internal tag: T1059.004 (Unix Shell)
use std::collections::HashMap;
use std::time::Duration;

use crate::scripts::{Finding, FindingSeverity};

fn map_get_value(map: &Map<String, Value>, key: &str) -> Value {
    map.get(key).cloned().unwrap_or(Value::Null)
}

fn map_get_array(map: &Map<String, Value>, key: &str) -> Value {
    map.get(key).cloned().unwrap_or(Value::Array(Vec::new()))
}

fn duration_to_value(duration: Duration) -> Value {
    (duration.as_secs() as u64).to_json_value()
}

fn duration_from_value(value: Value, default: Duration) -> Result<Duration, String> {
    match value {
        Value::Null => Ok(default),
        other => Ok(Duration::from_secs(u64::from_json_value(other)?)),
    }
}

fn tagged_value(tag: &str, value: Value) -> Value {
    let mut map = Map::new();
    map.insert(tag.to_string(), value);
    Value::Object(map)
}

fn map_get_bool(map: &Map<String, Value>, key: &str, default: bool) -> Result<bool, String> {
    match map.get(key) {
        Some(value) => bool::from_json_value(value.clone()),
        None => Ok(default),
    }
}

fn normalize_key(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Playbook phase - major stages of execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaybookPhase {
    /// Initial reconnaissance and target validation
    Recon,
    /// Establishing initial access
    InitialAccess,
    /// Post-exploitation activities
    Execution,
    /// Maintaining access
    Persistence,
    /// Escalating privileges
    PrivilegeEscalation,
    /// Avoiding detection
    DefenseEvasion,
    /// Accessing credentials
    CredentialAccess,
    /// Discovering network/system info
    Discovery,
    /// Moving through the network
    LateralMovement,
    /// Gathering target data
    Collection,
    /// Command and Control communications
    C2,
    /// Extracting data
    Exfiltration,
    /// Achieving objectives
    Impact,
    /// Cleanup and reporting
    Cleanup,
}

impl PlaybookPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlaybookPhase::Recon => "Reconnaissance",
            PlaybookPhase::InitialAccess => "Initial Access",
            PlaybookPhase::Execution => "Execution",
            PlaybookPhase::Persistence => "Persistence",
            PlaybookPhase::PrivilegeEscalation => "Privilege Escalation",
            PlaybookPhase::DefenseEvasion => "Defense Evasion",
            PlaybookPhase::CredentialAccess => "Credential Access",
            PlaybookPhase::Discovery => "Discovery",
            PlaybookPhase::LateralMovement => "Lateral Movement",
            PlaybookPhase::Collection => "Collection",
            PlaybookPhase::C2 => "Command & Control",
            PlaybookPhase::Exfiltration => "Exfiltration",
            PlaybookPhase::Impact => "Impact",
            PlaybookPhase::Cleanup => "Cleanup",
        }
    }
}

impl std::fmt::Display for PlaybookPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Target type for playbooks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetType {
    /// Single host (IP or hostname)
    Host,
    /// Web application (URL)
    WebApp,
    /// Network range (CIDR)
    Network,
    /// Domain for recon
    Domain,
    /// Cloud environment
    Cloud,
    /// Internal network (post-compromise)
    Internal,
    /// Container environment
    Container,
    /// API endpoint
    Api,
}

impl TargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetType::Host => "Host",
            TargetType::WebApp => "Web Application",
            TargetType::Network => "Network",
            TargetType::Domain => "Domain",
            TargetType::Cloud => "Cloud",
            TargetType::Internal => "Internal Network",
            TargetType::Container => "Container",
            TargetType::Api => "API",
        }
    }
}

/// Operating system target
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOS {
    Any,
    Linux,
    Windows,
    MacOS,
    FreeBSD,
    Android,
    IOS,
}

impl TargetOS {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetOS::Any => "Any",
            TargetOS::Linux => "Linux",
            TargetOS::Windows => "Windows",
            TargetOS::MacOS => "macOS",
            TargetOS::FreeBSD => "FreeBSD",
            TargetOS::Android => "Android",
            TargetOS::IOS => "iOS",
        }
    }
}

/// Risk level for playbooks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    /// Passive, no direct interaction
    Passive,
    /// Safe active probing
    Low,
    /// Standard active testing
    Medium,
    /// May trigger alerts
    High,
    /// Likely to trigger alerts, potential disruption
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Passive => "Passive",
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }

    /// Check if this risk level requires explicit consent
    pub fn requires_consent(&self) -> bool {
        matches!(self, RiskLevel::High | RiskLevel::Critical)
    }
}

/// Playbook metadata
#[derive(Debug, Clone)]
pub struct PlaybookMetadata {
    /// Unique identifier (e.g., "reverse-shell-linux")
    pub id: String,
    /// Human-readable name (e.g., "Reverse Shell Assessment (Linux)")
    pub name: String,
    /// Brief description of objective
    pub description: String,
    /// Detailed objective statement
    pub objective: String,
    /// Author
    pub author: String,
    /// Version
    pub version: String,
    /// Target types this playbook applies to
    pub target_types: Vec<TargetType>,
    /// Target operating systems
    pub target_os: Vec<TargetOS>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Estimated duration (human-readable)
    pub estimated_duration: String,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Internal-only: MITRE technique IDs (never exposed to users)
    #[doc(hidden)]
    pub mitre_techniques: Vec<String>,
}

impl Default for PlaybookMetadata {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            description: String::new(),
            objective: String::new(),
            author: "redblue".to_string(),
            version: "1.0".to_string(),
            target_types: Vec::new(),
            target_os: vec![TargetOS::Any],
            risk_level: RiskLevel::Medium,
            estimated_duration: "5-15 minutes".to_string(),
            tags: Vec::new(),
            mitre_techniques: Vec::new(),
        }
    }
}

/// Pre-condition that must be met before playbook execution
#[derive(Debug, Clone)]
pub struct PreCondition {
    /// Description of the condition
    pub description: String,
    /// Check function name or script ID
    pub check: Option<String>,
    /// Whether this is mandatory
    pub required: bool,
    /// Notes for the operator
    pub notes: Option<String>,
}

impl PreCondition {
    pub fn new(description: &str) -> Self {
        Self {
            description: description.to_string(),
            check: None,
            required: true,
            notes: None,
        }
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn with_check(mut self, check: &str) -> Self {
        self.check = Some(check.to_string());
        self
    }

    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = Some(notes.to_string());
        self
    }
}

/// A single step in the attack flow
#[derive(Debug, Clone)]
pub struct PlaybookStep {
    /// Step number (1-indexed)
    pub number: u8,
    /// Phase this step belongs to
    pub phase: PlaybookPhase,
    /// Human-readable name (e.g., "Establish Reverse Shell")
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Script IDs to execute (from builtin or TOML scripts)
    pub scripts: Vec<String>,
    /// CLI commands to suggest/run
    pub commands: Vec<String>,
    /// Manual instructions if automated execution not possible
    pub manual_instructions: Option<String>,
    /// Success criteria
    pub success_criteria: Vec<String>,
    /// What to do if this step fails
    pub on_failure: StepFailureAction,
    /// Dependencies on previous steps (by number)
    pub depends_on: Vec<u8>,
    /// Whether this step can be skipped
    pub optional: bool,
    /// Timeout for this step
    pub timeout: Duration,
    /// Internal-only: MITRE technique ID (never exposed)
    #[doc(hidden)]
    pub mitre_technique: Option<String>,
    /// Internal-only: MITRE sub-technique ID
    #[doc(hidden)]
    pub mitre_subtechnique: Option<String>,
    /// Parallel execution group - steps in same group run concurrently
    pub parallel_group: Option<u8>,
    /// Conditional execution criteria
    pub condition: StepCondition,
    /// Type of evidence this step collects
    pub evidence_type: Option<EvidenceType>,
}

impl PlaybookStep {
    pub fn new(number: u8, phase: PlaybookPhase, name: &str) -> Self {
        Self {
            number,
            phase,
            name: name.to_string(),
            description: String::new(),
            scripts: Vec::new(),
            commands: Vec::new(),
            manual_instructions: None,
            success_criteria: Vec::new(),
            on_failure: StepFailureAction::Continue,
            depends_on: Vec::new(),
            optional: false,
            timeout: Duration::from_secs(300), // 5 minutes default
            mitre_technique: None,
            mitre_subtechnique: None,
            parallel_group: None,
            condition: StepCondition::Always,
            evidence_type: None,
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_script(mut self, script_id: &str) -> Self {
        self.scripts.push(script_id.to_string());
        self
    }

    pub fn with_command(mut self, cmd: &str) -> Self {
        self.commands.push(cmd.to_string());
        self
    }

    pub fn with_manual(mut self, instructions: &str) -> Self {
        self.manual_instructions = Some(instructions.to_string());
        self
    }

    pub fn with_success(mut self, criteria: &str) -> Self {
        self.success_criteria.push(criteria.to_string());
        self
    }

    /// Set step to continue on failure (convenience for on_fail)
    pub fn with_failure(mut self, _message: &str) -> Self {
        // Note: message is available for logging but action is Continue
        self.on_failure = StepFailureAction::Continue;
        self
    }

    pub fn on_fail(mut self, action: StepFailureAction) -> Self {
        self.on_failure = action;
        self
    }

    pub fn depends(mut self, step: u8) -> Self {
        self.depends_on.push(step);
        self
    }

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Internal: Set MITRE mapping (not exposed to users)
    #[doc(hidden)]
    pub fn with_mitre(mut self, technique: &str, subtechnique: Option<&str>) -> Self {
        self.mitre_technique = Some(technique.to_string());
        self.mitre_subtechnique = subtechnique.map(|s| s.to_string());
        self
    }

    /// Set parallel execution group (steps in same group run concurrently)
    pub fn parallel(mut self, group: u8) -> Self {
        self.parallel_group = Some(group);
        self
    }

    /// Set execution condition
    pub fn when(mut self, condition: StepCondition) -> Self {
        self.condition = condition;
        self
    }

    /// Set evidence type this step collects
    pub fn collects(mut self, evidence: EvidenceType) -> Self {
        self.evidence_type = Some(evidence);
        self
    }

    /// Set custom timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout = Duration::from_secs(seconds);
        self
    }
}

/// What to do when a step fails
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepFailureAction {
    /// Continue to next step
    Continue,
    /// Abort the entire playbook
    Abort,
    /// Skip dependent steps
    SkipDependents,
    /// Retry the step
    Retry { max_attempts: u8 },
    /// Ask user what to do
    AskUser,
}

/// Conditional execution criteria for steps
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepCondition {
    /// Always execute this step
    Always,
    /// Execute only if step N succeeded
    OnSuccess(u8),
    /// Execute only if step N failed
    OnFailure(u8),
    /// Execute only if specific evidence type was collected
    OnEvidence(EvidenceType),
    /// Execute based on a custom expression (evaluated at runtime)
    Custom(String),
    /// Execute if a previous action (from database) matches criteria
    /// Format: "action_type:outcome" e.g., "scan:success" or "exploit:failed"
    OnPreviousAction(String),
    /// Execute only if target was NOT previously scanned successfully
    IfNotScanned,
    /// Execute only if target has previous vulnerabilities
    IfHasVulnerabilities,
}

impl Default for StepCondition {
    fn default() -> Self {
        Self::Always
    }
}

/// Classification of evidence collected during playbook execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    /// Username/password pairs, hashes, tokens
    Credentials,
    /// CVE, misconfig, weakness findings
    Vulnerability,
    /// Visual proof of access/impact
    Screenshot,
    /// PCAP or traffic capture
    NetworkCapture,
    /// Downloaded files, configs, etc.
    FileArtifact,
    /// Raw command/tool output
    CommandOutput,
    /// System or service information
    SystemInfo,
    /// Network topology data
    NetworkMap,
    /// Access tokens, session cookies
    SessionData,
}

impl EvidenceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::Vulnerability => "vulnerability",
            Self::Screenshot => "screenshot",
            Self::NetworkCapture => "network_capture",
            Self::FileArtifact => "file_artifact",
            Self::CommandOutput => "command_output",
            Self::SystemInfo => "system_info",
            Self::NetworkMap => "network_map",
            Self::SessionData => "session_data",
        }
    }
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Expected evidence from playbook execution
#[derive(Debug, Clone)]
pub struct ExpectedEvidence {
    /// Description of the evidence
    pub description: String,
    /// Where to find it
    pub location: String,
    /// How to identify it
    pub indicators: Vec<String>,
    /// Severity if found
    pub severity: FindingSeverity,
}

impl ExpectedEvidence {
    pub fn new(description: &str) -> Self {
        Self {
            description: description.to_string(),
            location: String::new(),
            indicators: Vec::new(),
            severity: FindingSeverity::Info,
        }
    }

    pub fn at(mut self, location: &str) -> Self {
        self.location = location.to_string();
        self
    }

    pub fn with_indicator(mut self, indicator: &str) -> Self {
        self.indicators.push(indicator.to_string());
        self
    }

    pub fn severity(mut self, severity: FindingSeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Controls that commonly fail to detect this attack
#[derive(Debug, Clone)]
pub struct FailedControl {
    /// Control name (e.g., "Egress Filtering")
    pub name: String,
    /// Why it fails
    pub reason: String,
    /// Remediation advice
    pub remediation: String,
}

impl FailedControl {
    pub fn new(name: &str, reason: &str) -> Self {
        Self {
            name: name.to_string(),
            reason: reason.to_string(),
            remediation: String::new(),
        }
    }

    pub fn with_fix(mut self, fix: &str) -> Self {
        self.remediation = fix.to_string();
        self
    }
}

/// Alternative approach/variation
#[derive(Debug, Clone, Default)]
pub struct PlaybookVariation {
    /// Name of the variation
    pub name: String,
    /// Description of the variation
    pub description: String,
    /// When to use this variation
    pub use_when: String,
    /// Command for this variation
    pub command: Option<String>,
    /// Steps that differ
    pub different_steps: Vec<PlaybookStep>,
    /// Additional notes
    pub notes: Option<String>,
}

impl PlaybookVariation {
    pub fn new(name: &str, use_when: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            use_when: use_when.to_string(),
            command: None,
            different_steps: Vec::new(),
            notes: None,
        }
    }

    pub fn with_step(mut self, step: PlaybookStep) -> Self {
        self.different_steps.push(step);
        self
    }

    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = Some(notes.to_string());
        self
    }
}

/// Complete playbook definition
#[derive(Debug, Clone)]
pub struct Playbook {
    /// Metadata
    pub metadata: PlaybookMetadata,
    /// Pre-conditions
    pub preconditions: Vec<PreCondition>,
    /// Attack flow steps
    pub steps: Vec<PlaybookStep>,
    /// Expected evidence
    pub evidence: Vec<ExpectedEvidence>,
    /// Controls that commonly fail
    pub failed_controls: Vec<FailedControl>,
    /// Variations/alternatives
    pub variations: Vec<PlaybookVariation>,
    /// Kill chain mapping (user-friendly version)
    pub kill_chain: Vec<KillChainPhase>,
    /// Playbook to run on success
    pub on_success: Option<String>,
    /// Playbook to run on failure
    pub on_failure: Option<String>,
    /// Assertions to validate at playbook end
    pub assertions: Vec<Assertion>,
}

impl Playbook {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            metadata: PlaybookMetadata {
                id: id.to_string(),
                name: name.to_string(),
                ..Default::default()
            },
            preconditions: Vec::new(),
            steps: Vec::new(),
            evidence: Vec::new(),
            failed_controls: Vec::new(),
            variations: Vec::new(),
            kill_chain: Vec::new(),
            on_success: None,
            on_failure: None,
            assertions: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.metadata.description = desc.to_string();
        self
    }

    pub fn with_objective(mut self, obj: &str) -> Self {
        self.metadata.objective = obj.to_string();
        self
    }

    pub fn for_target(mut self, target: TargetType) -> Self {
        self.metadata.target_types.push(target);
        self
    }

    pub fn for_os(mut self, os: TargetOS) -> Self {
        self.metadata.target_os.push(os);
        self
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.metadata.risk_level = risk;
        self
    }

    pub fn with_duration(mut self, duration: &str) -> Self {
        self.metadata.estimated_duration = duration.to_string();
        self
    }

    /// Add a tag for categorization
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.metadata.tags.push(tag.to_string());
        self
    }

    pub fn add_precondition(mut self, precondition: PreCondition) -> Self {
        self.preconditions.push(precondition);
        self
    }

    pub fn add_step(mut self, step: PlaybookStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn add_evidence(mut self, evidence: ExpectedEvidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn add_failed_control(mut self, control: FailedControl) -> Self {
        self.failed_controls.push(control);
        self
    }

    pub fn add_variation(mut self, variation: PlaybookVariation) -> Self {
        self.variations.push(variation);
        self
    }

    /// Add an assertion to validate at playbook end
    pub fn add_assertion(mut self, assertion: Assertion) -> Self {
        self.assertions.push(assertion);
        self
    }

    pub fn with_kill_chain(mut self, phase: KillChainPhase) -> Self {
        self.kill_chain.push(phase);
        self
    }

    /// Internal: Add MITRE technique (not exposed)
    #[doc(hidden)]
    pub fn with_mitre(mut self, technique: &str) -> Self {
        self.metadata.mitre_techniques.push(technique.to_string());
        self
    }

    /// Get total number of steps
    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    /// Get steps by phase
    pub fn steps_for_phase(&self, phase: PlaybookPhase) -> Vec<&PlaybookStep> {
        self.steps.iter().filter(|s| s.phase == phase).collect()
    }

    /// Check if playbook is safe (no high-risk steps)
    pub fn is_safe(&self) -> bool {
        self.metadata.risk_level < RiskLevel::High
    }

    pub fn with_next_playbook(mut self, playbook_id: &str) -> Self {
        self.on_success = Some(playbook_id.to_string());
        self
    }

    pub fn on_failure_playbook(mut self, playbook_id: &str) -> Self {
        self.on_failure = Some(playbook_id.to_string());
        self
    }
}

/// Kill Chain phase (user-friendly version, not MITRE-specific)
#[derive(Debug, Clone)]
pub struct KillChainPhase {
    /// Phase name
    pub name: String,
    /// Description
    pub description: String,
    /// Step numbers that belong to this phase
    pub step_numbers: Vec<u8>,
}

impl KillChainPhase {
    /// Reconnaissance phase
    #[allow(non_snake_case)]
    pub fn Reconnaissance() -> Self {
        Self::new("Reconnaissance", "Active/passive information gathering")
    }

    /// Initial Access phase
    #[allow(non_snake_case)]
    pub fn InitialAccess() -> Self {
        Self::new("Initial Access", "Gaining initial entry to target")
    }

    /// Execution phase
    #[allow(non_snake_case)]
    pub fn Execution() -> Self {
        Self::new("Execution", "Running malicious code")
    }

    /// Exploitation phase
    #[allow(non_snake_case)]
    pub fn Exploitation() -> Self {
        Self::new("Exploitation", "Exploiting vulnerabilities")
    }

    /// Privilege Escalation phase
    #[allow(non_snake_case)]
    pub fn PrivilegeEscalation() -> Self {
        Self::new("Privilege Escalation", "Gaining higher privileges")
    }

    /// Lateral Movement phase
    #[allow(non_snake_case)]
    pub fn LateralMovement() -> Self {
        Self::new("Lateral Movement", "Moving within the network")
    }

    /// Command and Control phase
    #[allow(non_snake_case)]
    pub fn CommandAndControl() -> Self {
        Self::new("Command and Control", "C2 communication")
    }

    /// Exfiltration phase
    #[allow(non_snake_case)]
    pub fn Exfiltration() -> Self {
        Self::new("Exfiltration", "Data theft/extraction")
    }

    /// Installation/Persistence phase
    #[allow(non_snake_case)]
    pub fn Installation() -> Self {
        Self::new("Installation", "Installing persistence mechanisms")
    }

    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            step_numbers: Vec::new(),
        }
    }

    pub fn with_steps(mut self, steps: &[u8]) -> Self {
        self.step_numbers = steps.to_vec();
        self
    }
}

/// Playbook execution context
#[derive(Debug, Clone)]
pub struct PlaybookContext {
    /// Target for this execution
    pub target: String,
    /// Additional targets (for network playbooks)
    pub additional_targets: Vec<String>,
    /// Unique session ID for this execution
    pub session_id: String,
    /// User-provided arguments
    pub args: HashMap<String, String>,
    /// Data gathered during execution
    pub gathered_data: HashMap<String, String>,
    /// Allow intrusive/high-risk steps
    pub allow_intrusive: bool,
    /// Timeout per step
    pub step_timeout: Duration,
    /// Total timeout for playbook
    pub total_timeout: Duration,
    /// Verbosity level (0-3)
    pub verbosity: u8,
    /// Dry run mode (don't execute, just show what would happen)
    pub dry_run: bool,
}

impl PlaybookContext {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            additional_targets: Vec::new(),
            session_id: Uuid::new_v4().to_string(),
            args: HashMap::new(),
            gathered_data: HashMap::new(),
            allow_intrusive: false,
            step_timeout: Duration::from_secs(300),
            total_timeout: Duration::from_secs(3600),
            verbosity: 1,
            dry_run: false,
        }
    }

    pub fn with_intrusive(mut self) -> Self {
        self.allow_intrusive = true;
        self
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    pub fn set_arg(&mut self, key: &str, value: &str) {
        self.args.insert(key.to_string(), value.to_string());
    }

    pub fn get_arg(&self, key: &str) -> Option<&str> {
        self.args.get(key).map(|s| s.as_str())
    }

    pub fn store_data(&mut self, key: &str, value: &str) {
        self.gathered_data
            .insert(key.to_string(), value.to_string());
    }

    pub fn get_data(&self, key: &str) -> Option<&str> {
        self.gathered_data.get(key).map(|s| s.as_str())
    }
}

/// Result of executing a single playbook step
#[derive(Debug, Clone)]
pub struct StepExecutionResult {
    /// Step number
    pub step_number: u8,
    /// Step name
    pub step_name: String,
    /// Whether the step succeeded
    pub success: bool,
    /// Status message
    pub status: String,
    /// Output/findings
    pub output: Vec<String>,
    /// Findings from scripts
    pub findings: Vec<Finding>,
    /// Data extracted for subsequent steps
    pub extracted_data: HashMap<String, String>,
    /// Duration
    pub duration: Duration,
    /// Whether this was skipped
    pub skipped: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl StepExecutionResult {
    pub fn new(step: &PlaybookStep) -> Self {
        Self {
            step_number: step.number,
            step_name: step.name.clone(),
            success: false,
            status: "Not executed".to_string(),
            output: Vec::new(),
            findings: Vec::new(),
            extracted_data: HashMap::new(),
            duration: Duration::ZERO,
            skipped: false,
            error: None,
        }
    }

    pub fn success(mut self) -> Self {
        self.success = true;
        self.status = "Completed".to_string();
        self
    }

    pub fn skipped(mut self, reason: &str) -> Self {
        self.skipped = true;
        self.status = format!("Skipped: {}", reason);
        self
    }

    pub fn failed(mut self, error: &str) -> Self {
        self.success = false;
        self.error = Some(error.to_string());
        self.status = "Failed".to_string();
        self
    }
}

/// Result of executing a complete playbook
#[derive(Debug, Clone)]
pub struct PlaybookExecutionResult {
    /// Playbook ID
    pub playbook_id: String,
    /// Playbook name
    pub playbook_name: String,
    /// Target
    pub target: String,
    /// Overall success
    pub success: bool,
    /// Step results
    pub step_results: Vec<StepExecutionResult>,
    /// All findings aggregated
    pub all_findings: Vec<Finding>,
    /// Total duration
    pub duration: Duration,
    /// Summary message
    pub summary: String,
    /// Steps completed
    pub steps_completed: usize,
    /// Steps skipped
    pub steps_skipped: usize,
    /// Steps failed
    pub steps_failed: usize,
    /// Next playbook to execute (if any)
    pub next_playbook: Option<String>,
    /// Assertion results (empty if no assertions defined)
    pub assertion_results: Vec<AssertionResult>,
}

impl PlaybookExecutionResult {
    pub fn new(playbook: &Playbook, target: &str) -> Self {
        Self {
            playbook_id: playbook.metadata.id.clone(),
            playbook_name: playbook.metadata.name.clone(),
            target: target.to_string(),
            success: false,
            step_results: Vec::new(),
            all_findings: Vec::new(),
            duration: Duration::ZERO,
            summary: String::new(),
            steps_completed: 0,
            steps_skipped: 0,
            steps_failed: 0,
            next_playbook: None,
            assertion_results: Vec::new(),
        }
    }

    pub fn add_step_result(&mut self, result: StepExecutionResult) {
        if result.success {
            self.steps_completed += 1;
        } else if result.skipped {
            self.steps_skipped += 1;
        } else {
            self.steps_failed += 1;
        }
        self.all_findings.extend(result.findings.clone());
        self.step_results.push(result);
    }

    pub fn finalize(&mut self, duration: Duration) {
        self.duration = duration;
        self.success = self.steps_failed == 0;
        self.summary = format!(
            "{} steps completed, {} skipped, {} failed in {:.1}s",
            self.steps_completed,
            self.steps_skipped,
            self.steps_failed,
            duration.as_secs_f64()
        );
    }
}

// ============================================================================
// PLAYBOOK CHAINING
// ============================================================================

/// Condition for executing a chained playbook
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainCondition {
    /// Always execute this playbook
    Always,
    /// Execute only if previous playbook succeeded
    OnSuccess,
    /// Execute only if previous playbook failed
    OnFailure,
    /// Execute only if specific evidence type was collected
    OnEvidence(EvidenceType),
    /// Execute only if specific finding severity was reached
    OnSeverity(crate::scripts::FindingSeverity),
}

impl Default for ChainCondition {
    fn default() -> Self {
        Self::Always
    }
}

/// A playbook within a chain with execution conditions
#[derive(Debug, Clone)]
pub struct ChainedPlaybook {
    /// ID of the playbook to execute
    pub playbook_id: String,
    /// Condition that must be met to execute
    pub condition: ChainCondition,
    /// Output variable mappings (previous output name -> this input name)
    pub output_mapping: std::collections::HashMap<String, String>,
    /// Whether to continue chain if this playbook fails
    pub continue_on_failure: bool,
}

impl ChainedPlaybook {
    pub fn new(playbook_id: &str) -> Self {
        Self {
            playbook_id: playbook_id.to_string(),
            condition: ChainCondition::Always,
            output_mapping: std::collections::HashMap::new(),
            continue_on_failure: false,
        }
    }

    pub fn when(mut self, condition: ChainCondition) -> Self {
        self.condition = condition;
        self
    }

    pub fn map_output(mut self, from: &str, to: &str) -> Self {
        self.output_mapping.insert(from.to_string(), to.to_string());
        self
    }

    pub fn continue_on_fail(mut self) -> Self {
        self.continue_on_failure = true;
        self
    }
}

/// A chain of playbooks for complex multi-stage attack flows
#[derive(Debug, Clone)]
pub struct PlaybookChain {
    /// Chain identifier
    pub id: String,
    /// Human-friendly name
    pub name: String,
    /// Description of what this chain accomplishes
    pub description: String,
    /// Ordered list of playbooks to execute
    pub playbooks: Vec<ChainedPlaybook>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Risk level (highest of contained playbooks)
    pub risk_level: RiskLevel,
}

impl PlaybookChain {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            playbooks: Vec::new(),
            tags: Vec::new(),
            risk_level: RiskLevel::Low,
        }
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk_level = risk;
        self
    }

    pub fn add_playbook(mut self, playbook: ChainedPlaybook) -> Self {
        self.playbooks.push(playbook);
        self
    }

    /// Add a playbook that always executes
    pub fn then(self, playbook_id: &str) -> Self {
        self.add_playbook(ChainedPlaybook::new(playbook_id))
    }

    /// Add a playbook that only executes on success
    pub fn on_success(self, playbook_id: &str) -> Self {
        self.add_playbook(ChainedPlaybook::new(playbook_id).when(ChainCondition::OnSuccess))
    }

    /// Add a playbook that only executes if evidence was collected
    pub fn on_evidence(self, playbook_id: &str, evidence: EvidenceType) -> Self {
        self.add_playbook(
            ChainedPlaybook::new(playbook_id).when(ChainCondition::OnEvidence(evidence)),
        )
    }

    pub fn total_playbooks(&self) -> usize {
        self.playbooks.len()
    }
}

// ============================================================================
// ASSERTIONS
// ============================================================================

/// Assertion operator for comparing values
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionOperator {
    /// Value must equal expected
    Equals,
    /// Value must not equal expected
    NotEquals,
    /// Value must be greater than expected
    GreaterThan,
    /// Value must be less than expected
    LessThan,
    /// Value must be greater than or equal to expected
    GreaterOrEqual,
    /// Value must be less than or equal to expected
    LessOrEqual,
    /// Value must contain substring
    Contains,
    /// Value must not contain substring
    NotContains,
    /// Value must match regex pattern
    Matches,
    /// Value must be true (for boolean conditions)
    IsTrue,
    /// Value must be false (for boolean conditions)
    IsFalse,
    /// Value must exist (not null/empty)
    Exists,
    /// Value must not exist (null/empty)
    NotExists,
}

impl AssertionOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equals => "==",
            Self::NotEquals => "!=",
            Self::GreaterThan => ">",
            Self::LessThan => "<",
            Self::GreaterOrEqual => ">=",
            Self::LessOrEqual => "<=",
            Self::Contains => "contains",
            Self::NotContains => "not_contains",
            Self::Matches => "matches",
            Self::IsTrue => "is_true",
            Self::IsFalse => "is_false",
            Self::Exists => "exists",
            Self::NotExists => "not_exists",
        }
    }
}

/// An assertion to validate playbook execution results
#[derive(Debug, Clone)]
pub struct Assertion {
    /// Human-readable description
    pub description: String,
    /// Variable or metric name to check (e.g., "steps_completed", "findings.count", "evidence.credentials")
    pub subject: String,
    /// Comparison operator
    pub operator: AssertionOperator,
    /// Expected value (for comparison operators)
    pub expected: Option<String>,
    /// Whether this assertion is critical (failure aborts playbook)
    pub critical: bool,
    /// Custom failure message
    pub failure_message: Option<String>,
}

impl Assertion {
    pub fn new(description: &str, subject: &str) -> Self {
        Self {
            description: description.to_string(),
            subject: subject.to_string(),
            operator: AssertionOperator::Exists,
            expected: None,
            critical: false,
            failure_message: None,
        }
    }

    pub fn equals(mut self, expected: &str) -> Self {
        self.operator = AssertionOperator::Equals;
        self.expected = Some(expected.to_string());
        self
    }

    pub fn not_equals(mut self, expected: &str) -> Self {
        self.operator = AssertionOperator::NotEquals;
        self.expected = Some(expected.to_string());
        self
    }

    pub fn greater_than(mut self, expected: &str) -> Self {
        self.operator = AssertionOperator::GreaterThan;
        self.expected = Some(expected.to_string());
        self
    }

    pub fn less_than(mut self, expected: &str) -> Self {
        self.operator = AssertionOperator::LessThan;
        self.expected = Some(expected.to_string());
        self
    }

    pub fn contains(mut self, expected: &str) -> Self {
        self.operator = AssertionOperator::Contains;
        self.expected = Some(expected.to_string());
        self
    }

    pub fn matches(mut self, pattern: &str) -> Self {
        self.operator = AssertionOperator::Matches;
        self.expected = Some(pattern.to_string());
        self
    }

    pub fn is_true(mut self) -> Self {
        self.operator = AssertionOperator::IsTrue;
        self
    }

    pub fn is_false(mut self) -> Self {
        self.operator = AssertionOperator::IsFalse;
        self
    }

    pub fn exists(mut self) -> Self {
        self.operator = AssertionOperator::Exists;
        self
    }

    pub fn critical(mut self) -> Self {
        self.critical = true;
        self
    }

    pub fn with_message(mut self, msg: &str) -> Self {
        self.failure_message = Some(msg.to_string());
        self
    }
}

/// Result of evaluating an assertion
#[derive(Debug, Clone)]
pub struct AssertionResult {
    /// The assertion that was evaluated
    pub description: String,
    /// Whether the assertion passed
    pub passed: bool,
    /// Actual value found
    pub actual_value: Option<String>,
    /// Expected value
    pub expected_value: Option<String>,
    /// Error or failure message
    pub message: Option<String>,
}

impl AssertionResult {
    pub fn passed(description: &str) -> Self {
        Self {
            description: description.to_string(),
            passed: true,
            actual_value: None,
            expected_value: None,
            message: None,
        }
    }

    pub fn failed(description: &str, message: &str) -> Self {
        Self {
            description: description.to_string(),
            passed: false,
            actual_value: None,
            expected_value: None,
            message: Some(message.to_string()),
        }
    }

    pub fn with_values(mut self, actual: &str, expected: &str) -> Self {
        self.actual_value = Some(actual.to_string());
        self.expected_value = Some(expected.to_string());
        self
    }
}

/// Result of executing a playbook chain
#[derive(Debug, Clone)]
pub struct ChainExecutionResult {
    /// Chain that was executed
    pub chain_id: String,
    /// Target that was assessed
    pub target: String,
    /// Overall success
    pub success: bool,
    /// Results from each playbook
    pub playbook_results: Vec<PlaybookExecutionResult>,
    /// Total duration
    pub duration: Duration,
    /// Combined findings
    pub all_findings: Vec<crate::scripts::Finding>,
    /// Summary message
    pub summary: String,
}

impl ChainExecutionResult {
    pub fn new(chain: &PlaybookChain, target: &str) -> Self {
        Self {
            chain_id: chain.id.clone(),
            target: target.to_string(),
            success: false,
            playbook_results: Vec::new(),
            duration: Duration::ZERO,
            all_findings: Vec::new(),
            summary: String::new(),
        }
    }

    pub fn add_playbook_result(&mut self, result: PlaybookExecutionResult) {
        self.all_findings.extend(result.all_findings.clone());
        self.playbook_results.push(result);
    }

    pub fn finalize(&mut self, duration: Duration) {
        self.duration = duration;
        self.success = self.playbook_results.iter().all(|r| r.success);
        let completed = self.playbook_results.iter().filter(|r| r.success).count();
        self.summary = format!(
            "{}/{} playbooks succeeded in {:.1}s",
            completed,
            self.playbook_results.len(),
            duration.as_secs_f64()
        );
    }
}

impl JsonEncode for PlaybookPhase {
    fn to_json_value(&self) -> Value {
        let s = match self {
            PlaybookPhase::Recon => "Recon",
            PlaybookPhase::InitialAccess => "InitialAccess",
            PlaybookPhase::Execution => "Execution",
            PlaybookPhase::Persistence => "Persistence",
            PlaybookPhase::PrivilegeEscalation => "PrivilegeEscalation",
            PlaybookPhase::DefenseEvasion => "DefenseEvasion",
            PlaybookPhase::CredentialAccess => "CredentialAccess",
            PlaybookPhase::Discovery => "Discovery",
            PlaybookPhase::LateralMovement => "LateralMovement",
            PlaybookPhase::Collection => "Collection",
            PlaybookPhase::C2 => "C2",
            PlaybookPhase::Exfiltration => "Exfiltration",
            PlaybookPhase::Impact => "Impact",
            PlaybookPhase::Cleanup => "Cleanup",
        };
        Value::String(s.to_string())
    }
}

impl JsonDecode for PlaybookPhase {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let s = String::from_json_value(value)?;
        let key = s
            .to_lowercase()
            .replace('&', "and")
            .replace(' ', "")
            .replace('-', "");
        match key.as_str() {
            "recon" | "reconnaissance" => Ok(PlaybookPhase::Recon),
            "initialaccess" => Ok(PlaybookPhase::InitialAccess),
            "execution" => Ok(PlaybookPhase::Execution),
            "persistence" => Ok(PlaybookPhase::Persistence),
            "privilegeescalation" => Ok(PlaybookPhase::PrivilegeEscalation),
            "defenseevasion" => Ok(PlaybookPhase::DefenseEvasion),
            "credentialaccess" => Ok(PlaybookPhase::CredentialAccess),
            "discovery" => Ok(PlaybookPhase::Discovery),
            "lateralmovement" => Ok(PlaybookPhase::LateralMovement),
            "collection" => Ok(PlaybookPhase::Collection),
            "c2" | "commandandcontrol" | "commandcontrol" => Ok(PlaybookPhase::C2),
            "exfiltration" => Ok(PlaybookPhase::Exfiltration),
            "impact" => Ok(PlaybookPhase::Impact),
            "cleanup" => Ok(PlaybookPhase::Cleanup),
            _ => Err("invalid playbook phase".to_string()),
        }
    }
}

impl JsonEncode for TargetType {
    fn to_json_value(&self) -> Value {
        let s = match self {
            TargetType::Host => "Host",
            TargetType::WebApp => "WebApp",
            TargetType::Network => "Network",
            TargetType::Domain => "Domain",
            TargetType::Cloud => "Cloud",
            TargetType::Internal => "Internal",
            TargetType::Container => "Container",
            TargetType::Api => "Api",
        };
        Value::String(s.to_string())
    }
}

impl JsonDecode for TargetType {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let s = String::from_json_value(value)?;
        let key = normalize_key(&s);
        match key.as_str() {
            "host" => Ok(TargetType::Host),
            "webapp" | "webapplication" => Ok(TargetType::WebApp),
            "network" => Ok(TargetType::Network),
            "domain" => Ok(TargetType::Domain),
            "cloud" => Ok(TargetType::Cloud),
            "internal" | "internalnetwork" => Ok(TargetType::Internal),
            "container" => Ok(TargetType::Container),
            "api" => Ok(TargetType::Api),
            _ => Err("invalid target type".to_string()),
        }
    }
}

impl JsonEncode for TargetOS {
    fn to_json_value(&self) -> Value {
        let s = match self {
            TargetOS::Any => "Any",
            TargetOS::Linux => "Linux",
            TargetOS::Windows => "Windows",
            TargetOS::MacOS => "MacOS",
            TargetOS::FreeBSD => "FreeBSD",
            TargetOS::Android => "Android",
            TargetOS::IOS => "IOS",
        };
        Value::String(s.to_string())
    }
}

impl JsonDecode for TargetOS {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let s = String::from_json_value(value)?;
        let key = normalize_key(&s);
        match key.as_str() {
            "any" => Ok(TargetOS::Any),
            "linux" => Ok(TargetOS::Linux),
            "windows" => Ok(TargetOS::Windows),
            "macos" | "mac" => Ok(TargetOS::MacOS),
            "freebsd" => Ok(TargetOS::FreeBSD),
            "android" => Ok(TargetOS::Android),
            "ios" => Ok(TargetOS::IOS),
            _ => Err("invalid target os".to_string()),
        }
    }
}

impl JsonEncode for RiskLevel {
    fn to_json_value(&self) -> Value {
        let s = match self {
            RiskLevel::Passive => "Passive",
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        };
        Value::String(s.to_string())
    }
}

impl JsonDecode for RiskLevel {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let s = String::from_json_value(value)?;
        match s.to_lowercase().as_str() {
            "passive" => Ok(RiskLevel::Passive),
            "low" => Ok(RiskLevel::Low),
            "medium" => Ok(RiskLevel::Medium),
            "high" => Ok(RiskLevel::High),
            "critical" => Ok(RiskLevel::Critical),
            _ => Err("invalid risk level".to_string()),
        }
    }
}

impl JsonEncode for EvidenceType {
    fn to_json_value(&self) -> Value {
        let s = match self {
            EvidenceType::Credentials => "Credentials",
            EvidenceType::Vulnerability => "Vulnerability",
            EvidenceType::Screenshot => "Screenshot",
            EvidenceType::NetworkCapture => "NetworkCapture",
            EvidenceType::FileArtifact => "FileArtifact",
            EvidenceType::CommandOutput => "CommandOutput",
            EvidenceType::SystemInfo => "SystemInfo",
            EvidenceType::NetworkMap => "NetworkMap",
            EvidenceType::SessionData => "SessionData",
        };
        Value::String(s.to_string())
    }
}

impl JsonDecode for EvidenceType {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let s = String::from_json_value(value)?;
        let key = normalize_key(&s);
        match key.as_str() {
            "credentials" => Ok(EvidenceType::Credentials),
            "vulnerability" => Ok(EvidenceType::Vulnerability),
            "screenshot" => Ok(EvidenceType::Screenshot),
            "networkcapture" => Ok(EvidenceType::NetworkCapture),
            "fileartifact" => Ok(EvidenceType::FileArtifact),
            "commandoutput" => Ok(EvidenceType::CommandOutput),
            "systeminfo" => Ok(EvidenceType::SystemInfo),
            "networkmap" => Ok(EvidenceType::NetworkMap),
            "sessiondata" => Ok(EvidenceType::SessionData),
            _ => Err("invalid evidence type".to_string()),
        }
    }
}

impl JsonEncode for StepFailureAction {
    fn to_json_value(&self) -> Value {
        match self {
            StepFailureAction::Continue => Value::String("Continue".to_string()),
            StepFailureAction::Abort => Value::String("Abort".to_string()),
            StepFailureAction::SkipDependents => Value::String("SkipDependents".to_string()),
            StepFailureAction::AskUser => Value::String("AskUser".to_string()),
            StepFailureAction::Retry { max_attempts } => {
                let mut inner = Map::new();
                inner.insert("max_attempts".to_string(), max_attempts.to_json_value());
                tagged_value("Retry", Value::Object(inner))
            }
        }
    }
}

impl JsonDecode for StepFailureAction {
    fn from_json_value(value: Value) -> Result<Self, String> {
        match value {
            Value::String(s) => {
                let key = normalize_key(&s);
                match key.as_str() {
                    "continue" => Ok(StepFailureAction::Continue),
                    "abort" => Ok(StepFailureAction::Abort),
                    "skipdependents" => Ok(StepFailureAction::SkipDependents),
                    "askuser" => Ok(StepFailureAction::AskUser),
                    _ => Err("invalid step failure action".to_string()),
                }
            }
            Value::Object(map) if map.len() == 1 => {
                let (key, value) = map.into_iter().next().unwrap();
                match key.as_str() {
                    "Retry" | "retry" => match value {
                        Value::Object(inner) => Ok(StepFailureAction::Retry {
                            max_attempts: u8::from_json_value(map_get_value(
                                &inner,
                                "max_attempts",
                            ))?,
                        }),
                        other => Ok(StepFailureAction::Retry {
                            max_attempts: u8::from_json_value(other)?,
                        }),
                    },
                    _ => Err("invalid step failure action".to_string()),
                }
            }
            _ => Err("invalid step failure action".to_string()),
        }
    }
}

impl JsonEncode for StepCondition {
    fn to_json_value(&self) -> Value {
        match self {
            StepCondition::Always => Value::String("Always".to_string()),
            StepCondition::OnSuccess(step) => tagged_value("OnSuccess", step.to_json_value()),
            StepCondition::OnFailure(step) => tagged_value("OnFailure", step.to_json_value()),
            StepCondition::OnEvidence(evidence) => {
                tagged_value("OnEvidence", evidence.to_json_value())
            }
            StepCondition::Custom(expr) => tagged_value("Custom", expr.to_json_value()),
            StepCondition::OnPreviousAction(action) => {
                tagged_value("OnPreviousAction", action.to_json_value())
            }
            StepCondition::IfNotScanned => Value::String("IfNotScanned".to_string()),
            StepCondition::IfHasVulnerabilities => {
                Value::String("IfHasVulnerabilities".to_string())
            }
        }
    }
}

impl JsonDecode for StepCondition {
    fn from_json_value(value: Value) -> Result<Self, String> {
        match value {
            Value::String(s) => {
                let key = normalize_key(&s);
                match key.as_str() {
                    "always" => Ok(StepCondition::Always),
                    "ifnotscanned" => Ok(StepCondition::IfNotScanned),
                    "ifhasvulnerabilities" => Ok(StepCondition::IfHasVulnerabilities),
                    _ => Err("invalid step condition".to_string()),
                }
            }
            Value::Object(map) if map.len() == 1 => {
                let (key, value) = map.into_iter().next().unwrap();
                match key.as_str() {
                    "OnSuccess" | "onsuccess" => {
                        Ok(StepCondition::OnSuccess(u8::from_json_value(value)?))
                    }
                    "OnFailure" | "onfailure" => {
                        Ok(StepCondition::OnFailure(u8::from_json_value(value)?))
                    }
                    "OnEvidence" | "onevidence" => Ok(StepCondition::OnEvidence(
                        EvidenceType::from_json_value(value)?,
                    )),
                    "Custom" | "custom" => {
                        Ok(StepCondition::Custom(String::from_json_value(value)?))
                    }
                    "OnPreviousAction" | "onpreviousaction" => Ok(StepCondition::OnPreviousAction(
                        String::from_json_value(value)?,
                    )),
                    _ => Err("invalid step condition".to_string()),
                }
            }
            _ => Err("invalid step condition".to_string()),
        }
    }
}

impl JsonEncode for PlaybookMetadata {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("id".to_string(), self.id.to_json_value());
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("objective".to_string(), self.objective.to_json_value());
        map.insert("author".to_string(), self.author.to_json_value());
        map.insert("version".to_string(), self.version.to_json_value());
        map.insert(
            "target_types".to_string(),
            self.target_types.to_json_value(),
        );
        map.insert("target_os".to_string(), self.target_os.to_json_value());
        map.insert("risk_level".to_string(), self.risk_level.to_json_value());
        map.insert(
            "estimated_duration".to_string(),
            self.estimated_duration.to_json_value(),
        );
        map.insert("tags".to_string(), self.tags.to_json_value());
        map.insert(
            "mitre_techniques".to_string(),
            self.mitre_techniques.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonDecode for PlaybookMetadata {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let mut meta = PlaybookMetadata::default();

        if let Ok(id) = String::from_json_value(map_get_value(&map, "id")) {
            meta.id = id;
        }
        if let Ok(name) = String::from_json_value(map_get_value(&map, "name")) {
            meta.name = name;
        }
        if map.contains_key("description") {
            meta.description = String::from_json_value(map_get_value(&map, "description"))?;
        }
        if map.contains_key("objective") {
            meta.objective = String::from_json_value(map_get_value(&map, "objective"))?;
        }
        if map.contains_key("author") {
            meta.author = String::from_json_value(map_get_value(&map, "author"))?;
        }
        if map.contains_key("version") {
            meta.version = String::from_json_value(map_get_value(&map, "version"))?;
        }
        if map.contains_key("target_types") {
            meta.target_types =
                Vec::<TargetType>::from_json_value(map_get_value(&map, "target_types"))?;
        }
        if map.contains_key("target_os") {
            meta.target_os = Vec::<TargetOS>::from_json_value(map_get_value(&map, "target_os"))?;
        }
        if map.contains_key("risk_level") {
            meta.risk_level = RiskLevel::from_json_value(map_get_value(&map, "risk_level"))?;
        }
        if map.contains_key("estimated_duration") {
            meta.estimated_duration =
                String::from_json_value(map_get_value(&map, "estimated_duration"))?;
        }
        if map.contains_key("tags") {
            meta.tags = Vec::<String>::from_json_value(map_get_value(&map, "tags"))?;
        }
        if map.contains_key("mitre_techniques") {
            meta.mitre_techniques =
                Vec::<String>::from_json_value(map_get_value(&map, "mitre_techniques"))?;
        }

        if meta.id.is_empty() || meta.name.is_empty() {
            return Err("playbook metadata missing id or name".to_string());
        }
        Ok(meta)
    }
}

impl JsonEncode for PreCondition {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("check".to_string(), self.check.to_json_value());
        map.insert("required".to_string(), self.required.to_json_value());
        map.insert("notes".to_string(), self.notes.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for PreCondition {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            description: String::from_json_value(map_get_value(&map, "description"))?,
            check: Option::<String>::from_json_value(map_get_value(&map, "check"))?,
            required: map_get_bool(&map, "required", true)?,
            notes: Option::<String>::from_json_value(map_get_value(&map, "notes"))?,
        })
    }
}

impl JsonEncode for PlaybookStep {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("number".to_string(), self.number.to_json_value());
        map.insert("phase".to_string(), self.phase.to_json_value());
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("scripts".to_string(), self.scripts.to_json_value());
        map.insert("commands".to_string(), self.commands.to_json_value());
        map.insert(
            "manual_instructions".to_string(),
            self.manual_instructions.to_json_value(),
        );
        map.insert(
            "success_criteria".to_string(),
            self.success_criteria.to_json_value(),
        );
        map.insert("on_failure".to_string(), self.on_failure.to_json_value());
        map.insert("depends_on".to_string(), self.depends_on.to_json_value());
        map.insert("optional".to_string(), self.optional.to_json_value());
        map.insert("timeout".to_string(), duration_to_value(self.timeout));
        map.insert(
            "mitre_technique".to_string(),
            self.mitre_technique.to_json_value(),
        );
        map.insert(
            "mitre_subtechnique".to_string(),
            self.mitre_subtechnique.to_json_value(),
        );
        map.insert(
            "parallel_group".to_string(),
            self.parallel_group.to_json_value(),
        );
        map.insert("condition".to_string(), self.condition.to_json_value());
        map.insert(
            "evidence_type".to_string(),
            self.evidence_type.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonDecode for PlaybookStep {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let number = u8::from_json_value(map_get_value(&map, "number"))?;
        let phase = PlaybookPhase::from_json_value(map_get_value(&map, "phase"))?;
        let name = String::from_json_value(map_get_value(&map, "name"))?;
        let mut step = PlaybookStep::new(number, phase, &name);

        if map.contains_key("description") {
            step.description = String::from_json_value(map_get_value(&map, "description"))?;
        }
        if map.contains_key("scripts") {
            step.scripts = Vec::<String>::from_json_value(map_get_array(&map, "scripts"))?;
        }
        if map.contains_key("commands") {
            step.commands = Vec::<String>::from_json_value(map_get_array(&map, "commands"))?;
        }
        if map.contains_key("manual_instructions") {
            step.manual_instructions =
                Option::<String>::from_json_value(map_get_value(&map, "manual_instructions"))?;
        }
        if map.contains_key("success_criteria") {
            step.success_criteria =
                Vec::<String>::from_json_value(map_get_array(&map, "success_criteria"))?;
        }
        if map.contains_key("on_failure") {
            step.on_failure =
                StepFailureAction::from_json_value(map_get_value(&map, "on_failure"))?;
        }
        if map.contains_key("depends_on") {
            step.depends_on = Vec::<u8>::from_json_value(map_get_array(&map, "depends_on"))?;
        }
        step.optional = map_get_bool(&map, "optional", step.optional)?;
        step.timeout = duration_from_value(map_get_value(&map, "timeout"), step.timeout)?;
        if map.contains_key("mitre_technique") {
            step.mitre_technique =
                Option::<String>::from_json_value(map_get_value(&map, "mitre_technique"))?;
        }
        if map.contains_key("mitre_subtechnique") {
            step.mitre_subtechnique =
                Option::<String>::from_json_value(map_get_value(&map, "mitre_subtechnique"))?;
        }
        if map.contains_key("parallel_group") {
            step.parallel_group =
                Option::<u8>::from_json_value(map_get_value(&map, "parallel_group"))?;
        }
        if map.contains_key("condition") {
            step.condition = StepCondition::from_json_value(map_get_value(&map, "condition"))?;
        }
        if map.contains_key("evidence_type") {
            step.evidence_type =
                Option::<EvidenceType>::from_json_value(map_get_value(&map, "evidence_type"))?;
        }

        Ok(step)
    }
}

impl JsonEncode for ExpectedEvidence {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("location".to_string(), self.location.to_json_value());
        map.insert("indicators".to_string(), self.indicators.to_json_value());
        map.insert("severity".to_string(), self.severity.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for ExpectedEvidence {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let description = String::from_json_value(map_get_value(&map, "description"))?;
        let mut evidence = ExpectedEvidence::new(&description);
        if map.contains_key("location") {
            evidence.location = String::from_json_value(map_get_value(&map, "location"))?;
        }
        if map.contains_key("indicators") {
            evidence.indicators =
                Vec::<String>::from_json_value(map_get_array(&map, "indicators"))?;
        }
        if map.contains_key("severity") {
            evidence.severity = FindingSeverity::from_json_value(map_get_value(&map, "severity"))?;
        }
        Ok(evidence)
    }
}

impl JsonEncode for FailedControl {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("reason".to_string(), self.reason.to_json_value());
        map.insert("remediation".to_string(), self.remediation.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for FailedControl {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            name: String::from_json_value(map_get_value(&map, "name"))?,
            reason: String::from_json_value(map_get_value(&map, "reason"))?,
            remediation: String::from_json_value(map_get_value(&map, "remediation"))
                .unwrap_or_default(),
        })
    }
}

impl JsonEncode for PlaybookVariation {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("use_when".to_string(), self.use_when.to_json_value());
        map.insert("command".to_string(), self.command.to_json_value());
        map.insert(
            "different_steps".to_string(),
            self.different_steps.to_json_value(),
        );
        map.insert("notes".to_string(), self.notes.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for PlaybookVariation {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let name = String::from_json_value(map_get_value(&map, "name"))?;
        let mut variation = PlaybookVariation::new(&name, "");
        if map.contains_key("description") {
            variation.description = String::from_json_value(map_get_value(&map, "description"))?;
        }
        if map.contains_key("use_when") {
            variation.use_when = String::from_json_value(map_get_value(&map, "use_when"))?;
        }
        if map.contains_key("command") {
            variation.command = Option::<String>::from_json_value(map_get_value(&map, "command"))?;
        }
        if map.contains_key("different_steps") {
            variation.different_steps =
                Vec::<PlaybookStep>::from_json_value(map_get_array(&map, "different_steps"))?;
        }
        if map.contains_key("notes") {
            variation.notes = Option::<String>::from_json_value(map_get_value(&map, "notes"))?;
        }
        Ok(variation)
    }
}

impl JsonEncode for Playbook {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("metadata".to_string(), self.metadata.to_json_value());
        map.insert(
            "preconditions".to_string(),
            self.preconditions.to_json_value(),
        );
        map.insert("steps".to_string(), self.steps.to_json_value());
        map.insert("evidence".to_string(), self.evidence.to_json_value());
        map.insert(
            "failed_controls".to_string(),
            self.failed_controls.to_json_value(),
        );
        map.insert("variations".to_string(), self.variations.to_json_value());
        map.insert("kill_chain".to_string(), self.kill_chain.to_json_value());
        map.insert("on_success".to_string(), self.on_success.to_json_value());
        map.insert("on_failure".to_string(), self.on_failure.to_json_value());
        map.insert("assertions".to_string(), self.assertions.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for Playbook {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let metadata = PlaybookMetadata::from_json_value(map_get_value(&map, "metadata"))?;
        Ok(Self {
            metadata,
            preconditions: Vec::<PreCondition>::from_json_value(map_get_array(
                &map,
                "preconditions",
            ))
            .unwrap_or_default(),
            steps: Vec::<PlaybookStep>::from_json_value(map_get_array(&map, "steps"))
                .unwrap_or_default(),
            evidence: Vec::<ExpectedEvidence>::from_json_value(map_get_array(&map, "evidence"))
                .unwrap_or_default(),
            failed_controls: Vec::<FailedControl>::from_json_value(map_get_array(
                &map,
                "failed_controls",
            ))
            .unwrap_or_default(),
            variations: Vec::<PlaybookVariation>::from_json_value(map_get_array(
                &map,
                "variations",
            ))
            .unwrap_or_default(),
            kill_chain: Vec::<KillChainPhase>::from_json_value(map_get_array(&map, "kill_chain"))
                .unwrap_or_default(),
            on_success: Option::<String>::from_json_value(map_get_value(&map, "on_success"))?,
            on_failure: Option::<String>::from_json_value(map_get_value(&map, "on_failure"))?,
            assertions: Vec::<Assertion>::from_json_value(map_get_array(&map, "assertions"))
                .unwrap_or_default(),
        })
    }
}

impl JsonEncode for KillChainPhase {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert(
            "step_numbers".to_string(),
            self.step_numbers.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonDecode for KillChainPhase {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            name: String::from_json_value(map_get_value(&map, "name"))?,
            description: String::from_json_value(map_get_value(&map, "description"))?,
            step_numbers: Vec::<u8>::from_json_value(map_get_array(&map, "step_numbers"))
                .unwrap_or_default(),
        })
    }
}

impl JsonEncode for PlaybookContext {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("target".to_string(), self.target.to_json_value());
        map.insert(
            "additional_targets".to_string(),
            self.additional_targets.to_json_value(),
        );
        map.insert("session_id".to_string(), self.session_id.to_json_value());
        map.insert("args".to_string(), self.args.to_json_value());
        map.insert(
            "gathered_data".to_string(),
            self.gathered_data.to_json_value(),
        );
        map.insert(
            "allow_intrusive".to_string(),
            self.allow_intrusive.to_json_value(),
        );
        map.insert(
            "step_timeout".to_string(),
            duration_to_value(self.step_timeout),
        );
        map.insert(
            "total_timeout".to_string(),
            duration_to_value(self.total_timeout),
        );
        map.insert("verbosity".to_string(), self.verbosity.to_json_value());
        map.insert("dry_run".to_string(), self.dry_run.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for PlaybookContext {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let target = String::from_json_value(map_get_value(&map, "target"))?;
        let session_id = match map.get("session_id") {
            Some(value) => String::from_json_value(value.clone())?,
            None => Uuid::new_v4().to_string(),
        };
        Ok(Self {
            target,
            additional_targets: Vec::<String>::from_json_value(map_get_array(
                &map,
                "additional_targets",
            ))
            .unwrap_or_default(),
            session_id,
            args: HashMap::<String, String>::from_json_value(map_get_value(&map, "args"))
                .unwrap_or_default(),
            gathered_data: HashMap::<String, String>::from_json_value(map_get_value(
                &map,
                "gathered_data",
            ))
            .unwrap_or_default(),
            allow_intrusive: map_get_bool(&map, "allow_intrusive", false)?,
            step_timeout: duration_from_value(
                map_get_value(&map, "step_timeout"),
                Duration::from_secs(300),
            )?,
            total_timeout: duration_from_value(
                map_get_value(&map, "total_timeout"),
                Duration::from_secs(3600),
            )?,
            verbosity: u8::from_json_value(map_get_value(&map, "verbosity")).unwrap_or(1),
            dry_run: map_get_bool(&map, "dry_run", false)?,
        })
    }
}

impl JsonEncode for StepExecutionResult {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("step_number".to_string(), self.step_number.to_json_value());
        map.insert("step_name".to_string(), self.step_name.to_json_value());
        map.insert("success".to_string(), self.success.to_json_value());
        map.insert("status".to_string(), self.status.to_json_value());
        map.insert("output".to_string(), self.output.to_json_value());
        map.insert("findings".to_string(), self.findings.to_json_value());
        map.insert(
            "extracted_data".to_string(),
            self.extracted_data.to_json_value(),
        );
        map.insert("duration".to_string(), duration_to_value(self.duration));
        map.insert("skipped".to_string(), self.skipped.to_json_value());
        map.insert("error".to_string(), self.error.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for StepExecutionResult {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            step_number: u8::from_json_value(map_get_value(&map, "step_number"))?,
            step_name: String::from_json_value(map_get_value(&map, "step_name"))?,
            success: map_get_bool(&map, "success", false)?,
            status: String::from_json_value(map_get_value(&map, "status"))
                .unwrap_or_else(|_| "Not executed".to_string()),
            output: Vec::<String>::from_json_value(map_get_array(&map, "output"))
                .unwrap_or_default(),
            findings: Vec::<Finding>::from_json_value(map_get_array(&map, "findings"))
                .unwrap_or_default(),
            extracted_data: HashMap::<String, String>::from_json_value(map_get_value(
                &map,
                "extracted_data",
            ))
            .unwrap_or_default(),
            duration: duration_from_value(map_get_value(&map, "duration"), Duration::ZERO)?,
            skipped: map_get_bool(&map, "skipped", false)?,
            error: Option::<String>::from_json_value(map_get_value(&map, "error"))?,
        })
    }
}

impl JsonEncode for PlaybookExecutionResult {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("playbook_id".to_string(), self.playbook_id.to_json_value());
        map.insert(
            "playbook_name".to_string(),
            self.playbook_name.to_json_value(),
        );
        map.insert("target".to_string(), self.target.to_json_value());
        map.insert("success".to_string(), self.success.to_json_value());
        map.insert(
            "step_results".to_string(),
            self.step_results.to_json_value(),
        );
        map.insert(
            "all_findings".to_string(),
            self.all_findings.to_json_value(),
        );
        map.insert("duration".to_string(), duration_to_value(self.duration));
        map.insert("summary".to_string(), self.summary.to_json_value());
        map.insert(
            "steps_completed".to_string(),
            self.steps_completed.to_json_value(),
        );
        map.insert(
            "steps_skipped".to_string(),
            self.steps_skipped.to_json_value(),
        );
        map.insert(
            "steps_failed".to_string(),
            self.steps_failed.to_json_value(),
        );
        map.insert(
            "next_playbook".to_string(),
            self.next_playbook.to_json_value(),
        );
        map.insert(
            "assertion_results".to_string(),
            self.assertion_results.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonDecode for PlaybookExecutionResult {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            playbook_id: String::from_json_value(map_get_value(&map, "playbook_id"))?,
            playbook_name: String::from_json_value(map_get_value(&map, "playbook_name"))?,
            target: String::from_json_value(map_get_value(&map, "target"))?,
            success: map_get_bool(&map, "success", false)?,
            step_results: Vec::<StepExecutionResult>::from_json_value(map_get_array(
                &map,
                "step_results",
            ))
            .unwrap_or_default(),
            all_findings: Vec::<Finding>::from_json_value(map_get_array(&map, "all_findings"))
                .unwrap_or_default(),
            duration: duration_from_value(map_get_value(&map, "duration"), Duration::ZERO)?,
            summary: String::from_json_value(map_get_value(&map, "summary")).unwrap_or_default(),
            steps_completed: usize::from_json_value(map_get_value(&map, "steps_completed"))
                .unwrap_or(0),
            steps_skipped: usize::from_json_value(map_get_value(&map, "steps_skipped"))
                .unwrap_or(0),
            steps_failed: usize::from_json_value(map_get_value(&map, "steps_failed")).unwrap_or(0),
            next_playbook: Option::<String>::from_json_value(map_get_value(&map, "next_playbook"))?,
            assertion_results: Vec::<AssertionResult>::from_json_value(map_get_array(
                &map,
                "assertion_results",
            ))
            .unwrap_or_default(),
        })
    }
}

impl JsonEncode for ChainCondition {
    fn to_json_value(&self) -> Value {
        match self {
            ChainCondition::Always => Value::String("Always".to_string()),
            ChainCondition::OnSuccess => Value::String("OnSuccess".to_string()),
            ChainCondition::OnFailure => Value::String("OnFailure".to_string()),
            ChainCondition::OnEvidence(evidence) => {
                tagged_value("OnEvidence", evidence.to_json_value())
            }
            ChainCondition::OnSeverity(severity) => {
                tagged_value("OnSeverity", severity.to_json_value())
            }
        }
    }
}

impl JsonDecode for ChainCondition {
    fn from_json_value(value: Value) -> Result<Self, String> {
        match value {
            Value::String(s) => {
                let key = normalize_key(&s);
                match key.as_str() {
                    "always" => Ok(ChainCondition::Always),
                    "onsuccess" => Ok(ChainCondition::OnSuccess),
                    "onfailure" => Ok(ChainCondition::OnFailure),
                    _ => Err("invalid chain condition".to_string()),
                }
            }
            Value::Object(map) if map.len() == 1 => {
                let (key, value) = map.into_iter().next().unwrap();
                match key.as_str() {
                    "OnEvidence" | "onevidence" => Ok(ChainCondition::OnEvidence(
                        EvidenceType::from_json_value(value)?,
                    )),
                    "OnSeverity" | "onseverity" => Ok(ChainCondition::OnSeverity(
                        FindingSeverity::from_json_value(value)?,
                    )),
                    _ => Err("invalid chain condition".to_string()),
                }
            }
            _ => Err("invalid chain condition".to_string()),
        }
    }
}

impl JsonEncode for ChainedPlaybook {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("playbook_id".to_string(), self.playbook_id.to_json_value());
        map.insert("condition".to_string(), self.condition.to_json_value());
        map.insert(
            "output_mapping".to_string(),
            self.output_mapping.to_json_value(),
        );
        map.insert(
            "continue_on_failure".to_string(),
            self.continue_on_failure.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonDecode for ChainedPlaybook {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            playbook_id: String::from_json_value(map_get_value(&map, "playbook_id"))?,
            condition: ChainCondition::from_json_value(map_get_value(&map, "condition"))
                .unwrap_or_default(),
            output_mapping: HashMap::<String, String>::from_json_value(map_get_value(
                &map,
                "output_mapping",
            ))
            .unwrap_or_default(),
            continue_on_failure: map_get_bool(&map, "continue_on_failure", false)?,
        })
    }
}

impl JsonEncode for PlaybookChain {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("id".to_string(), self.id.to_json_value());
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("playbooks".to_string(), self.playbooks.to_json_value());
        map.insert("tags".to_string(), self.tags.to_json_value());
        map.insert("risk_level".to_string(), self.risk_level.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for PlaybookChain {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            id: String::from_json_value(map_get_value(&map, "id"))?,
            name: String::from_json_value(map_get_value(&map, "name"))?,
            description: String::from_json_value(map_get_value(&map, "description"))
                .unwrap_or_default(),
            playbooks: Vec::<ChainedPlaybook>::from_json_value(map_get_array(&map, "playbooks"))
                .unwrap_or_default(),
            tags: Vec::<String>::from_json_value(map_get_array(&map, "tags")).unwrap_or_default(),
            risk_level: RiskLevel::from_json_value(map_get_value(&map, "risk_level"))
                .unwrap_or(RiskLevel::Low),
        })
    }
}

impl JsonEncode for AssertionOperator {
    fn to_json_value(&self) -> Value {
        let s = match self {
            AssertionOperator::Equals => "Equals",
            AssertionOperator::NotEquals => "NotEquals",
            AssertionOperator::GreaterThan => "GreaterThan",
            AssertionOperator::LessThan => "LessThan",
            AssertionOperator::GreaterOrEqual => "GreaterOrEqual",
            AssertionOperator::LessOrEqual => "LessOrEqual",
            AssertionOperator::Contains => "Contains",
            AssertionOperator::NotContains => "NotContains",
            AssertionOperator::Matches => "Matches",
            AssertionOperator::IsTrue => "IsTrue",
            AssertionOperator::IsFalse => "IsFalse",
            AssertionOperator::Exists => "Exists",
            AssertionOperator::NotExists => "NotExists",
        };
        Value::String(s.to_string())
    }
}

impl JsonDecode for AssertionOperator {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let s = String::from_json_value(value)?;
        let key = s.to_lowercase();
        match key.as_str() {
            "equals" | "==" => Ok(AssertionOperator::Equals),
            "notequals" | "!=" => Ok(AssertionOperator::NotEquals),
            "greaterthan" | ">" => Ok(AssertionOperator::GreaterThan),
            "lessthan" | "<" => Ok(AssertionOperator::LessThan),
            "greaterorequal" | ">=" => Ok(AssertionOperator::GreaterOrEqual),
            "lessorequal" | "<=" => Ok(AssertionOperator::LessOrEqual),
            "contains" => Ok(AssertionOperator::Contains),
            "notcontains" => Ok(AssertionOperator::NotContains),
            "matches" => Ok(AssertionOperator::Matches),
            "istrue" => Ok(AssertionOperator::IsTrue),
            "isfalse" => Ok(AssertionOperator::IsFalse),
            "exists" => Ok(AssertionOperator::Exists),
            "notexists" => Ok(AssertionOperator::NotExists),
            _ => Err("invalid assertion operator".to_string()),
        }
    }
}

impl JsonEncode for Assertion {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("subject".to_string(), self.subject.to_json_value());
        map.insert("operator".to_string(), self.operator.to_json_value());
        map.insert("expected".to_string(), self.expected.to_json_value());
        map.insert("critical".to_string(), self.critical.to_json_value());
        map.insert(
            "failure_message".to_string(),
            self.failure_message.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonDecode for Assertion {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            description: String::from_json_value(map_get_value(&map, "description"))?,
            subject: String::from_json_value(map_get_value(&map, "subject"))?,
            operator: AssertionOperator::from_json_value(map_get_value(&map, "operator"))
                .unwrap_or(AssertionOperator::Exists),
            expected: Option::<String>::from_json_value(map_get_value(&map, "expected"))?,
            critical: map_get_bool(&map, "critical", false)?,
            failure_message: Option::<String>::from_json_value(map_get_value(
                &map,
                "failure_message",
            ))?,
        })
    }
}

impl JsonEncode for AssertionResult {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert("passed".to_string(), self.passed.to_json_value());
        map.insert(
            "actual_value".to_string(),
            self.actual_value.to_json_value(),
        );
        map.insert(
            "expected_value".to_string(),
            self.expected_value.to_json_value(),
        );
        map.insert("message".to_string(), self.message.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for AssertionResult {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            description: String::from_json_value(map_get_value(&map, "description"))?,
            passed: map_get_bool(&map, "passed", false)?,
            actual_value: Option::<String>::from_json_value(map_get_value(&map, "actual_value"))?,
            expected_value: Option::<String>::from_json_value(map_get_value(
                &map,
                "expected_value",
            ))?,
            message: Option::<String>::from_json_value(map_get_value(&map, "message"))?,
        })
    }
}

impl JsonEncode for ChainExecutionResult {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("chain_id".to_string(), self.chain_id.to_json_value());
        map.insert("target".to_string(), self.target.to_json_value());
        map.insert("success".to_string(), self.success.to_json_value());
        map.insert(
            "playbook_results".to_string(),
            self.playbook_results.to_json_value(),
        );
        map.insert("duration".to_string(), duration_to_value(self.duration));
        map.insert(
            "all_findings".to_string(),
            self.all_findings.to_json_value(),
        );
        map.insert("summary".to_string(), self.summary.to_json_value());
        Value::Object(map)
    }
}

impl JsonDecode for ChainExecutionResult {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            chain_id: String::from_json_value(map_get_value(&map, "chain_id"))?,
            target: String::from_json_value(map_get_value(&map, "target"))?,
            success: map_get_bool(&map, "success", false)?,
            playbook_results: Vec::<PlaybookExecutionResult>::from_json_value(map_get_array(
                &map,
                "playbook_results",
            ))
            .unwrap_or_default(),
            duration: duration_from_value(map_get_value(&map, "duration"), Duration::ZERO)?,
            all_findings: Vec::<Finding>::from_json_value(map_get_array(&map, "all_findings"))
                .unwrap_or_default(),
            summary: String::from_json_value(map_get_value(&map, "summary")).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_creation() {
        let playbook = Playbook::new("test-playbook", "Test Playbook")
            .with_description("A test playbook")
            .with_objective("Test the playbook system")
            .for_target(TargetType::Host)
            .for_os(TargetOS::Linux)
            .with_risk(RiskLevel::Low)
            .add_precondition(PreCondition::new("Target must be reachable"))
            .add_step(
                PlaybookStep::new(1, PlaybookPhase::Recon, "Port Scan")
                    .with_description("Scan for open ports")
                    .with_command("rb network ports scan <target>")
                    .with_success("Open ports identified"),
            )
            .add_evidence(
                ExpectedEvidence::new("Open SSH port")
                    .at("Port 22")
                    .with_indicator("SSH service banner"),
            )
            .add_failed_control(
                FailedControl::new("Perimeter Firewall", "SSH often allowed for admin access")
                    .with_fix("Implement IP allowlisting for SSH access"),
            );

        assert_eq!(playbook.metadata.id, "test-playbook");
        assert_eq!(playbook.total_steps(), 1);
        assert!(playbook.is_safe());
    }

    #[test]
    fn test_risk_levels() {
        assert!(!RiskLevel::Passive.requires_consent());
        assert!(!RiskLevel::Low.requires_consent());
        assert!(!RiskLevel::Medium.requires_consent());
        assert!(RiskLevel::High.requires_consent());
        assert!(RiskLevel::Critical.requires_consent());
    }

    #[test]
    fn test_step_dependencies() {
        let step1 = PlaybookStep::new(1, PlaybookPhase::Recon, "Recon");
        let step2 = PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Access").depends(1);

        assert!(step1.depends_on.is_empty());
        assert_eq!(step2.depends_on, vec![1]);
    }
}
