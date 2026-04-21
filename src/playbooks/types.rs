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
    self
      .gathered_data
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
    self.add_playbook(ChainedPlaybook::new(playbook_id).when(ChainCondition::OnEvidence(evidence)))
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

#[path = "types_serde.rs"]
mod types_serde;
pub use types_serde::*;
