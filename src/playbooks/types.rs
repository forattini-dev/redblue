use serde::{Deserialize, Serialize};
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
use uuid::Uuid;

use crate::scripts::{Finding, FindingSeverity, ScriptCategory, ScriptContext, ScriptResult};

/// Helper for serializing Duration as seconds
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Playbook phase - major stages of execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    /// Internal-only: MITRE technique ID (never exposed)
    #[doc(hidden)]
    pub mitre_technique: Option<String>,
    /// Internal-only: MITRE sub-technique ID
    #[doc(hidden)]
    pub mitre_subtechnique: Option<String>,
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
}

/// What to do when a step fails
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Expected evidence from playbook execution
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookVariation {
    /// Name of the variation
    pub name: String,
    /// When to use this variation
    pub use_when: String,
    /// Steps that differ
    pub different_steps: Vec<PlaybookStep>,
    /// Additional notes
    pub notes: Option<String>,
}

impl PlaybookVariation {
    pub fn new(name: &str, use_when: &str) -> Self {
        Self {
            name: name.to_string(),
            use_when: use_when.to_string(),
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn with_kill_chain(mut self, phases: Vec<KillChainPhase>) -> Self {
        self.kill_chain = phases;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    /// Phase name
    pub name: String,
    /// Description
    pub description: String,
    /// Step numbers that belong to this phase
    pub step_numbers: Vec<u8>,
}

impl KillChainPhase {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(with = "duration_serde")]
    pub step_timeout: Duration,
    /// Total timeout for playbook
    #[serde(with = "duration_serde")]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(with = "duration_serde")]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(with = "duration_serde")]
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
