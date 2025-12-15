pub mod apt_catalog;
pub mod catalog;
pub mod executor;
pub mod recommender;
pub mod template;
/// redblue Playbook System
///
/// Intelligent security playbooks for Red Team operations.
///
/// ## Design Philosophy
///
/// Playbooks provide structured, repeatable security assessments following
/// Red Team methodology. Key principles:
///
/// 1. **Human-Friendly**: All names and descriptions are operator-friendly.
///    No MITRE IDs, technique numbers, or jargon exposed to users.
///
/// 2. **Internal Mapping**: MITRE ATT&CK techniques are mapped internally
///    for correlation, reporting, and threat intel integration - but NEVER
///    exposed in the user interface.
///
/// 3. **Structured Flow**: Each playbook follows the pattern:
///    - Objective: Clear goal statement
///    - Pre-conditions: What must be true to start
///    - Attack Flow: Step-by-step execution
///    - Evidence: What indicates success
///    - Failed Controls: Common defensive gaps
///    - Variations: Alternative approaches
///
/// ## Available Playbooks
///
/// ### Remote Access (High Risk)
/// - `reverse-shell-linux` - Establish reverse shell on Linux
/// - `reverse-shell-windows` - Establish reverse shell on Windows
/// - `webshell-upload` - Upload and execute webshell
///
/// ### Initial Access (Medium Risk)
/// - `web-app-assessment` - Web application security assessment
/// - `external-footprint` - External attack surface mapping
/// - `ssh-credential-test` - SSH credential testing
///
/// ### Privilege Escalation (Medium Risk)
/// - `linux-privesc` - Linux privilege escalation assessment
/// - `windows-privesc` - Windows privilege escalation assessment
///
/// ### Network (Medium-High Risk)
/// - `internal-recon` - Internal network reconnaissance
/// - `lateral-movement` - Lateral movement assessment
///
/// ### Data Collection (High Risk)
/// - `credential-harvesting` - Credential collection assessment
///
/// ## APT Adversary Emulation Playbooks (MITRE ATT&CK v18.1)
///
/// Pre-built playbooks based on real APT group TTPs:
///
/// - `apt28` - Russia GRU (Fancy Bear) - 91 techniques
/// - `apt29` - Russia SVR (Cozy Bear) - 66 techniques
/// - `apt3` - China MSS (Gothic Panda) - 44 techniques
/// - `apt32` - Vietnam (OceanLotus) - 78 techniques
/// - `apt41` - China (Wicked Panda) - 82 techniques
/// - `fin7` - Financially motivated (Carbanak) - 67 techniques
/// - `kimsuky` - North Korea (Velvet Chollima) - 109 techniques
/// - `lazarus-group` - North Korea (HIDDEN COBRA) - 93 techniques
/// - `muddywater` - Iran MOIS - 58 techniques
/// - `oilrig` - Iran (APT34) - 76 techniques
/// - `sandworm-team` - Russia GRU (BlackEnergy) - 79 techniques
/// - `scattered-spider` - Financially motivated - 64 techniques
/// - `turla` - Russia FSB (Waterbug) - 68 techniques
/// - `volt-typhoon` - China (BRONZE SILHOUETTE) - 81 techniques
/// - `wizard-spider` - Russia (TrickBot/Ryuk) - 64 techniques
///
/// ## Usage
///
/// ```rust
/// use crate::playbooks::{catalog, apt_catalog, PlaybookContext};
///
/// // List all playbooks
/// for playbook in catalog::all_playbooks() {
///     println!("{}: {}", playbook.metadata.id, playbook.metadata.name);
/// }
///
/// // Get a specific playbook
/// if let Some(playbook) = catalog::get_playbook("reverse-shell-linux") {
///     println!("Objective: {}", playbook.metadata.objective);
///     println!("Steps: {}", playbook.total_steps());
/// }
///
/// // Get an APT playbook
/// if let Some(playbook) = apt_catalog::get_apt_playbook("apt29") {
///     println!("APT Playbook: {}", playbook.metadata.name);
/// }
///
/// // List all APT groups
/// for (id, name) in apt_catalog::list_apt_groups() {
///     println!("{}: {}", id, name);
/// }
///
/// // Filter by target type
/// for playbook in catalog::playbooks_for_target(TargetType::WebApp) {
///     println!("Web playbook: {}", playbook.metadata.name);
/// }
/// ```
pub mod types;

pub use apt_catalog::{all_apt_playbooks, get_apt_playbook, list_apt_groups};
pub use catalog::{
    all_playbooks, get_playbook, playbooks_by_risk, playbooks_by_tag, playbooks_for_target,
};
pub use executor::PlaybookExecutor;
pub use recommender::{
    findings_from_planner_input, recommend_from_attack_plan, recommend_playbooks, DetectedOS,
    PlaybookRecommendation, PlaybookRecommender, RecommendationResult, RecommendationSummary,
    ReconFindings,
};
pub use types::*;
