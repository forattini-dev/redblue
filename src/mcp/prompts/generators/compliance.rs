//! Compliance and MITRE prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_compliance_check(args: &Args) -> String {
    let standard = get_arg(args, "standard", "unknown");
    let scope = get_arg(args, "scope", "not specified");

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

pub fn gen_gap_analysis(args: &Args) -> String {
    let current_state = get_arg(args, "current_state", "unknown");
    let target_state = get_arg(args, "target_state", "not specified");

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

pub fn gen_mitre_mapping(args: &Args) -> String {
    let findings = get_arg(args, "findings", "none");
    let format = get_arg(args, "format", "navigator");

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

pub fn gen_attack_simulation(args: &Args) -> String {
    let threat_actor = get_arg(args, "threat_actor", "generic APT");
    let scope = get_arg(args, "scope", "not specified");

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
