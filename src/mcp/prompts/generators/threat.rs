//! Threat modeling and incident response prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_threat_model(args: &Args) -> String {
    let system = get_arg(args, "system", "unknown system");
    let assets = get_arg(args, "assets", "not specified");
    let threat_actors = get_arg(args, "threat_actors", "general");

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

pub fn gen_incident_response(args: &Args) -> String {
    let incident_type = get_arg(args, "incident_type", "unknown");
    let indicators = get_arg(args, "indicators", "none provided");
    let affected_systems = get_arg(args, "affected_systems", "unknown");

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

pub fn gen_detection_rules(args: &Args) -> String {
    let threat = get_arg(args, "threat", "unknown threat");
    let format = get_arg(args, "format", "sigma");

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
