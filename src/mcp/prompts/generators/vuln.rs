//! Vulnerability assessment prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_vuln_assessment(args: &Args) -> String {
    let target = get_arg(args, "target", "unknown");
    let scan_data = get_arg(args, "scan_data", "none provided");

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

pub fn gen_cve_analysis(args: &Args) -> String {
    let cve_id = get_arg(args, "cve_id", "CVE-XXXX-XXXXX");
    let context = get_arg(args, "context", "general");

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

pub fn gen_patch_priority(args: &Args) -> String {
    let vulns = get_arg(args, "vulns", "none listed");
    let environment = get_arg(args, "environment", "production");

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
