//! Report generation prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_pentest_report(args: &Args) -> String {
  let findings = get_arg(args, "findings", "none");
  let scope = get_arg(args, "scope", "not specified");
  let format = get_arg(args, "format", "full");

  format!(
    r#"# Penetration Test Report Generation

## Findings
{findings}

## Engagement Scope
{scope}

## Report Format
{format}

---

Generate penetration test report:

1. **Executive Summary**
   - Overall risk rating
   - Key findings (3-5)
   - Business impact
   - Top recommendations

2. **Technical Findings**
   | ID | Title | Severity | CVSS | Status |
   |----|-------|----------|------|--------|

3. **Finding Details** (for each)
   - Description
   - Evidence
   - Impact
   - Remediation
   - References

4. **Attack Narrative**
   - Attack path used
   - Techniques employed
   - MITRE ATT&CK mapping

5. **Recommendations**
   - Prioritized action items
   - Quick wins
   - Long-term improvements

6. **Appendices**
   - Methodology
   - Tools used
   - Raw evidence
"#
  )
}

pub fn gen_executive_summary(args: &Args) -> String {
  let findings = get_arg(args, "findings", "none");
  let audience = get_arg(args, "audience", "c-suite");

  format!(
    r#"# Executive Summary Generation

## Technical Findings
{findings}

## Target Audience
{audience}

---

Create an executive summary:

1. **Overall Assessment**
   - Risk rating (Critical/High/Medium/Low)
   - Comparison to industry
   - Trend from previous assessments

2. **Key Findings** (non-technical language)
   - Top 3-5 issues
   - Business impact of each
   - Real-world examples/analogies

3. **Risk Visualization**
   - Risk matrix
   - Trend charts
   - Comparison metrics

4. **Investment Recommendations**
   - Cost of inaction
   - Recommended investments
   - Expected risk reduction

5. **Next Steps**
   - Immediate actions
   - Strategic initiatives
   - Timeline
"#
  )
}

pub fn gen_risk_matrix(args: &Args) -> String {
  let vulnerabilities = get_arg(args, "vulnerabilities", "none");
  let business_context = get_arg(args, "business_context", "general");

  format!(
    r#"# Risk Matrix Generation

## Vulnerabilities
{vulnerabilities}

## Business Context
{business_context}

---

Generate a risk matrix:

1. **Likelihood Assessment**
   - Skill level required
   - Access requirements
   - Exploit availability

2. **Impact Assessment**
   - Confidentiality impact
   - Integrity impact
   - Availability impact
   - Financial impact
   - Reputational impact

3. **Risk Matrix**
   ```
                    IMPACT
             Low    Med    High   Crit
   L   High |  M  |  H  |  H  |  C  |
   I   Med  |  L  |  M  |  H  |  H  |
   K   Low  |  L  |  L  |  M  |  H  |
   E   VLow |  L  |  L  |  L  |  M  |
   ```

4. **Vulnerability Placement**
   | Vulnerability | Likelihood | Impact | Risk |
   |---------------|------------|--------|------|

5. **Prioritization**
   - Critical (immediate)
   - High (this week)
   - Medium (this month)
   - Low (this quarter)
"#
  )
}
