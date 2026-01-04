//! Reconnaissance prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_recon_strategy(args: &Args) -> String {
    let target = get_arg(args, "target", "unknown");
    let scope = get_arg(args, "scope", "full");
    let time_limit = get_arg(args, "time_limit", "no limit");

    format!(
        r#"# Reconnaissance Strategy Request

## Target
{target}

## Scope
{scope}

## Time Constraints
{time_limit}

---

Please create a comprehensive reconnaissance strategy for this target. Include:

1. **Passive Reconnaissance**
   - DNS enumeration approach
   - WHOIS and registration data
   - Certificate transparency logs
   - Web archives and cached data
   - Social media and OSINT sources
   - Job postings and technology indicators

2. **Active Reconnaissance** (if scope allows)
   - Port scanning strategy
   - Service enumeration
   - Web application discovery
   - Virtual host enumeration
   - Technology fingerprinting

3. **Tools & Commands**
   - Specific redblue commands to run
   - Order of operations
   - Expected outputs

4. **Risk Assessment**
   - Detection likelihood
   - Operational security considerations

Use redblue tool commands where applicable (e.g., `rb network ports scan`, `rb dns record lookup`, `rb recon domain whois`).
"#
    )
}

pub fn gen_subdomain_hunt(args: &Args) -> String {
    let domain = get_arg(args, "domain", "example.com");
    let depth = get_arg(args, "depth", "standard");

    format!(
        r#"# Subdomain Enumeration Request

## Target Domain
{domain}

## Enumeration Depth
{depth}

---

Please help me enumerate subdomains for this target. Provide:

1. **Enumeration Strategy**
   - Passive sources to query
   - Active brute-force approach
   - Permutation strategies

2. **Commands to Run**
   ```bash
   rb recon domain subdomains {domain}
   rb dns record lookup {domain} --type NS
   ```

3. **Analysis Framework**
   - How to prioritize interesting subdomains
   - What patterns to look for
   - Red flags and high-value targets

4. **Next Steps**
   - For each discovered subdomain type
   - Port scanning priorities
   - Technology fingerprinting

Focus on finding:
- Development/staging environments
- Admin panels
- API endpoints
- Legacy systems
- Third-party integrations
"#
    )
}

pub fn gen_osint_profile(args: &Args) -> String {
    let target = get_arg(args, "target", "unknown");
    let depth = get_arg(args, "depth", "moderate");

    format!(
        r#"# OSINT Profile Request

## Target
{target}

## Investigation Depth
{depth}

---

Build OSINT profile:

1. **Domain Intelligence**
   ```bash
   rb recon domain whois {target}
   rb recon domain subdomains {target}
   rb dns record lookup {target}
   ```

2. **Technical Footprint**
   - IP ranges
   - ASN information
   - Hosting providers
   - Technology stack

3. **Digital Presence**
   - Social media
   - Job postings
   - Press releases
   - Partnerships

4. **Security Posture Indicators**
   - Exposed services
   - Data leaks
   - Previous breaches
   - Security headers

5. **Key Findings Summary**
   - Attack surface highlights
   - Interesting discoveries
   - Recommended next steps
"#
    )
}

pub fn gen_attack_surface(args: &Args) -> String {
    let organization = get_arg(args, "organization", "unknown");
    let include_subs = get_arg(args, "include_subsidiaries", "false");

    format!(
        r#"# External Attack Surface Mapping

## Organization
{organization}

## Include Subsidiaries
{include_subs}

---

Map external attack surface:

1. **Domain Discovery**
   ```bash
   rb recon domain whois {organization}
   rb recon domain subdomains {organization}
   ```

2. **Asset Inventory**
   | Domain | IPs | Services | Risk |
   |--------|-----|----------|------|

3. **Service Exposure**
   - Internet-facing services
   - Administrative interfaces
   - API endpoints
   - Development/staging

4. **Risk Assessment**
   - Critical exposures
   - Outdated services
   - Missing security controls

5. **Recommendations**
   - Immediate actions
   - Services to secure
   - Monitoring requirements
"#
    )
}
