//! Attack planning prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_attack_plan(args: &Args) -> String {
    let target = get_arg(args, "target", "unknown");
    let findings = get_arg(args, "findings", "none");
    let objective = get_arg(args, "objective", "initial_access");

    format!(
        r#"# Attack Plan Generation (AUTHORIZED PENTEST ONLY)

## Target
{target}

## Reconnaissance Findings
{findings}

## Objective
{objective}

---

**WARNING: This is for authorized penetration testing only.**

Generate an attack plan with:

1. **Attack Phases** (MITRE ATT&CK mapped)
   - Initial Access techniques
   - Execution methods
   - Persistence options
   - Privilege escalation paths
   - Defense evasion considerations

2. **Attack Path Options**
   | Path | Entry Point | Steps | Likelihood | Impact |
   |------|-------------|-------|------------|--------|

3. **Tool Recommendations**
   ```bash
   rb exploit payload shell <type> <lhost> <lport>
   rb exploit plan generate --target <target>
   ```

4. **Operational Security**
   - Detection risks
   - Log artifacts
   - Cleanup requirements

5. **Contingency Plans**
   - If initial access fails
   - If detected
   - Emergency extraction
"#
    )
}

pub fn gen_exploit_suggest(args: &Args) -> String {
    let vulnerabilities = get_arg(args, "vulnerabilities", "none");
    let target_os = get_arg(args, "target_os", "unknown");

    format!(
        r#"# Exploit Suggestion Request

## Identified Vulnerabilities
{vulnerabilities}

## Target OS
{target_os}

---

Please suggest exploits for these vulnerabilities:

1. **Exploit Research**
   ```bash
   rb intel vuln exploit <CVE>
   rb intel vuln search <technology> --source all
   ```

2. **Exploit Matrix**
   | CVE | Exploit | Type | Reliability | Link |
   |-----|---------|------|-------------|------|

3. **Payload Recommendations**
   - For each viable exploit
   - Platform-specific payloads
   - Evasion considerations

4. **Alternative Approaches**
   - If no public exploit exists
   - Manual exploitation steps
   - Custom payload requirements

5. **Testing Considerations**
   - Lab environment setup
   - Safe testing procedures
   - Backup and recovery
"#
    )
}

pub fn gen_lateral_movement(args: &Args) -> String {
    let current_access = get_arg(args, "current_access", "unknown");
    let network_map = get_arg(args, "network_map", "not provided");
    let credentials = get_arg(args, "credentials", "none");

    format!(
        r#"# Lateral Movement Planning

## Current Access
{current_access}

## Network Map
{network_map}

## Available Credentials
{credentials}

---

Plan lateral movement with:

1. **Current Position Analysis**
   - What access do we have?
   - What can we reach from here?
   - What credentials are available?

2. **Target Identification**
   | Target | Reachability | Value | Method |
   |--------|--------------|-------|--------|

3. **Movement Techniques** (MITRE T1021)
   - RDP (T1021.001)
   - SMB/Admin Shares (T1021.002)
   - SSH (T1021.004)
   - WinRM (T1021.006)

4. **Credential Usage**
   - Pass-the-hash opportunities
   - Kerberos ticket usage
   - Credential reuse analysis

5. **OPSEC Considerations**
   - Log artifacts
   - Detection risks
   - Alternative paths
"#
    )
}

pub fn gen_persistence_analysis(args: &Args) -> String {
    let target_os = get_arg(args, "target_os", "linux");
    let access_level = get_arg(args, "access_level", "user");
    let stealth = get_arg(args, "stealth", "medium");

    format!(
        r#"# Persistence Mechanism Analysis

## Target OS
{target_os}

## Access Level
{access_level}

## Stealth Requirement
{stealth}

---

Analyze persistence options:

1. **Available Mechanisms** (based on access level)
   | Technique | MITRE ID | Access Needed | Detection Risk |
   |-----------|----------|---------------|----------------|

2. **Recommended Approach**
   ```bash
   rb exploit payload persist --os {target_os} --stealth {stealth}
   ```

3. **Implementation Details**
   - Exact commands/files
   - Configuration changes
   - Trigger mechanisms

4. **Detection & Cleanup**
   - How it would be detected
   - Forensic artifacts
   - Removal procedures

5. **Backup Mechanisms**
   - Secondary persistence
   - Failsafe options
"#
    )
}
