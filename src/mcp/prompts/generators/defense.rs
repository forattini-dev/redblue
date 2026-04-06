//! Defensive security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_hardening_guide(args: &Args) -> String {
  let system = get_arg(args, "system", "unknown");
  let baseline = get_arg(args, "baseline", "CIS");

  format!(
    r#"# System Hardening Guide

## System
{system}

## Baseline Standard
{baseline}

---

Generate hardening recommendations:

1. **Configuration Hardening**
   | Setting | Current | Recommended | Priority |
   |---------|---------|-------------|----------|

2. **Network Hardening**
   - Firewall rules
   - Network segmentation
   - Service exposure

3. **Access Controls**
   - Authentication requirements
   - Authorization policies
   - Privilege restrictions

4. **Logging & Monitoring**
   - Required log sources
   - Retention policies
   - Alert thresholds

5. **Verification Commands**
   ```bash
   # Commands to verify each setting
   ```
"#
  )
}
