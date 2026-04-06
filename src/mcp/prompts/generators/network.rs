//! Network security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_network_segmentation(args: &Args) -> String {
  let topology = get_arg(args, "topology", "not provided");
  let zones = get_arg(args, "zones", "not defined");

  format!(
    r#"# Network Segmentation Analysis

## Network Topology
{topology}

## Security Zones
{zones}

---

Analyze network segmentation:

1. **Zone Inventory**
   | Zone | CIDR | Purpose | Trust Level |
   |------|------|---------|-------------|
   | DMZ | | Public services | Low |
   | Internal | | Corporate | Medium |
   | Management | | Admin | High |
   | PCI | | Cardholder data | Critical |

2. **Segmentation Controls**
   - VLAN configuration
   - Routing ACLs
   - Firewall rules
   - Micro-segmentation
   - Software-defined

3. **Inter-Zone Traffic**
   | Source Zone | Dest Zone | Allowed | Denied | Review |
   |-------------|-----------|---------|--------|--------|

4. **Critical Path Analysis**
   - Internet -> DMZ -> Internal
   - Internal -> Database
   - Management access
   - Backup flows

5. **Compliance Mapping**
   - PCI DSS zones
   - HIPAA segments
   - Regulatory requirements

6. **Gap Analysis**
   - Missing controls
   - Overly permissive rules
   - Flat network areas
   - Legacy exceptions

7. **Recommendations**
   - Quick wins
   - Strategic changes
   - Monitoring additions

8. **Network Diagram**
   ```
   [Internet]
       |
   [Firewall]
       |
   +---+---+
   |  DMZ  |--[IDS]
   +---+---+
       |
   [Internal FW]
       |
   +---+-----------+
   |   Internal    |
   +---------------+
   ```
"#
  )
}

pub fn gen_firewall_review(args: &Args) -> String {
  let rules = get_arg(args, "rules", "not provided");
  let vendor = get_arg(args, "vendor", "generic");

  format!(
    r#"# Firewall Rule Set Review

## Rules Configuration
{rules}

## Firewall Vendor
{vendor}

---

Review firewall rules for security issues:

1. **Rule Analysis**
   | # | Source | Dest | Service | Action | Risk | Issue |
   |---|--------|------|---------|--------|------|-------|

2. **Common Issues**
   - Any/Any rules
   - Overly broad sources
   - Unnecessary services
   - Deprecated protocols
   - Shadow rules
   - Redundant rules

3. **Best Practices Check**
   - [ ] Default deny
   - [ ] Explicit allow rules
   - [ ] Logging enabled
   - [ ] No disabled rules
   - [ ] Rule documentation
   - [ ] Regular review

4. **High-Risk Rules**
   - Rules allowing inbound from any
   - Rules to sensitive networks
   - Broad outbound access
   - Management access rules

5. **Rule Optimization**
   - Consolidation opportunities
   - Object group usage
   - Rule ordering
   - Performance impact

6. **Compliance Check**
   | Requirement | Status | Rule # | Notes |
   |-------------|--------|--------|-------|

7. **Change Recommendations**
   | Current Rule | Recommended | Priority |
   |--------------|-------------|----------|

8. **Monitoring Gaps**
   - Logging configuration
   - Alert rules
   - Baseline traffic
   - Anomaly detection
"#
  )
}

pub fn gen_vpn_security(args: &Args) -> String {
  let config = get_arg(args, "config", "not provided");
  let protocol = get_arg(args, "protocol", "ipsec");

  format!(
    r#"# VPN Security Assessment

## VPN Configuration
{config}

## VPN Protocol
{protocol}

---

Assess VPN security configuration:

1. **Protocol Security**
   - Protocol version
   - Cipher suites
   - Key exchange
   - Authentication
   - Perfect forward secrecy

2. **Authentication**
   - Authentication method
   - Certificate validation
   - MFA enforcement
   - Pre-shared key strength
   - User management

3. **Encryption**
   | Phase | Algorithm | Key Size | Status |
   |-------|-----------|----------|--------|
   | Phase 1 | | | |
   | Phase 2 | | | |
   | Data | | | |

4. **Tunnel Security**
   - Split tunneling
   - DNS leak prevention
   - IPv6 protection
   - Kill switch
   - Reconnection behavior

5. **Access Controls**
   - User authorization
   - Group policies
   - Network access rules
   - Time-based access
   - Geo-restrictions

6. **Logging & Monitoring**
   - Connection logs
   - Authentication logs
   - Traffic analysis
   - Anomaly detection

7. **Vulnerability Check**
   - Known CVEs
   - Configuration weaknesses
   - Downgrade attacks
   - Implementation flaws

8. **Recommendations**
   | Finding | Severity | Current | Recommended |
   |---------|----------|---------|-------------|

9. **Hardened Configuration**
   ```
   # Recommended configuration
   ```
"#
  )
}
