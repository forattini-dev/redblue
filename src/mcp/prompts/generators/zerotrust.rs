//! Zero Trust security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_zero_trust_assessment(args: &Args) -> String {
  let current_state = get_arg(args, "current_state", "not provided");
  let maturity = get_arg(args, "maturity", "developing");

  format!(
    r#"# Zero Trust Architecture Assessment

## Current State
{current_state}

## Target Maturity
{maturity}

---

Assess Zero Trust maturity and roadmap:

1. **Zero Trust Pillars Assessment**
   | Pillar | Current | Target | Gap |
   |--------|---------|--------|-----|
   | Identity | | | |
   | Devices | | | |
   | Network | | | |
   | Applications | | | |
   | Data | | | |
   | Visibility | | | |
   | Automation | | | |

2. **Identity Pillar**
   - Identity verification
   - Strong authentication (MFA)
   - Continuous validation
   - Privileged access
   - Identity governance

3. **Device Pillar**
   - Device inventory
   - Health attestation
   - Endpoint protection
   - Mobile device management
   - Compliance enforcement

4. **Network Pillar**
   - Micro-segmentation
   - Encrypted transport
   - Network visibility
   - Software-defined perimeter
   - Zero trust network access

5. **Application Pillar**
   - Application discovery
   - Secure access
   - Workload protection
   - API security
   - DevSecOps

6. **Data Pillar**
   - Data classification
   - Encryption
   - DLP controls
   - Access monitoring
   - Rights management

7. **Maturity Model**
   ```
   Traditional -> Initial -> Developing -> Defined -> Managed -> Optimizing
                    ^
               Current State
   ```

8. **Roadmap**
   | Phase | Timeline | Focus Area | Deliverables |
   |-------|----------|------------|--------------|
   | 1 | 0-3 mo | | |
   | 2 | 3-6 mo | | |
   | 3 | 6-12 mo | | |

9. **Quick Wins**
   - Immediate actions
   - Low effort/high impact
   - Foundation building
"#
  )
}

pub fn gen_identity_security(args: &Args) -> String {
  let provider = get_arg(args, "provider", "unknown");
  let scope = get_arg(args, "scope", "full");

  format!(
    r#"# Identity & Access Management Security Review

## Identity Provider
{provider}

## Assessment Scope
{scope}

---

Review IAM security:

1. **Identity Lifecycle**
   - Provisioning process
   - Deprovisioning automation
   - Access reviews
   - Orphan accounts
   - Service accounts

2. **Authentication Security**
   - MFA coverage
   - MFA methods
   - Password policies
   - Risk-based authentication
   - Passwordless adoption

3. **Authorization Controls**
   - RBAC implementation
   - Least privilege
   - Role mining
   - Entitlement review
   - Segregation of duties

4. **Privileged Access**
   - Privileged accounts inventory
   - PAM solution
   - Just-in-time access
   - Session recording
   - Break-glass procedures

5. **Federation & SSO**
   - IdP configuration
   - SAML/OIDC security
   - Claims mapping
   - Session management
   - Conditional access

6. **Identity Governance**
   - Access certification
   - Policy enforcement
   - Compliance reporting
   - Audit trails
   - SoD violations

7. **Findings Matrix**
   | Finding | Category | Risk | Remediation |
   |---------|----------|------|-------------|

8. **Metrics**
   - MFA adoption: X%
   - Average permissions: X
   - Orphan accounts: X
   - Access review completion: X%

9. **Recommendations**
   - Critical fixes
   - Process improvements
   - Technology additions
"#
  )
}

pub fn gen_microsegmentation(args: &Args) -> String {
  let environment = get_arg(args, "environment", "hybrid");
  let workloads = get_arg(args, "workloads", "mixed");

  format!(
    r#"# Microsegmentation Strategy

## Environment
{environment}

## Workload Types
{workloads}

---

Design microsegmentation strategy:

1. **Current State Assessment**
   - Existing segmentation
   - Network visibility
   - Traffic patterns
   - Application dependencies

2. **Workload Discovery**
   | Workload | Location | Tier | Dependencies | Critical |
   |----------|----------|------|--------------|----------|

3. **Policy Design**
   - Default deny
   - Application-centric policies
   - Identity-based rules
   - Environment isolation
   - Exception handling

4. **Implementation Approach**
   | Phase | Workloads | Mode | Timeline |
   |-------|-----------|------|----------|
   | 1 | Critical apps | Monitor | Week 1-2 |
   | 2 | Critical apps | Enforce | Week 3-4 |
   | 3 | Standard apps | Monitor | Week 5-6 |
   | 4 | Standard apps | Enforce | Week 7-8 |

5. **Policy Examples**
   ```yaml
   # Application tier policy
   source: web-tier
   destination: app-tier
   ports: [8080, 8443]
   action: allow
   ```

6. **Technology Options**
   | Solution | Pros | Cons | Fit |
   |----------|------|------|-----|
   | Host-based | | | |
   | Network-based | | | |
   | Cloud-native | | | |

7. **Operational Model**
   - Policy management
   - Change process
   - Monitoring & alerts
   - Troubleshooting
   - Compliance reporting

8. **Success Metrics**
   - Policy coverage
   - Violation rate
   - Mean time to policy
   - Drift detection

9. **Risks & Mitigations**
   - Application breakage
   - Performance impact
   - Operational overhead
"#
  )
}

pub fn gen_sase_assessment(args: &Args) -> String {
  let current_tools = get_arg(args, "current_tools", "not provided");
  let requirements = get_arg(args, "requirements", "general");

  format!(
    r#"# SASE (Secure Access Service Edge) Assessment

## Current Security Tools
{current_tools}

## Business Requirements
{requirements}

---

Assess SASE readiness and strategy:

1. **Current State Inventory**
   | Component | Current Tool | Location | Status |
   |-----------|--------------|----------|--------|
   | SWG | | | |
   | CASB | | | |
   | ZTNA | | | |
   | FWaaS | | | |
   | SD-WAN | | | |

2. **SASE Components Assessment**
   - Secure Web Gateway (SWG)
   - Cloud Access Security Broker (CASB)
   - Zero Trust Network Access (ZTNA)
   - Firewall as a Service (FWaaS)
   - SD-WAN integration

3. **Requirements Analysis**
   | Requirement | Priority | Current | SASE Solution |
   |-------------|----------|---------|---------------|
   | Remote access | | | |
   | Cloud security | | | |
   | Branch connectivity | | | |
   | Data protection | | | |
   | Threat protection | | | |

4. **Architecture Options**
   ```
   Option A: Single Vendor SASE
   [Users] -> [SASE PoP] -> [Cloud Apps]
                        -> [Data Center]

   Option B: Best-of-Breed
   [Users] -> [SD-WAN] -> [SSE] -> [Apps]
   ```

5. **Vendor Evaluation**
   | Vendor | SWG | CASB | ZTNA | FWaaS | SD-WAN | Score |
   |--------|-----|------|------|-------|--------|-------|

6. **Migration Approach**
   | Phase | Component | Timeline | Dependencies |
   |-------|-----------|----------|--------------|
   | 1 | | | |
   | 2 | | | |
   | 3 | | | |

7. **Risk Assessment**
   - Vendor lock-in
   - Performance impact
   - Integration complexity
   - Compliance gaps
   - Cost implications

8. **Business Case**
   - Current TCO
   - SASE TCO
   - Efficiency gains
   - Risk reduction

9. **Recommendations**
   - Preferred approach
   - Vendor shortlist
   - Implementation roadmap
"#
  )
}
