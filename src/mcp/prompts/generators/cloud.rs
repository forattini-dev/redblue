//! Cloud security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_cloud_audit(args: &Args) -> String {
    let provider = get_arg(args, "provider", "aws");
    let scope = get_arg(args, "scope", "full");
    let compliance = get_arg(args, "compliance", "cis");

    format!(
        r#"# Cloud Infrastructure Security Audit

## Cloud Provider
{provider}

## Audit Scope
{scope}

## Compliance Framework
{compliance}

---

Perform comprehensive cloud security audit:

1. **Identity & Access Management**
   - Root/admin account usage
   - MFA enforcement
   - Service account hygiene
   - Role policies (least privilege)
   - Cross-account access

2. **Network Security**
   - VPC configuration
   - Security groups / NSGs
   - Public exposure
   - Network ACLs
   - VPN/Direct Connect

3. **Data Protection**
   - Encryption at rest
   - Encryption in transit
   - Key management
   - Backup policies
   - Data classification

4. **Logging & Monitoring**
   - CloudTrail / Activity Log / Audit Log
   - Flow logs
   - Alert configuration
   - SIEM integration

5. **Compute Security**
   - Instance metadata protection
   - Patch management
   - Container security
   - Serverless security

6. **{compliance} Compliance Mapping**
   | Control | Status | Evidence | Remediation |
   |---------|--------|----------|-------------|

7. **Critical Findings**
   - High-risk misconfigurations
   - Immediate actions required
   - Remediation priority
"#
    )
}

pub fn gen_aws_security(args: &Args) -> String {
    let account_id = get_arg(args, "account_id", "unknown");
    let services = get_arg(args, "services", "all");

    format!(
        r#"# AWS Security Assessment

## AWS Account
{account_id}

## Services to Audit
{services}

---

Perform AWS-specific security assessment:

1. **IAM Security**
   - Root account MFA
   - IAM users vs roles
   - Policy analysis (overly permissive)
   - Access keys age
   - Password policy

2. **S3 Security**
   - Public buckets
   - Bucket policies
   - ACL configuration
   - Block public access settings
   - Encryption configuration

3. **EC2 Security**
   - IMDSv2 enforcement
   - Security group rules
   - EBS encryption
   - Public IPs
   - Key pair management

4. **Lambda Security**
   - Function permissions
   - VPC configuration
   - Environment variables
   - Execution role policies

5. **RDS Security**
   - Public accessibility
   - Encryption
   - Security groups
   - IAM authentication
   - Audit logging

6. **CloudTrail & GuardDuty**
   - Multi-region trails
   - Log file validation
   - GuardDuty findings
   - S3 data events

7. **Network Security**
   - VPC flow logs
   - Default VPC usage
   - NAT gateway configuration
   - Transit Gateway

8. **Recommendations**
   | Finding | Severity | AWS Service | Remediation |
   |---------|----------|-------------|-------------|
"#
    )
}

pub fn gen_azure_security(args: &Args) -> String {
    let subscription = get_arg(args, "subscription", "unknown");
    let focus = get_arg(args, "focus", "full");

    format!(
        r#"# Azure Security Assessment

## Azure Subscription
{subscription}

## Focus Area
{focus}

---

Perform Azure-specific security assessment:

1. **Azure AD Security**
   - Privileged Identity Management (PIM)
   - Conditional Access policies
   - MFA enforcement
   - Guest user access
   - App registrations

2. **Identity & Access**
   - RBAC assignments
   - Management groups
   - Custom roles
   - Service principals
   - Managed identities

3. **Network Security**
   - NSG rules
   - Azure Firewall
   - Application Gateway WAF
   - Private endpoints
   - VNet peering

4. **Storage Security**
   - Storage account access
   - Blob public access
   - SAS token policies
   - Encryption settings
   - Network rules

5. **Compute Security**
   - VM extensions
   - Just-in-time access
   - Update management
   - Disk encryption
   - Bastion hosts

6. **Microsoft Defender for Cloud**
   - Security posture score
   - Recommendations
   - Alert status
   - Regulatory compliance

7. **Logging & Monitoring**
   - Activity log export
   - Diagnostic settings
   - Azure Monitor
   - Log Analytics

8. **Recommendations**
   | Finding | Severity | Azure Service | Remediation |
   |---------|----------|---------------|-------------|
"#
    )
}

pub fn gen_gcp_security(args: &Args) -> String {
    let project = get_arg(args, "project", "unknown");
    let services = get_arg(args, "services", "all");

    format!(
        r#"# GCP Security Assessment

## GCP Project
{project}

## Services to Audit
{services}

---

Perform GCP-specific security assessment:

1. **IAM Security**
   - Service account usage
   - Key management
   - Workload identity
   - Organization policies
   - Custom roles

2. **Cloud Storage Security**
   - Bucket ACLs
   - Uniform bucket-level access
   - Public access prevention
   - Retention policies
   - CMEK encryption

3. **Compute Engine Security**
   - VM metadata
   - Service account scopes
   - Firewall rules
   - Shielded VMs
   - OS patch management

4. **Cloud Functions Security**
   - Function permissions
   - Ingress settings
   - VPC connector
   - Environment secrets

5. **GKE Security**
   - Private clusters
   - Workload identity
   - Network policies
   - Binary authorization
   - Pod security policies

6. **BigQuery Security**
   - Dataset access
   - Column-level security
   - Audit logging
   - Data masking

7. **Security Command Center**
   - Findings status
   - Asset inventory
   - Compliance status
   - Threat detection

8. **Recommendations**
   | Finding | Severity | GCP Service | Remediation |
   |---------|----------|-------------|-------------|
"#
    )
}

pub fn gen_s3_audit(args: &Args) -> String {
    let bucket = get_arg(args, "bucket", "*");
    let deep_scan = get_arg(args, "deep_scan", "false");

    format!(
        r#"# AWS S3 Bucket Security Audit

## Target Bucket(s)
{bucket}

## Deep Content Scan
{deep_scan}

---

Perform S3 bucket security audit:

1. **Access Configuration**
   - Block Public Access settings
   - Bucket policy analysis
   - ACL configuration
   - Cross-account access
   - Pre-signed URL policies

2. **Encryption**
   - Default encryption
   - SSE-S3 vs SSE-KMS vs SSE-C
   - Bucket key usage
   - In-transit encryption

3. **Logging & Monitoring**
   - Server access logging
   - CloudTrail data events
   - S3 event notifications
   - Access analyzer findings

4. **Data Protection**
   - Versioning enabled
   - MFA delete
   - Object lock
   - Lifecycle policies
   - Replication rules

5. **Access Points**
   - Access point policies
   - VPC restrictions
   - Network origin

6. **Sensitive Data Discovery**
   - PII indicators
   - Credentials/secrets
   - Backup files
   - Log files with sensitive data

7. **Findings Summary**
   | Bucket | Issue | Severity | Remediation |
   |--------|-------|----------|-------------|

8. **Remediation Commands**
   ```bash
   aws s3api put-public-access-block --bucket <bucket> ...
   aws s3api put-bucket-encryption --bucket <bucket> ...
   ```
"#
    )
}
