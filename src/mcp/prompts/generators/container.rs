//! Container and Kubernetes security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_container_security(args: &Args) -> String {
    let image = get_arg(args, "image", "unknown");
    let runtime = get_arg(args, "runtime", "docker");

    format!(
        r#"# Container Security Assessment

## Container Image
{image}

## Container Runtime
{runtime}

---

Perform container security assessment:

1. **Image Security**
   - Base image analysis
   - Layer history
   - Vulnerability scanning
   - Malware detection
   - Image signing/verification

2. **Build Security**
   - Dockerfile best practices
   - Multi-stage builds
   - Secret handling
   - User permissions
   - Package sources

3. **Runtime Security**
   - Privileged mode
   - Capabilities
   - Seccomp profiles
   - AppArmor/SELinux
   - Read-only filesystem

4. **Network Security**
   - Exposed ports
   - Network mode
   - Container isolation
   - Traffic encryption

5. **Resource Limits**
   - CPU limits
   - Memory limits
   - PID limits
   - Storage limits

6. **Secrets & Configuration**
   - Environment variables
   - Mounted secrets
   - Config files
   - Sensitive data exposure

7. **Vulnerability Report**
   | Package | Version | CVE | Severity | Fixed In |
   |---------|---------|-----|----------|----------|

8. **Hardening Recommendations**
   - Critical fixes
   - Base image alternatives
   - Runtime restrictions
"#
    )
}

pub fn gen_k8s_security(args: &Args) -> String {
    let cluster = get_arg(args, "cluster", "unknown");
    let namespace = get_arg(args, "namespace", "all");
    let focus = get_arg(args, "focus", "full");

    format!(
        r#"# Kubernetes Security Assessment

## Cluster
{cluster}

## Namespace
{namespace}

## Focus Area
{focus}

---

Perform Kubernetes security assessment:

1. **Cluster Configuration**
   - API server security
   - etcd encryption
   - Admission controllers
   - Audit logging
   - Network policies default

2. **RBAC Analysis**
   - Cluster roles
   - Role bindings
   - Service accounts
   - Privileged bindings
   - Default service accounts

3. **Pod Security**
   - Pod Security Standards/Policies
   - Privileged containers
   - Host namespaces
   - Capabilities
   - Security contexts

4. **Network Security**
   - Network policies
   - Ingress configuration
   - Service mesh
   - mTLS enforcement
   - Egress controls

5. **Secrets Management**
   - Secret encryption
   - External secrets
   - Secret access
   - Rotation policies

6. **Workload Security**
   - Image policies
   - Resource limits
   - Liveness/readiness
   - PodDisruptionBudgets

7. **Runtime Security**
   - Container runtime
   - Runtime classes
   - Falco/runtime detection
   - Pod security admission

8. **Findings Matrix**
   | Resource | Namespace | Issue | Severity | Remediation |
   |----------|-----------|-------|----------|-------------|
"#
    )
}

pub fn gen_dockerfile_review(args: &Args) -> String {
    let dockerfile = get_arg(args, "dockerfile", "not provided");
    let base_image = get_arg(args, "base_image", "unknown");

    format!(
        r#"# Dockerfile Security Review

## Dockerfile Content
```dockerfile
{dockerfile}
```

## Base Image
{base_image}

---

Review Dockerfile for security issues:

1. **Base Image Analysis**
   - Official image vs custom
   - Image tag (avoid :latest)
   - Known vulnerabilities
   - Size optimization
   - Distroless alternatives

2. **Build Security**
   - Multi-stage builds
   - Build arguments
   - Cache optimization
   - Layer ordering

3. **User Permissions**
   - Non-root user
   - USER instruction
   - File permissions
   - Capability dropping

4. **Secrets Handling**
   - No secrets in build
   - Build-time secrets
   - Multi-stage for secrets
   - .dockerignore review

5. **Package Management**
   - Package pinning
   - Vulnerability scanning
   - Unnecessary packages
   - Cache cleanup

6. **Runtime Configuration**
   - EXPOSE statements
   - ENTRYPOINT vs CMD
   - Health checks
   - Signal handling

7. **Security Checklist**
   | Check | Status | Line | Recommendation |
   |-------|--------|------|----------------|
   | Non-root user | | | |
   | Pinned versions | | | |
   | No secrets | | | |
   | Minimal base | | | |

8. **Optimized Dockerfile**
   ```dockerfile
   # Recommended changes
   ```
"#
    )
}

pub fn gen_helm_security(args: &Args) -> String {
    let chart = get_arg(args, "chart", "unknown");
    let values = get_arg(args, "values", "default");

    format!(
        r#"# Helm Chart Security Review

## Chart
{chart}

## Values Configuration
{values}

---

Review Helm chart for security issues:

1. **Chart Structure**
   - Chart.yaml analysis
   - Dependencies review
   - Template security
   - NOTES.txt disclosure

2. **Security Contexts**
   - Pod security contexts
   - Container security contexts
   - RunAsNonRoot
   - ReadOnlyRootFilesystem
   - Capabilities

3. **RBAC Configuration**
   - Service accounts
   - Roles/ClusterRoles
   - Bindings
   - Least privilege

4. **Network Policies**
   - Ingress rules
   - Egress rules
   - Default deny
   - Service exposure

5. **Resource Limits**
   - CPU limits
   - Memory limits
   - Replica counts
   - HPA configuration

6. **Secrets Handling**
   - Secret references
   - External secrets
   - Sealed secrets
   - Vault integration

7. **Image Configuration**
   - Image pull policy
   - Image tags
   - Private registries
   - Image pull secrets

8. **Security Findings**
   | Template | Line | Issue | Severity | Fix |
   |----------|------|-------|----------|-----|

9. **Hardened Values**
   ```yaml
   # Security-focused values.yaml
   ```
"#
    )
}
