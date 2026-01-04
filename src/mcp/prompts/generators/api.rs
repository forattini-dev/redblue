//! API security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_api_security(args: &Args) -> String {
    let api_spec = get_arg(args, "api_spec", "not provided");
    let auth_type = get_arg(args, "auth_type", "unknown");

    format!(
        r#"# API Security Assessment

## API Specification
{api_spec}

## Authentication Type
{auth_type}

---

Perform API security assessment:

1. **Authentication Analysis**
   - Auth mechanism review
   - Token security
   - Session management
   - Credential handling
   - Brute force protection

2. **Authorization Testing**
   - BOLA/IDOR testing
   - BFLA testing
   - Role-based access
   - Horizontal privilege escalation
   - Vertical privilege escalation

3. **Input Validation**
   - Injection points
   - Parameter tampering
   - Mass assignment
   - Type confusion
   - XXE vulnerabilities

4. **Data Exposure**
   - Excessive data exposure
   - Sensitive data in responses
   - Debug information
   - Error messages
   - Stack traces

5. **Rate Limiting**
   - Request limits
   - Resource exhaustion
   - DoS protection
   - Throttling bypass

6. **Security Headers**
   - CORS configuration
   - Content-Type validation
   - Security headers
   - Cache controls

7. **OWASP API Top 10**
   | Risk | API1:2023 | Status | Details |
   |------|-----------|--------|---------|
   | Broken Object Level Auth | | | |
   | Broken Authentication | | | |
   | Broken Object Property Auth | | | |
   | Unrestricted Resource Consumption | | | |
   | Broken Function Level Auth | | | |

8. **Test Cases**
   ```bash
   # API security testing commands
   rb web asset get <endpoint>
   ```
"#
    )
}

pub fn gen_graphql_security(args: &Args) -> String {
    let endpoint = get_arg(args, "endpoint", "unknown");
    let schema = get_arg(args, "schema", "introspection");

    format!(
        r#"# GraphQL Security Testing

## Endpoint
{endpoint}

## Schema Source
{schema}

---

Perform GraphQL security testing:

1. **Introspection Analysis**
   - Introspection enabled
   - Schema disclosure
   - Hidden fields/types
   - Deprecated fields

2. **Authentication**
   - Auth mechanism
   - Token handling
   - Session security
   - Unauthenticated access

3. **Authorization**
   - Field-level authorization
   - Type-level authorization
   - Resolver authorization
   - IDOR vulnerabilities

4. **Query Attacks**
   - Deep query attacks
   - Circular queries
   - Alias overloading
   - Directive overloading
   - Field duplication

5. **Resource Limits**
   - Query depth limits
   - Query complexity limits
   - Timeout configuration
   - Pagination limits
   - Batching limits

6. **Injection Testing**
   - SQL injection via arguments
   - NoSQL injection
   - Command injection
   - SSRF via inputs

7. **Information Disclosure**
   - Error verbosity
   - Stack traces
   - Debug mode
   - Suggestions in errors

8. **Testing Queries**
   ```graphql
   # Introspection query
   query {{ __schema {{ types {{ name }} }} }}

   # Depth test
   query {{ user {{ posts {{ comments {{ author {{ posts ... }} }} }} }} }}
   ```

9. **Findings**
   | Vulnerability | Severity | Query | Remediation |
   |---------------|----------|-------|-------------|
"#
    )
}

pub fn gen_oauth_audit(args: &Args) -> String {
    let provider = get_arg(args, "provider", "unknown");
    let flows = get_arg(args, "flows", "authorization_code");

    format!(
        r#"# OAuth/OIDC Security Audit

## OAuth Provider
{provider}

## OAuth Flows Used
{flows}

---

Perform OAuth/OIDC security audit:

1. **Flow Configuration**
   - Supported flows
   - PKCE enforcement
   - State parameter usage
   - Nonce validation
   - Response types

2. **Token Security**
   - Token storage
   - Token transmission
   - Access token lifetime
   - Refresh token rotation
   - Token revocation

3. **Client Configuration**
   - Client authentication
   - Redirect URI validation
   - Client types
   - CORS configuration
   - Origins validation

4. **Authorization Server**
   - Discovery document
   - JWKS endpoint
   - Token endpoint security
   - Consent handling
   - Scope validation

5. **Common Vulnerabilities**
   | Attack | Risk | Mitigation | Status |
   |--------|------|------------|--------|
   | Open Redirect | | | |
   | Token Leakage | | | |
   | CSRF | | | |
   | Code Injection | | | |
   | Mix-up Attack | | | |

6. **ID Token Validation**
   - Signature verification
   - Claims validation
   - Issuer validation
   - Audience validation
   - Expiration checks

7. **Best Practices Checklist**
   - [ ] PKCE for public clients
   - [ ] Short-lived access tokens
   - [ ] Refresh token rotation
   - [ ] Secure token storage
   - [ ] State parameter validation

8. **Recommendations**
   - Critical fixes
   - Configuration changes
   - Monitoring additions
"#
    )
}

pub fn gen_jwt_analysis(args: &Args) -> String {
    let token = get_arg(args, "token", "[TOKEN]");
    let context = get_arg(args, "context", "general");

    format!(
        r#"# JWT Token Security Analysis

## Token
{token}

## Usage Context
{context}

---

Analyze JWT for security issues:

1. **Header Analysis**
   - Algorithm used
   - Key ID (kid)
   - Type claim
   - Custom headers

2. **Payload Analysis**
   - Standard claims (iss, sub, aud, exp, nbf, iat, jti)
   - Custom claims
   - Sensitive data exposure
   - Claim validation requirements

3. **Signature Verification**
   - Algorithm verification
   - Key/secret strength
   - None algorithm check
   - Algorithm confusion

4. **Common Vulnerabilities**
   | Attack | Risk | Details |
   |--------|------|---------|
   | None Algorithm | Critical | alg: none bypass |
   | Algorithm Confusion | Critical | RS256 to HS256 |
   | Weak Secret | High | Brute-forceable |
   | No Expiration | High | Token reuse |
   | Information Leak | Medium | Sensitive claims |

5. **Token Lifetime**
   - Expiration (exp)
   - Not Before (nbf)
   - Issued At (iat)
   - Refresh mechanism

6. **Storage & Transmission**
   - Where stored (cookie vs localStorage)
   - HttpOnly/Secure flags
   - SameSite attribute
   - Transmission security

7. **Validation Checklist**
   - [ ] Signature verified
   - [ ] Algorithm whitelisted
   - [ ] Expiration checked
   - [ ] Issuer validated
   - [ ] Audience validated

8. **Decoded Token**
   ```json
   {{
     "header": {{}},
     "payload": {{}},
     "signature": ""
   }}
   ```

9. **Recommendations**
   - Security fixes
   - Claim additions
   - Rotation strategy
"#
    )
}
