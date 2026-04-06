//! Web Application Playbooks
//!
//! Playbooks for web vulnerabilities: SQLi, XSS, auth bypass, API testing, file upload.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// SQL Injection Discovery
pub fn sql_injection_discovery() -> Playbook {
  Playbook::new("sql-injection-discovery", "SQL Injection Discovery")
    .with_description("Detect and exploit SQL injection vulnerabilities in web applications")
    .with_objective("Identify SQL injection points and assess database access impact")
    .for_target(TargetType::WebApp)
    .for_target(TargetType::Api)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::Medium)
    .with_duration("30-90 minutes")
    .with_tag("web")
    .with_tag("injection")
    .with_tag("database")
    .with_mitre("T1190")
    .add_precondition(PreCondition::new("Target web application accessible"))
    .add_precondition(PreCondition::new("Authorization for injection testing"))
    // Parameter Discovery
    .add_step(
      PlaybookStep::new(1, PlaybookPhase::Recon, "Parameter Discovery")
        .with_description("Identify injectable parameters in forms and URLs")
        .with_command("rb web crawl {{ target }} --depth 3")
        .with_success("Input parameters mapped")
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1595.002", None),
    )
    // Error-based Testing
    .add_step(
      PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Error-Based SQLi Test")
        .with_description("Test for error-based SQL injection")
        .with_command("rb web fuzz {{ target }} --wordlist sqli-error")
        .with_success("SQLi error responses captured")
        .depends(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1190", None),
    )
    // Blind SQLi Testing
    .add_step(
      PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Blind SQLi Test")
        .with_description("Test for blind SQL injection using time-based techniques")
        .with_command("rb web fuzz {{ target }} --wordlist sqli-blind")
        .with_success("Blind SQLi confirmed via time delays")
        .depends(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1190", None),
    )
    // Data Extraction
    .add_step(
      PlaybookStep::new(4, PlaybookPhase::Collection, "Database Enumeration")
        .with_description("Extract database schema and data")
        .with_manual("Use sqlmap or manual UNION-based extraction")
        .with_success("Database structure extracted")
        .when(StepCondition::OnSuccess(2))
        .collects(EvidenceType::Credentials)
        .with_mitre("T1005", None),
    )
    .add_evidence(
      ExpectedEvidence::new("SQLi vulnerability proof")
        .at("Injection response")
        .with_indicator("Database errors, extracted data")
        .severity(FindingSeverity::Critical),
    )
    .add_failed_control(
      FailedControl::new(
        "Input Validation",
        "User input not sanitized before SQL queries",
      )
      .with_fix("Use parameterized queries and prepared statements"),
    )
}

/// Cross-Site Scripting Detection
pub fn xss_detection() -> Playbook {
  Playbook::new("xss-detection", "Cross-Site Scripting Detection")
    .with_description("Detect stored, reflected, and DOM-based XSS vulnerabilities")
    .with_objective(
      "Identify XSS vulnerabilities that could lead to session hijacking or data theft",
    )
    .for_target(TargetType::WebApp)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::Low)
    .with_duration("30-60 minutes")
    .with_tag("web")
    .with_tag("xss")
    .with_tag("injection")
    .with_mitre("T1059.007")
    .add_precondition(PreCondition::new("Target web application accessible"))
    // Input Point Mapping
    .add_step(
      PlaybookStep::new(1, PlaybookPhase::Recon, "Input Point Mapping")
        .with_description("Identify all user input reflection points")
        .with_command("rb web crawl {{ target }} --forms")
        .with_success("Form inputs and parameters mapped")
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1595.002", None),
    )
    // Reflected XSS Testing
    .add_step(
      PlaybookStep::new(2, PlaybookPhase::Execution, "Reflected XSS Test")
        .with_description("Test for reflected XSS in URL parameters")
        .with_command("rb web fuzz {{ target }} --wordlist xss-reflected")
        .with_success("Reflected XSS found")
        .depends(1)
        .parallel(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1059.007", None),
    )
    // Stored XSS Testing
    .add_step(
      PlaybookStep::new(3, PlaybookPhase::Execution, "Stored XSS Test")
        .with_description("Test for stored XSS in persistent data")
        .with_manual("Submit XSS payloads to forms, comments, profiles")
        .with_success("Stored XSS payload persisted and executed")
        .depends(1)
        .parallel(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1059.007", None),
    )
    // DOM XSS Testing
    .add_step(
      PlaybookStep::new(4, PlaybookPhase::Execution, "DOM-Based XSS Test")
        .with_description("Test for DOM-based XSS in client-side code")
        .with_manual("Analyze JavaScript for DOM manipulation sinks")
        .with_success("DOM XSS vectors identified")
        .optional()
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1059.007", None),
    )
    .add_evidence(
      ExpectedEvidence::new("XSS proof of concept")
        .at("Browser alert or DOM modification")
        .with_indicator("Script execution in user context")
        .severity(FindingSeverity::High),
    )
    .add_failed_control(
      FailedControl::new("Output Encoding", "User input rendered without encoding")
        .with_fix("Implement context-aware output encoding, CSP headers"),
    )
}

/// Authentication Bypass
pub fn authentication_bypass() -> Playbook {
  Playbook::new("authentication-bypass", "Authentication Bypass")
        .with_description("Test for authentication flaws including default creds, session issues, and bypass techniques")
        .with_objective("Identify authentication weaknesses that allow unauthorized access")
        .for_target(TargetType::WebApp)
        .for_target(TargetType::Api)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Medium)
        .with_duration("30-60 minutes")
        .with_tag("web")
        .with_tag("authentication")
        .with_tag("session")
        .with_mitre("T1078")
        .add_precondition(PreCondition::new("Login page or API authentication endpoint identified"))
        // Default Credentials
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::InitialAccess, "Default Credential Test")
                .with_description("Test for default and common credentials")
                .with_command("rb password spray {{ target }} --wordlist default-creds")
                .with_success("Default credentials work")
                .parallel(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1078.001", None),
        )
        // Credential Stuffing
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Credential Stuffing")
                .with_description("Test leaked credentials from breach databases")
                .with_manual("Use breach data against login endpoint")
                .with_success("Reused credentials found")
                .parallel(1)
                .collects(EvidenceType::Credentials)
                .with_mitre("T1078", None),
        )
        // Session Testing
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::CredentialAccess, "Session Token Analysis")
                .with_description("Analyze session tokens for weaknesses")
                .with_manual("Check token entropy, predictability, expiration")
                .with_success("Session weaknesses documented")
                .collects(EvidenceType::SessionData)
                .with_mitre("T1539", None),
        )
        // JWT Testing
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::CredentialAccess, "JWT/Token Bypass")
                .with_description("Test for JWT signature bypass and manipulation")
                .with_manual("Test alg=none, weak signing keys, claim manipulation")
                .with_success("JWT bypass successful")
                .optional()
                .collects(EvidenceType::SessionData)
                .with_mitre("T1550", None),
        )
        .add_evidence(
            ExpectedEvidence::new("Authentication bypass proof")
                .at("Authenticated session")
                .with_indicator("Access to protected resources without valid credentials")
                .severity(FindingSeverity::Critical),
        )
        .add_failed_control(
            FailedControl::new("Credential Management", "Default or weak credentials in use")
                .with_fix("Enforce strong password policy, MFA, account lockout"),
        )
}

/// API Security Assessment
pub fn api_security_assessment() -> Playbook {
  Playbook::new("api-security-assessment", "API Security Assessment")
    .with_description("Comprehensive security testing for REST and GraphQL APIs")
    .with_objective(
      "Identify API-specific vulnerabilities including BOLA, injection, and authorization flaws",
    )
    .for_target(TargetType::Api)
    .for_target(TargetType::WebApp)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::Medium)
    .with_duration("1-3 hours")
    .with_tag("web")
    .with_tag("api")
    .with_tag("rest")
    .with_tag("graphql")
    .with_mitre("T1190")
    .add_precondition(PreCondition::new("API endpoints identified"))
    .add_precondition(PreCondition::new(
      "API documentation or schema available (preferred)",
    ))
    // Endpoint Discovery
    .add_step(
      PlaybookStep::new(1, PlaybookPhase::Recon, "API Endpoint Discovery")
        .with_description("Discover API endpoints and methods")
        .with_command("rb web fuzz {{ target }}/api --wordlist api-endpoints")
        .with_success("API endpoints mapped")
        .parallel(1)
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1595.002", None),
    )
    // Schema Analysis
    .add_step(
      PlaybookStep::new(2, PlaybookPhase::Recon, "Schema/Spec Discovery")
        .with_description("Find OpenAPI/Swagger specs or GraphQL schema")
        .with_command("rb web asset get {{ target }}/swagger.json")
        .with_manual("Check /api-docs, /graphql, /.well-known/")
        .with_success("API schema obtained")
        .parallel(1)
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1592.002", None),
    )
    // BOLA Testing
    .add_step(
      PlaybookStep::new(3, PlaybookPhase::InitialAccess, "BOLA/IDOR Testing")
        .with_description("Test for Broken Object Level Authorization")
        .with_manual("Modify object IDs to access other users' data")
        .with_success("BOLA vulnerability confirmed")
        .depends(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1190", None),
    )
    // Rate Limiting
    .add_step(
      PlaybookStep::new(4, PlaybookPhase::Execution, "Rate Limiting Test")
        .with_description("Test API rate limiting and abuse prevention")
        .with_command("rb web fuzz {{ target }} --rate 100")
        .with_success("Rate limiting assessed")
        .depends(1)
        .collects(EvidenceType::CommandOutput)
        .with_mitre("T1498", None),
    )
    // Mass Assignment
    .add_step(
      PlaybookStep::new(
        5,
        PlaybookPhase::PrivilegeEscalation,
        "Mass Assignment Test",
      )
      .with_description("Test for mass assignment vulnerabilities")
      .with_manual("Add extra fields like isAdmin, role to requests")
      .with_success("Mass assignment exploitation possible")
      .optional()
      .collects(EvidenceType::Vulnerability)
      .with_mitre("T1190", None),
    )
    .add_evidence(
      ExpectedEvidence::new("API vulnerability report")
        .at("Test results")
        .with_indicator("BOLA, injection, authorization bypass findings")
        .severity(FindingSeverity::High),
    )
    .add_failed_control(
      FailedControl::new(
        "API Authorization",
        "Missing or weak object-level authorization",
      )
      .with_fix("Implement proper authorization checks per object"),
    )
}

/// File Upload Exploitation
pub fn file_upload_exploitation() -> Playbook {
  Playbook::new("file-upload-exploitation", "File Upload Exploitation")
    .with_description("Test file upload functionality for bypass techniques leading to RCE")
    .with_objective("Achieve code execution through malicious file upload")
    .for_target(TargetType::WebApp)
    .for_os(TargetOS::Any)
    .with_risk(RiskLevel::High)
    .with_duration("30-60 minutes")
    .with_tag("web")
    .with_tag("upload")
    .with_tag("rce")
    .with_mitre("T1190")
    .add_precondition(PreCondition::new("File upload functionality identified"))
    .add_precondition(PreCondition::new("Authorization for exploitation testing"))
    // Upload Discovery
    .add_step(
      PlaybookStep::new(1, PlaybookPhase::Recon, "Upload Endpoint Discovery")
        .with_description("Identify file upload endpoints")
        .with_command("rb web crawl {{ target }} --forms")
        .with_success("Upload forms identified")
        .collects(EvidenceType::SystemInfo)
        .with_mitre("T1595.002", None),
    )
    // Extension Bypass
    .add_step(
      PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Extension Filter Bypass")
        .with_description("Test file extension validation bypass")
        .with_manual("Try: .php5, .phtml, .php.jpg, .php%00.jpg")
        .with_success("Extension filter bypassed")
        .depends(1)
        .parallel(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1190", None),
    )
    // Content-Type Bypass
    .add_step(
      PlaybookStep::new(3, PlaybookPhase::InitialAccess, "Content-Type Bypass")
        .with_description("Test MIME type validation bypass")
        .with_manual("Modify Content-Type header while keeping malicious content")
        .with_success("Content-Type filter bypassed")
        .depends(1)
        .parallel(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1190", None),
    )
    // Magic Bytes
    .add_step(
      PlaybookStep::new(4, PlaybookPhase::InitialAccess, "Magic Bytes Injection")
        .with_description("Prepend valid file headers to bypass content checking")
        .with_manual("Add GIF89a or PNG header before PHP code")
        .with_success("Magic byte bypass successful")
        .depends(1)
        .collects(EvidenceType::Vulnerability)
        .with_mitre("T1190", None),
    )
    // Web Shell Execution
    .add_step(
      PlaybookStep::new(5, PlaybookPhase::Execution, "Shell Execution")
        .with_description("Execute uploaded webshell")
        .with_command("rb exploit payload shell {{ shell_type }} {{ ip }} {{ port }}")
        .with_success("Command execution achieved")
        .when(StepCondition::OnSuccess(2))
        .collects(EvidenceType::CommandOutput)
        .with_mitre("T1059.004", None),
    )
    .add_evidence(
      ExpectedEvidence::new("Remote code execution proof")
        .at("Shell output")
        .with_indicator("Command execution on target server")
        .severity(FindingSeverity::Critical),
    )
    .add_failed_control(
      FailedControl::new(
        "File Upload Validation",
        "Insufficient file type validation",
      )
      .with_fix("Whitelist allowed extensions, validate content, store outside webroot"),
    )
}
