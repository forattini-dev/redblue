/// Behavioral Pattern Analysis for Service Fingerprinting
///
/// Different implementations of the same protocol exhibit unique behavioral patterns:
///
/// - Error message formatting and content
/// - Response to malformed requests
/// - Default configuration values
/// - Protocol compliance vs. implementation quirks
/// - Edge case handling
/// - Timeout behavior under load
///
/// By analyzing these subtle behavioral differences, we can fingerprint exact
/// service implementations and detect security misconfigurations.
use std::collections::HashMap;

/// Behavioral fingerprint result
#[derive(Debug, Clone)]
pub struct BehaviorFingerprint {
    pub service: String,
    pub implementation: Option<String>,
    pub patterns: Vec<BehaviorPattern>,
    pub quirks: Vec<String>,
    pub security_indicators: Vec<SecurityIndicator>,
}

/// Specific behavior pattern observed
#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub category: PatternCategory,
    pub observation: String,
    pub significance: Significance,
}

/// Category of behavioral pattern
#[derive(Debug, Clone, PartialEq)]
pub enum PatternCategory {
    ErrorHandling,
    ProtocolCompliance,
    DefaultConfig,
    TimingBehavior,
    ResourceLimits,
    AuthenticationFlow,
    EncodingQuirks,
}

/// Significance level of pattern
#[derive(Debug, Clone, PartialEq)]
pub enum Significance {
    High,   // Strong fingerprint indicator
    Medium, // Moderate confidence
    Low,    // Weak indicator
}

/// Security-relevant indicators
#[derive(Debug, Clone)]
pub struct SecurityIndicator {
    pub indicator_type: IndicatorType,
    pub description: String,
    pub severity: Severity,
}

/// Type of security indicator
#[derive(Debug, Clone, PartialEq)]
pub enum IndicatorType {
    DefaultCredentials,
    NoAuthentication,
    WeakEncryption,
    InformationLeak,
    OutdatedVersion,
    MisconfiguredSecurity,
    DebugModeEnabled,
}

/// Severity level
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Analyze SSH error message patterns
///
/// Different SSH implementations have distinct error formats:
///
/// OpenSSH:
/// - "Permission denied (publickey,password)"
/// - "Too many authentication failures"
/// - "Connection closed by remote host"
///
/// Dropbear:
/// - "Login attempt for nonexistent user"
/// - "Bad password attempt"
///
/// Commercial SSH:
/// - More verbose, corporate-style messages
pub fn analyze_ssh_errors(error_msg: &str) -> BehaviorFingerprint {
    let mut fingerprint = BehaviorFingerprint {
        service: "SSH".to_string(),
        implementation: None,
        patterns: Vec::new(),
        quirks: Vec::new(),
        security_indicators: Vec::new(),
    };

    let lower = error_msg.to_lowercase();

    // OpenSSH patterns
    if lower.contains("permission denied (publickey") {
        fingerprint.implementation = Some("OpenSSH".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "Standard OpenSSH authentication error format".to_string(),
            significance: Significance::High,
        });

        if lower.contains("password") {
            fingerprint.security_indicators.push(SecurityIndicator {
                indicator_type: IndicatorType::InformationLeak,
                description: "Server reveals password authentication is enabled".to_string(),
                severity: Severity::Low,
            });
        }
    }

    // Dropbear patterns
    if lower.contains("nonexistent user") || lower.contains("bad password attempt") {
        fingerprint.implementation = Some("Dropbear".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "Dropbear-specific error messages".to_string(),
            significance: Significance::High,
        });
    }

    // Too many authentication failures
    if lower.contains("too many authentication failures") {
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ResourceLimits,
            observation: "MaxAuthTries limit reached".to_string(),
            significance: Significance::Medium,
        });
    }

    fingerprint
}

/// Analyze FTP error patterns
///
/// ProFTPD: Detailed, formatted error messages
/// vsftpd: Terse, minimal messages
/// IIS FTP: Windows-style verbose errors
pub fn analyze_ftp_errors(error_code: u16, error_msg: &str) -> BehaviorFingerprint {
    let mut fingerprint = BehaviorFingerprint {
        service: "FTP".to_string(),
        implementation: None,
        patterns: Vec::new(),
        quirks: Vec::new(),
        security_indicators: Vec::new(),
    };

    let lower = error_msg.to_lowercase();

    // ProFTPD patterns
    if lower.contains("proftpd") || error_msg.contains("530-") {
        fingerprint.implementation = Some("ProFTPD".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "Multi-line error responses (530-)".to_string(),
            significance: Significance::High,
        });
    }

    // vsftpd patterns (very terse)
    if error_msg.len() < 30 && error_code == 530 {
        fingerprint.implementation = Some("vsftpd".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "Minimal error messages".to_string(),
            significance: Significance::Medium,
        });
    }

    // IIS FTP patterns
    if lower.contains("microsoft") || lower.contains("win32") {
        fingerprint.implementation = Some("Microsoft IIS".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "Windows-style error messages".to_string(),
            significance: Significance::High,
        });
    }

    // Anonymous FTP enabled
    if error_code == 230 && lower.contains("anonymous") {
        fingerprint.security_indicators.push(SecurityIndicator {
            indicator_type: IndicatorType::NoAuthentication,
            description: "Anonymous FTP access enabled".to_string(),
            severity: Severity::Medium,
        });
    }

    fingerprint
}

/// Analyze HTTP error page patterns
///
/// Apache: Detailed error pages with server signature
/// nginx: Minimal error pages
/// IIS: Windows-style error pages with detailed stack traces (if debug enabled)
pub fn analyze_http_error(
    status_code: u16,
    body: &str,
    _headers: &HashMap<String, String>,
) -> BehaviorFingerprint {
    let mut fingerprint = BehaviorFingerprint {
        service: "HTTP".to_string(),
        implementation: None,
        patterns: Vec::new(),
        quirks: Vec::new(),
        security_indicators: Vec::new(),
    };

    let lower = body.to_lowercase();

    // Apache patterns
    if lower.contains("apache") || lower.contains("the requested url") {
        fingerprint.implementation = Some("Apache".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "Apache-style error page format".to_string(),
            significance: Significance::High,
        });

        if lower.contains("apache/2") {
            fingerprint.security_indicators.push(SecurityIndicator {
                indicator_type: IndicatorType::InformationLeak,
                description: "Server version disclosed in error page".to_string(),
                severity: Severity::Low,
            });
        }
    }

    // nginx patterns
    if lower.contains("<center>nginx</center>") {
        fingerprint.implementation = Some("nginx".to_string());
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::ErrorHandling,
            observation: "nginx minimal error page".to_string(),
            significance: Significance::High,
        });
    }

    // IIS patterns
    if lower.contains("internet information services") || lower.contains("iis") {
        fingerprint.implementation = Some("Microsoft IIS".to_string());

        // Debug mode detection
        if lower.contains("stack trace:") || lower.contains("system.web") {
            fingerprint.security_indicators.push(SecurityIndicator {
                indicator_type: IndicatorType::DebugModeEnabled,
                description: "ASP.NET debug mode enabled - stack traces visible".to_string(),
                severity: Severity::High,
            });
        }
    }

    // Generic patterns
    if status_code == 403 && lower.contains("directory listing denied") {
        fingerprint.patterns.push(BehaviorPattern {
            category: PatternCategory::DefaultConfig,
            observation: "Directory listing disabled (good security practice)".to_string(),
            significance: Significance::Low,
        });
    }

    // Check for overly verbose errors
    if body.len() > 5000 && status_code >= 500 {
        fingerprint.security_indicators.push(SecurityIndicator {
            indicator_type: IndicatorType::InformationLeak,
            description: "Verbose error messages may leak internal paths/config".to_string(),
            severity: Severity::Medium,
        });
    }

    fingerprint
}

/// Analyze database error patterns
///
/// MySQL: Error codes like 1045, 2003 with specific messages
/// PostgreSQL: SQLSTATE codes like 28P01, 28000
/// MSSQL: Windows error style with error numbers
pub fn analyze_database_error(error_msg: &str, db_type: &str) -> BehaviorFingerprint {
    let mut fingerprint = BehaviorFingerprint {
        service: format!("Database ({})", db_type),
        implementation: Some(db_type.to_string()),
        patterns: Vec::new(),
        quirks: Vec::new(),
        security_indicators: Vec::new(),
    };

    let lower = error_msg.to_lowercase();

    match db_type {
        "MySQL" => {
            // MySQL error code patterns
            if lower.contains("error 1045") {
                fingerprint.patterns.push(BehaviorPattern {
                    category: PatternCategory::AuthenticationFlow,
                    observation: "MySQL error 1045 - Access denied".to_string(),
                    significance: Significance::High,
                });
            }

            if lower.contains("error 2003") {
                fingerprint.patterns.push(BehaviorPattern {
                    category: PatternCategory::ErrorHandling,
                    observation: "MySQL error 2003 - Connection refused".to_string(),
                    significance: Significance::High,
                });
            }

            // Version leak
            if error_msg.contains("5.") || error_msg.contains("8.") {
                fingerprint.security_indicators.push(SecurityIndicator {
                    indicator_type: IndicatorType::InformationLeak,
                    description: "MySQL version disclosed in error message".to_string(),
                    severity: Severity::Low,
                });
            }
        }

        "PostgreSQL" => {
            // SQLSTATE pattern
            if error_msg.contains("SQLSTATE") {
                fingerprint.patterns.push(BehaviorPattern {
                    category: PatternCategory::ErrorHandling,
                    observation: "PostgreSQL SQLSTATE error format".to_string(),
                    significance: Significance::High,
                });
            }

            // Common PostgreSQL errors
            if lower.contains("28p01") || lower.contains("invalid password") {
                fingerprint.patterns.push(BehaviorPattern {
                    category: PatternCategory::AuthenticationFlow,
                    observation: "PostgreSQL authentication failed".to_string(),
                    significance: Significance::Medium,
                });
            }
        }

        "MSSQL" => {
            // MSSQL error number pattern
            if error_msg.contains("Msg ") || error_msg.contains("Error:") {
                fingerprint.patterns.push(BehaviorPattern {
                    category: PatternCategory::ErrorHandling,
                    observation: "MSSQL-style error message format".to_string(),
                    significance: Significance::High,
                });
            }

            // SQL Server version in error
            if lower.contains("sql server") {
                fingerprint.security_indicators.push(SecurityIndicator {
                    indicator_type: IndicatorType::InformationLeak,
                    description: "SQL Server version may be disclosed".to_string(),
                    severity: Severity::Low,
                });
            }
        }

        _ => {}
    }

    fingerprint
}

/// Analyze protocol quirks and non-standard behaviors
///
/// These are implementation-specific deviations from protocol specifications
/// that can be used for fingerprinting.
pub fn detect_protocol_quirks(service: &str, observations: &[String]) -> Vec<String> {
    let mut quirks = Vec::new();

    for obs in observations {
        let lower = obs.to_lowercase();

        // HTTP quirks
        if service == "HTTP" {
            if lower.contains("content-length") && lower.contains("transfer-encoding") {
                quirks.push(
                    "Both Content-Length and Transfer-Encoding present (potential desync)"
                        .to_string(),
                );
            }

            if lower.contains("server: ") && obs.len() > 100 {
                quirks.push("Unusually verbose Server header".to_string());
            }
        }

        // SSH quirks
        if service == "SSH" && lower.contains("ssh-1.") {
            quirks.push("SSH protocol version 1 (DEPRECATED and insecure)".to_string());
        }

        // TLS quirks
        if service == "TLS" && (lower.contains("sslv3") || lower.contains("sslv2")) {
            quirks.push("Obsolete SSL version supported (security risk)".to_string());
        }
    }

    quirks
}

/// Analyze default configuration indicators
///
/// Detect if a service is running with default/insecure configuration
pub fn detect_default_config(
    service: &str,
    config_indicators: &HashMap<String, String>,
) -> Vec<SecurityIndicator> {
    let mut indicators = Vec::new();

    match service {
        "MongoDB" => {
            if config_indicators
                .get("auth")
                .is_some_and(|v| v == "disabled")
            {
                indicators.push(SecurityIndicator {
                    indicator_type: IndicatorType::NoAuthentication,
                    description: "MongoDB running without authentication".to_string(),
                    severity: Severity::Critical,
                });
            }
        }

        "Redis" => {
            if config_indicators
                .get("requirepass")
                .is_none_or(|v| v.is_empty())
            {
                indicators.push(SecurityIndicator {
                    indicator_type: IndicatorType::NoAuthentication,
                    description: "Redis has no password configured".to_string(),
                    severity: Severity::Critical,
                });
            }
        }

        "Elasticsearch" => {
            if config_indicators
                .get("xpack.security.enabled")
                .is_none_or(|v| v == "false")
            {
                indicators.push(SecurityIndicator {
                    indicator_type: IndicatorType::NoAuthentication,
                    description: "Elasticsearch X-Pack security not enabled".to_string(),
                    severity: Severity::Critical,
                });
            }
        }

        "Tomcat" => {
            if config_indicators
                .get("user")
                .is_some_and(|v| v == "tomcat" || v == "admin")
            {
                indicators.push(SecurityIndicator {
                    indicator_type: IndicatorType::DefaultCredentials,
                    description: "Default Tomcat credentials detected".to_string(),
                    severity: Severity::High,
                });
            }
        }

        _ => {}
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_ssh_errors() {
        let error = "Permission denied (publickey,password).";
        let fingerprint = analyze_ssh_errors(error);

        assert_eq!(fingerprint.implementation, Some("OpenSSH".to_string()));
        assert!(!fingerprint.patterns.is_empty());
    }

    #[test]
    fn test_analyze_ftp_errors() {
        let fingerprint = analyze_ftp_errors(530, "Login incorrect.");
        assert_eq!(fingerprint.service, "FTP");
    }

    #[test]
    fn test_detect_protocol_quirks_ssh() {
        let obs = vec!["SSH-1.99-OldSSH".to_string()];
        let quirks = detect_protocol_quirks("SSH", &obs);
        assert!(!quirks.is_empty());
    }

    #[test]
    fn test_detect_default_config_mongodb() {
        let mut config = HashMap::new();
        config.insert("auth".to_string(), "disabled".to_string());

        let indicators = detect_default_config("MongoDB", &config);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].severity, Severity::Critical);
    }

    #[test]
    fn test_security_indicator_types() {
        let indicator = SecurityIndicator {
            indicator_type: IndicatorType::DefaultCredentials,
            description: "Test".to_string(),
            severity: Severity::High,
        };

        assert_eq!(indicator.indicator_type, IndicatorType::DefaultCredentials);
        assert_eq!(indicator.severity, Severity::High);
    }
}
