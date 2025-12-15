/// MongoDB Information Script
///
/// Detects MongoDB servers and identifies security issues
/// including unauthenticated access.
use crate::scripts::types::*;
use crate::scripts::Script;

/// MongoDB Information Script
pub struct MongodbInfoScript {
    meta: ScriptMetadata,
}

impl MongodbInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "mongodb-info".to_string(),
                name: "MongoDB Server Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description:
                    "Detects MongoDB servers and identifies version and security configuration"
                        .to_string(),
                categories: vec![
                    ScriptCategory::Banner,
                    ScriptCategory::Version,
                    ScriptCategory::Vuln,
                    ScriptCategory::Safe,
                ],
                protocols: vec!["mongodb".to_string()],
                ports: vec![27017, 27018, 27019, 28017],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec!["https://docs.mongodb.com/manual/security/".to_string()],
            },
        }
    }
}

impl Default for MongodbInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for MongodbInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let banner = ctx.get_data("banner").unwrap_or("");
        let server_status = ctx.get_data("mongodb_status").unwrap_or("");

        if banner.is_empty() && server_status.is_empty() {
            result.add_output("No MongoDB data available in context");
            return Ok(result);
        }

        result.success = true;

        let combined = format!("{} {}", banner, server_status);
        let combined_lower = combined.to_lowercase();

        // Detect MongoDB
        if combined_lower.contains("mongodb")
            || combined_lower.contains("ismaster")
            || combined_lower.contains("mongod")
        {
            result.add_finding(
                Finding::new(FindingType::Discovery, "MongoDB Server Detected")
                    .with_evidence(&combined)
                    .with_severity(FindingSeverity::Info),
            );
            result.extract("service", "mongodb");
        }

        // Parse version
        if let Some(version) = self.extract_version(&combined) {
            result.extract("mongodb_version", &version);
            result.add_finding(
                Finding::new(FindingType::Version, &format!("MongoDB {}", version))
                    .with_description(&format!("MongoDB Server Version: {}", version))
                    .with_severity(FindingSeverity::Info),
            );

            self.check_vulnerabilities(&version, &mut result);
        }

        // Check for unauthenticated access
        if (combined_lower.contains("ismaster") || combined_lower.contains("ok"))
            && !combined_lower.contains("authentication")
            && !combined_lower.contains("unauthorized")
        {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "MongoDB Unauthenticated Access")
                    .with_description("MongoDB appears to allow unauthenticated access")
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Enable MongoDB authentication and create admin users"),
            );
        }

        // Check for HTTP interface (deprecated and insecure)
        if ctx.port == 28017 || combined_lower.contains("http interface") {
            result.add_finding(
                Finding::new(
                    FindingType::Misconfiguration,
                    "MongoDB HTTP Interface Enabled",
                )
                .with_description("MongoDB HTTP interface is enabled (deprecated and insecure)")
                .with_severity(FindingSeverity::High)
                .with_remediation("Disable HTTP interface with net.http.enabled: false"),
            );
        }

        // Check for exposed databases
        if combined_lower.contains("admin")
            || combined_lower.contains("local")
            || combined_lower.contains("config")
        {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "MongoDB System Databases Accessible")
                    .with_description("MongoDB system databases may be accessible")
                    .with_severity(FindingSeverity::Medium),
            );
        }

        result.add_output(&format!(
            "MongoDB analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

impl MongodbInfoScript {
    fn extract_version(&self, data: &str) -> Option<String> {
        // Look for version patterns
        for line in data.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.contains("version") {
                // Try to extract version after colon or quotes
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        let version = &line[start + 1..start + 1 + end];
                        if version
                            .chars()
                            .next()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false)
                        {
                            return Some(version.to_string());
                        }
                    }
                }
                if let Some(colon) = line.find(':') {
                    let after = line[colon + 1..].trim().trim_matches('"');
                    if after
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                    {
                        return Some(after.split_whitespace().next().unwrap_or(after).to_string());
                    }
                }
            }
        }
        None
    }

    fn check_vulnerabilities(&self, version: &str, result: &mut ScriptResult) {
        // CVE-2020-7921 - Info disclosure
        if self.version_in_range(version, "4.0.0", "4.0.19")
            || self.version_in_range(version, "4.2.0", "4.2.8")
        {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "MongoDB Information Disclosure")
                    .with_cve("CVE-2020-7921")
                    .with_description("MongoDB has an information disclosure vulnerability")
                    .with_severity(FindingSeverity::Medium)
                    .with_remediation("Upgrade to MongoDB 4.0.19+, 4.2.8+, or later"),
            );
        }

        // Very old MongoDB
        if self.version_lt(version, "4.0.0") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "End-of-Life MongoDB Version")
                    .with_description("MongoDB 3.x is end-of-life and no longer supported")
                    .with_severity(FindingSeverity::High)
                    .with_remediation("Upgrade to MongoDB 4.4+ or later"),
            );
        }

        // Check for 4.4+ (current supported)
        if self.version_lt(version, "4.4.0") && !self.version_lt(version, "4.0.0") {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "MongoDB Nearing End-of-Life")
                    .with_description("MongoDB 4.0 and 4.2 are nearing end-of-life")
                    .with_severity(FindingSeverity::Low)
                    .with_remediation("Plan upgrade to MongoDB 5.0+ or later"),
            );
        }
    }

    fn version_lt(&self, version: &str, target: &str) -> bool {
        let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
        let v1 = parse(version);
        let v2 = parse(target);
        for (a, b) in v1.iter().zip(v2.iter()) {
            if a < b {
                return true;
            }
            if a > b {
                return false;
            }
        }
        v1.len() < v2.len()
    }

    fn version_in_range(&self, version: &str, min: &str, max: &str) -> bool {
        !self.version_lt(version, min) && self.version_lt(version, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mongodb_script() {
        let script = MongodbInfoScript::new();
        assert_eq!(script.id(), "mongodb-info");
    }

    #[test]
    fn test_mongodb_detection() {
        let script = MongodbInfoScript::new();
        let mut ctx = ScriptContext::new("localhost", 27017);
        ctx.set_data("banner", r#"{"ismaster": true, "version": "4.4.6"}"#);

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
    }
}
