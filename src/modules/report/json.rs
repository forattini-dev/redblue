//! JSON Export for reports
//!
//! Generates structured JSON output for automation and integration.

use super::{Finding, HostInfo, PortInfo, Report, Severity};

pub struct JsonExporter;

impl JsonExporter {
    /// Export report to JSON string
    pub fn export(report: &Report) -> String {
        let mut json = String::with_capacity(8192);
        json.push_str("{\n");

        // Metadata
        json.push_str(&format!(
            "  \"title\": {},\n",
            Self::escape_string(&report.title)
        ));
        json.push_str(&format!(
            "  \"target\": {},\n",
            Self::escape_string(&report.target)
        ));
        json.push_str(&format!(
            "  \"scan_date\": {},\n",
            Self::escape_string(&report.scan_date)
        ));
        json.push_str(&format!(
            "  \"executive_summary\": {},\n",
            Self::escape_string(&report.executive_summary)
        ));

        // Summary stats
        let counts = report.severity_counts();
        json.push_str("  \"summary\": {\n");
        json.push_str(&format!(
            "    \"total_findings\": {},\n",
            report.findings.len()
        ));
        json.push_str(&format!(
            "    \"critical\": {},\n",
            counts.get(&Severity::Critical).unwrap_or(&0)
        ));
        json.push_str(&format!(
            "    \"high\": {},\n",
            counts.get(&Severity::High).unwrap_or(&0)
        ));
        json.push_str(&format!(
            "    \"medium\": {},\n",
            counts.get(&Severity::Medium).unwrap_or(&0)
        ));
        json.push_str(&format!(
            "    \"low\": {},\n",
            counts.get(&Severity::Low).unwrap_or(&0)
        ));
        json.push_str(&format!(
            "    \"info\": {},\n",
            counts.get(&Severity::Info).unwrap_or(&0)
        ));
        json.push_str(&format!("    \"total_hosts\": {}\n", report.hosts.len()));
        json.push_str("  },\n");

        // Hosts
        json.push_str("  \"hosts\": [\n");
        for (i, host) in report.hosts.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!(
                "      \"hostname\": {},\n",
                Self::escape_string(&host.hostname)
            ));
            if let Some(ref ip) = host.ip {
                json.push_str(&format!("      \"ip\": {},\n", Self::escape_string(ip)));
            } else {
                json.push_str("      \"ip\": null,\n");
            }

            // Ports
            json.push_str("      \"ports\": [\n");
            for (j, port) in host.ports.iter().enumerate() {
                json.push_str("        {\n");
                json.push_str(&format!("          \"port\": {},\n", port.port));
                json.push_str(&format!(
                    "          \"state\": {},\n",
                    Self::escape_string(&port.state)
                ));
                json.push_str(&format!(
                    "          \"service\": {},\n",
                    Self::escape_string(&port.service)
                ));
                if let Some(ref ver) = port.version {
                    json.push_str(&format!(
                        "          \"version\": {}\n",
                        Self::escape_string(ver)
                    ));
                } else {
                    json.push_str("          \"version\": null\n");
                }
                json.push_str("        }");
                if j < host.ports.len() - 1 {
                    json.push(',');
                }
                json.push('\n');
            }
            json.push_str("      ],\n");

            // Technologies
            json.push_str("      \"technologies\": [");
            for (j, tech) in host.technologies.iter().enumerate() {
                json.push_str(&Self::escape_string(tech));
                if j < host.technologies.len() - 1 {
                    json.push_str(", ");
                }
            }
            json.push_str("]\n");

            json.push_str("    }");
            if i < report.hosts.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str("  ],\n");

        // Findings
        json.push_str("  \"findings\": [\n");
        for (i, finding) in report.findings.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!(
                "      \"title\": {},\n",
                Self::escape_string(&finding.title)
            ));
            json.push_str(&format!(
                "      \"severity\": {},\n",
                Self::escape_string(finding.severity.as_str())
            ));
            json.push_str(&format!(
                "      \"description\": {},\n",
                Self::escape_string(&finding.description)
            ));

            if let Some(ref evidence) = finding.evidence {
                json.push_str(&format!(
                    "      \"evidence\": {},\n",
                    Self::escape_string(evidence)
                ));
            } else {
                json.push_str("      \"evidence\": null,\n");
            }

            if let Some(ref remediation) = finding.remediation {
                json.push_str(&format!(
                    "      \"remediation\": {},\n",
                    Self::escape_string(remediation)
                ));
            } else {
                json.push_str("      \"remediation\": null,\n");
            }

            // References
            json.push_str("      \"references\": [");
            for (j, reference) in finding.references.iter().enumerate() {
                json.push_str(&Self::escape_string(reference));
                if j < finding.references.len() - 1 {
                    json.push_str(", ");
                }
            }
            json.push_str("],\n");

            // Tags
            json.push_str("      \"tags\": [");
            for (j, tag) in finding.tags.iter().enumerate() {
                json.push_str(&Self::escape_string(tag));
                if j < finding.tags.len() - 1 {
                    json.push_str(", ");
                }
            }
            json.push_str("]\n");

            json.push_str("    }");
            if i < report.findings.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str("  ],\n");

        // Raw data
        json.push_str("  \"raw_data\": {\n");
        let raw_entries: Vec<_> = report.raw_data.iter().collect();
        for (i, (key, value)) in raw_entries.iter().enumerate() {
            json.push_str(&format!(
                "    {}: {}",
                Self::escape_string(key),
                Self::escape_string(value)
            ));
            if i < raw_entries.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str("  }\n");

        json.push('}');
        json
    }

    /// Escape string for JSON
    fn escape_string(s: &str) -> String {
        let mut escaped = String::with_capacity(s.len() + 2);
        escaped.push('"');
        for c in s.chars() {
            match c {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c if c.is_control() => {
                    escaped.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => escaped.push(c),
            }
        }
        escaped.push('"');
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_export() {
        let mut report = Report::new("Test Report", "example.com");
        report.add_finding(
            Finding::new("Test Finding", Severity::High).with_description("This is a test"),
        );

        let json = JsonExporter::export(&report);
        assert!(json.contains("\"title\": \"Test Report\""));
        assert!(json.contains("\"severity\": \"High\""));
    }

    #[test]
    fn test_escape_string() {
        assert_eq!(JsonExporter::escape_string("test"), "\"test\"");
        assert_eq!(JsonExporter::escape_string("te\"st"), "\"te\\\"st\"");
        assert_eq!(JsonExporter::escape_string("te\nst"), "\"te\\nst\"");
    }
}
