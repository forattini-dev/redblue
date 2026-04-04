//! Report MCP Tools
//!
//! Pentest report generation, templates, and executive summary tools.
//! Uses the report module for real report generation from loot and findings.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::modules::common::Severity;
use crate::modules::report::pentest::PentestReport;
use crate::modules::report::Finding;
use crate::utils::json::JsonValue;

/// Register report tools with the server
pub fn register_report_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.report.generate",
            description: "Generate a pentest report from findings. Provide target and findings \
                         to produce a full report in markdown, HTML, or JSON format.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target of the pentest (hostname, IP, or description).",
                    required: true,
                },
                ToolField {
                    name: "title",
                    field_type: "string",
                    description: "Report title. Defaults to 'Penetration Test Report - <target>'.",
                    required: false,
                },
                ToolField {
                    name: "format",
                    field_type: "string",
                    description: "Output format: markdown, html, json (default: markdown).",
                    required: false,
                },
                ToolField {
                    name: "findings",
                    field_type: "array",
                    description: "Array of finding objects, each with: title (string), \
                                 severity (string: info/low/medium/high/critical), \
                                 description (string), evidence (string, optional), \
                                 remediation (string, optional).",
                    required: false,
                },
                ToolField {
                    name: "methodology",
                    field_type: "string",
                    description: "Methodology used (e.g., OWASP, PTES, custom).",
                    required: false,
                },
                ToolField {
                    name: "scope",
                    field_type: "array",
                    description: "Array of in-scope items (IPs, domains, URLs).",
                    required: false,
                },
                ToolField {
                    name: "from_storage",
                    field_type: "boolean",
                    description: "If true, load findings from RedDB storage for the target \
                                 instead of using provided findings.",
                    required: false,
                },
            ],
            handler: tool_report_generate,
        },
        ToolDefinition {
            name: "rb.report.template.list",
            description: "List available report templates with descriptions and supported formats.",
            fields: &[],
            handler: tool_report_template_list,
        },
        ToolDefinition {
            name: "rb.report.summary",
            description: "Generate an executive summary from findings. Produces a concise \
                         overview suitable for non-technical stakeholders.",
            fields: &[
                ToolField {
                    name: "target",
                    field_type: "string",
                    description: "Target of the assessment.",
                    required: true,
                },
                ToolField {
                    name: "findings",
                    field_type: "array",
                    description: "Array of finding objects, each with: title (string), \
                                 severity (string: info/low/medium/high/critical), \
                                 description (string, optional).",
                    required: false,
                },
                ToolField {
                    name: "from_storage",
                    field_type: "boolean",
                    description: "If true, load findings from RedDB storage for the target.",
                    required: false,
                },
            ],
            handler: tool_report_summary,
        },
    ]
}

/// Parse severity from string
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" | "crit" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse findings from a JSON array of finding objects
fn parse_findings(arr: &[JsonValue]) -> Vec<Finding> {
    arr.iter()
        .filter_map(|item| {
            let title = item.get("title").and_then(|v| v.as_str())?;
            let severity = item
                .get("severity")
                .and_then(|v| v.as_str())
                .map(parse_severity)
                .unwrap_or(Severity::Info);

            let mut finding = Finding::new(title, severity);

            if let Some(desc) = item.get("description").and_then(|v| v.as_str()) {
                finding = finding.with_description(desc);
            }
            if let Some(evidence) = item.get("evidence").and_then(|v| v.as_str()) {
                finding = finding.with_evidence(evidence);
            }
            if let Some(remediation) = item.get("remediation").and_then(|v| v.as_str()) {
                finding = finding.with_remediation(remediation);
            }
            if let Some(refs) = item.get("references").and_then(|v| v.as_array()) {
                for r in refs {
                    if let Some(s) = r.as_str() {
                        finding = finding.add_reference(s);
                    }
                }
            }
            if let Some(tags) = item.get("tags").and_then(|v| v.as_array()) {
                for t in tags {
                    if let Some(s) = t.as_str() {
                        finding = finding.add_tag(s);
                    }
                }
            }

            Some(finding)
        })
        .collect()
}

/// Build severity statistics as JSON
fn severity_stats(findings: &[Finding]) -> JsonValue {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;

    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    JsonValue::object(vec![
        ("critical".to_string(), JsonValue::Number(critical as f64)),
        ("high".to_string(), JsonValue::Number(high as f64)),
        ("medium".to_string(), JsonValue::Number(medium as f64)),
        ("low".to_string(), JsonValue::Number(low as f64)),
        ("info".to_string(), JsonValue::Number(info as f64)),
        (
            "total".to_string(),
            JsonValue::Number(findings.len() as f64),
        ),
    ])
}

fn tool_report_generate(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let format = args
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("markdown");

    let from_storage = args
        .get("from_storage")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Try loading from storage if requested
    if from_storage {
        match PentestReport::from_storage(target) {
            Ok(report) => {
                let output = match format {
                    "html" | "htm" => report.base.to_html(),
                    "json" => report.base.to_json(),
                    _ => report.to_markdown(),
                };

                let stats = severity_stats(&report.base.findings);

                return Ok(ToolResult::with_data(
                    output,
                    JsonValue::object(vec![
                        ("target".to_string(), JsonValue::String(target.to_string())),
                        ("format".to_string(), JsonValue::String(format.to_string())),
                        ("source".to_string(), JsonValue::String("storage".to_string())),
                        (
                            "findings_count".to_string(),
                            JsonValue::Number(report.base.findings.len() as f64),
                        ),
                        ("severity_stats".to_string(), stats),
                    ]),
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Failed to load from storage: {}. Try providing findings \
                     directly or run scans first with 'rb network ports scan {}'.",
                    e, target
                ));
            }
        }
    }

    // Build report from provided findings
    let title = args
        .get("title")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("Penetration Test Report - {}", target));

    let mut pentest_report = PentestReport::new(&title, target);

    // Set methodology
    if let Some(methodology) = args.get("methodology").and_then(|v| v.as_str()) {
        pentest_report = pentest_report.with_methodology(methodology);
    }

    // Set scope
    if let Some(scope_arr) = args.get("scope").and_then(|v| v.as_array()) {
        for item in scope_arr {
            if let Some(s) = item.as_str() {
                pentest_report = pentest_report.add_scope(s);
            }
        }
    }

    // Parse and add findings
    let findings = args
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| parse_findings(arr))
        .unwrap_or_default();

    for finding in &findings {
        pentest_report.base.add_finding(finding.clone());
    }

    // Generate executive summary based on findings
    let summary = build_executive_summary(target, &findings);
    pentest_report.base = pentest_report.base.with_summary(&summary);

    // Generate output in requested format
    let output = match format {
        "html" | "htm" => pentest_report.base.to_html(),
        "json" => pentest_report.base.to_json(),
        _ => pentest_report.to_markdown(),
    };

    let stats = severity_stats(&findings);

    Ok(ToolResult::with_data(
        output,
        JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            ("format".to_string(), JsonValue::String(format.to_string())),
            ("source".to_string(), JsonValue::String("provided".to_string())),
            (
                "findings_count".to_string(),
                JsonValue::Number(findings.len() as f64),
            ),
            ("severity_stats".to_string(), stats),
        ]),
    ))
}

fn tool_report_template_list(
    _server: &mut McpServer,
    _args: &JsonValue,
) -> Result<ToolResult, String> {
    let templates = vec![
        (
            "pentest-full",
            "Full penetration test report with executive summary, findings, \
             attack paths, timeline, and recommendations",
            &["markdown", "html", "json"][..],
        ),
        (
            "pentest-executive",
            "Executive summary only - high-level overview for management",
            &["markdown", "html"][..],
        ),
        (
            "vulnerability-assessment",
            "Vulnerability-focused report listing all discovered issues by severity",
            &["markdown", "html", "json"][..],
        ),
        (
            "network-audit",
            "Network infrastructure audit with host inventory, open ports, and services",
            &["markdown", "html", "json"][..],
        ),
        (
            "web-security",
            "Web application security assessment covering OWASP Top 10 categories",
            &["markdown", "html", "json"][..],
        ),
        (
            "compliance-check",
            "Compliance-oriented report mapping findings to security standards",
            &["markdown", "html"][..],
        ),
    ];

    let mut text = format!("Available report templates ({}):\n\n", templates.len());
    for (name, desc, formats) in &templates {
        text.push_str(&format!("  {} - {}\n", name, desc));
        text.push_str(&format!("    Formats: {}\n\n", formats.join(", ")));
    }
    text.push_str(
        "Use rb.report.generate with findings to create a report. \
         Templates guide the structure; all use the same underlying report engine.\n\
         CLI equivalent: rb report generate <target> --template <name> --format <fmt>",
    );

    let templates_json: Vec<JsonValue> = templates
        .iter()
        .map(|(name, desc, formats)| {
            let formats_json: Vec<JsonValue> = formats
                .iter()
                .map(|f| JsonValue::String(f.to_string()))
                .collect();
            JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(name.to_string())),
                (
                    "description".to_string(),
                    JsonValue::String(desc.to_string()),
                ),
                ("formats".to_string(), JsonValue::array(formats_json)),
            ])
        })
        .collect();

    Ok(ToolResult::with_data(
        text,
        JsonValue::object(vec![(
            "templates".to_string(),
            JsonValue::array(templates_json),
        )]),
    ))
}

fn tool_report_summary(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let from_storage = args
        .get("from_storage")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Collect findings from storage or provided data
    let findings: Vec<Finding> = if from_storage {
        match PentestReport::from_storage(target) {
            Ok(report) => report.base.findings,
            Err(_) => Vec::new(),
        }
    } else {
        args.get("findings")
            .and_then(|v| v.as_array())
            .map(|arr| parse_findings(arr))
            .unwrap_or_default()
    };

    let summary = build_executive_summary(target, &findings);
    let stats = severity_stats(&findings);

    // Build risk rating
    let risk_level = if findings.iter().any(|f| f.severity == Severity::Critical) {
        "CRITICAL"
    } else if findings.iter().any(|f| f.severity == Severity::High) {
        "HIGH"
    } else if findings.iter().any(|f| f.severity == Severity::Medium) {
        "MEDIUM"
    } else if findings.iter().any(|f| f.severity == Severity::Low) {
        "LOW"
    } else if findings.is_empty() {
        "NOT ASSESSED"
    } else {
        "INFORMATIONAL"
    };

    let mut text = format!("Executive Summary: {}\n", target);
    text.push_str(&format!("Overall Risk: {}\n\n", risk_level));
    text.push_str(&summary);

    Ok(ToolResult::with_data(
        text,
        JsonValue::object(vec![
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "risk_level".to_string(),
                JsonValue::String(risk_level.to_string()),
            ),
            (
                "summary".to_string(),
                JsonValue::String(summary),
            ),
            ("severity_stats".to_string(), stats),
        ]),
    ))
}

/// Build an executive summary from findings
fn build_executive_summary(target: &str, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return format!(
            "A security assessment was performed against {}. \
             No findings were provided for this report. Run security scans \
             (rb network ports scan, rb web asset security) to discover issues, \
             or add findings manually.",
            target
        );
    }

    let total = findings.len();
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let mut summary = format!(
        "A security assessment was performed against {}. \
         A total of {} findings were identified",
        target, total
    );

    let mut severity_parts = Vec::new();
    if critical > 0 {
        severity_parts.push(format!("{} critical", critical));
    }
    if high > 0 {
        severity_parts.push(format!("{} high", high));
    }
    if medium > 0 {
        severity_parts.push(format!("{} medium", medium));
    }
    if low > 0 {
        severity_parts.push(format!("{} low", low));
    }

    if !severity_parts.is_empty() {
        summary.push_str(&format!(": {}.", severity_parts.join(", ")));
    } else {
        summary.push('.');
    }

    if critical > 0 || high > 0 {
        summary.push_str(
            "\n\nImmediate attention is required to address the critical and high severity \
             findings. These issues pose significant risk and should be remediated as a priority.",
        );
    } else if medium > 0 {
        summary.push_str(
            "\n\nWhile no critical or high severity findings were identified, \
             the medium severity issues should be addressed in the near term \
             to maintain a strong security posture.",
        );
    } else {
        summary.push_str(
            "\n\nThe assessment identified only low severity or informational findings. \
             The overall security posture appears reasonable, though the identified items \
             should still be reviewed and addressed as part of ongoing security maintenance.",
        );
    }

    // List top findings
    let critical_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
        .collect();

    if !critical_findings.is_empty() {
        summary.push_str("\n\nKey findings requiring immediate action:\n");
        for (i, finding) in critical_findings.iter().take(5).enumerate() {
            summary.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                finding.severity.as_str().to_uppercase(),
                finding.title
            ));
        }
    }

    summary
}
