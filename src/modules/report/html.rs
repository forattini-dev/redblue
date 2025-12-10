//! HTML Export for reports
//!
//! Generates rich HTML reports with embedded CSS (single-file output).

use super::{Report, Severity};

pub struct HtmlExporter;

impl HtmlExporter {
    /// Export report to HTML string
    pub fn export(report: &Report) -> String {
        let mut html = String::with_capacity(32768);

        // Document header
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("<title>{} - redblue Report</title>\n", Self::escape_html(&report.title)));
        html.push_str("<style>\n");
        html.push_str(Self::css());
        html.push_str("\n</style>\n</head>\n<body>\n");

        // Header
        html.push_str("<header>\n");
        html.push_str(&format!("<h1>{}</h1>\n", Self::escape_html(&report.title)));
        html.push_str(&format!("<p class=\"meta\">Target: <strong>{}</strong> | Scan Date: {}</p>\n",
            Self::escape_html(&report.target), Self::escape_html(&report.scan_date)));
        html.push_str("</header>\n\n");

        // Executive Summary
        html.push_str("<section class=\"summary\">\n");
        html.push_str("<h2>Executive Summary</h2>\n");
        if !report.executive_summary.is_empty() {
            html.push_str(&format!("<p>{}</p>\n", Self::escape_html(&report.executive_summary)));
        }

        // Stats cards
        let counts = report.severity_counts();
        html.push_str("<div class=\"stats-grid\">\n");
        html.push_str(&format!("<div class=\"stat-card critical\"><span class=\"count\">{}</span><span class=\"label\">Critical</span></div>\n",
            counts.get(&Severity::Critical).unwrap_or(&0)));
        html.push_str(&format!("<div class=\"stat-card high\"><span class=\"count\">{}</span><span class=\"label\">High</span></div>\n",
            counts.get(&Severity::High).unwrap_or(&0)));
        html.push_str(&format!("<div class=\"stat-card medium\"><span class=\"count\">{}</span><span class=\"label\">Medium</span></div>\n",
            counts.get(&Severity::Medium).unwrap_or(&0)));
        html.push_str(&format!("<div class=\"stat-card low\"><span class=\"count\">{}</span><span class=\"label\">Low</span></div>\n",
            counts.get(&Severity::Low).unwrap_or(&0)));
        html.push_str(&format!("<div class=\"stat-card info\"><span class=\"count\">{}</span><span class=\"label\">Info</span></div>\n",
            counts.get(&Severity::Info).unwrap_or(&0)));
        html.push_str("</div>\n</section>\n\n");

        // Hosts section
        if !report.hosts.is_empty() {
            html.push_str("<section class=\"hosts\">\n");
            html.push_str("<h2>Discovered Hosts</h2>\n");
            html.push_str("<table>\n<thead>\n<tr><th>Hostname</th><th>IP</th><th>Open Ports</th><th>Technologies</th></tr>\n</thead>\n<tbody>\n");

            for host in &report.hosts {
                let ports_str = host.ports.iter()
                    .map(|p| format!("{}/{}", p.port, p.service))
                    .collect::<Vec<_>>()
                    .join(", ");

                html.push_str("<tr>");
                html.push_str(&format!("<td>{}</td>", Self::escape_html(&host.hostname)));
                html.push_str(&format!("<td>{}</td>", host.ip.as_deref().unwrap_or("-")));
                html.push_str(&format!("<td>{}</td>", Self::escape_html(&ports_str)));
                html.push_str(&format!("<td>{}</td>", Self::escape_html(&host.technologies.join(", "))));
                html.push_str("</tr>\n");
            }

            html.push_str("</tbody>\n</table>\n</section>\n\n");
        }

        // Findings section
        html.push_str("<section class=\"findings\">\n");
        html.push_str("<h2>Security Findings</h2>\n");

        // Sort findings by severity (critical first)
        let mut sorted_findings = report.findings.clone();
        sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        for finding in &sorted_findings {
            let severity_class = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };

            html.push_str(&format!("<div class=\"finding {}\">\n", severity_class));
            html.push_str(&format!("<h3><span class=\"badge {}\">{}</span> {}</h3>\n",
                severity_class, finding.severity.as_str(), Self::escape_html(&finding.title)));

            if !finding.description.is_empty() {
                html.push_str(&format!("<p class=\"description\">{}</p>\n", Self::escape_html(&finding.description)));
            }

            if let Some(ref evidence) = finding.evidence {
                html.push_str("<div class=\"evidence\">\n<h4>Evidence</h4>\n");
                html.push_str(&format!("<pre><code>{}</code></pre>\n</div>\n", Self::escape_html(evidence)));
            }

            if let Some(ref remediation) = finding.remediation {
                html.push_str("<div class=\"remediation\">\n<h4>Remediation</h4>\n");
                html.push_str(&format!("<p>{}</p>\n</div>\n", Self::escape_html(remediation)));
            }

            if !finding.references.is_empty() {
                html.push_str("<div class=\"references\">\n<h4>References</h4>\n<ul>\n");
                for reference in &finding.references {
                    html.push_str(&format!("<li><a href=\"{}\" target=\"_blank\">{}</a></li>\n",
                        Self::escape_html(reference), Self::escape_html(reference)));
                }
                html.push_str("</ul>\n</div>\n");
            }

            if !finding.tags.is_empty() {
                html.push_str("<div class=\"tags\">\n");
                for tag in &finding.tags {
                    html.push_str(&format!("<span class=\"tag\">{}</span>\n", Self::escape_html(tag)));
                }
                html.push_str("</div>\n");
            }

            html.push_str("</div>\n\n");
        }
        html.push_str("</section>\n\n");

        // Footer
        html.push_str("<footer>\n");
        html.push_str("<p>Generated by <strong>redblue</strong> - Security Assessment Toolkit</p>\n");
        html.push_str("</footer>\n\n");

        html.push_str("</body>\n</html>");
        html
    }

    /// Escape HTML special characters
    fn escape_html(s: &str) -> String {
        let mut escaped = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '&' => escaped.push_str("&amp;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#x27;"),
                _ => escaped.push(c),
            }
        }
        escaped
    }

    /// Embedded CSS
    fn css() -> &'static str {
        r#"
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --critical: #f85149;
  --high: #f0883e;
  --medium: #d29922;
  --low: #3fb950;
  --info: #58a6ff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 2rem;
  max-width: 1200px;
  margin: 0 auto;
}

header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 1rem;
  margin-bottom: 2rem;
}

h1 { font-size: 2rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.5rem; margin-bottom: 1rem; color: var(--text); }
h3 { font-size: 1.1rem; margin-bottom: 0.5rem; }
h4 { font-size: 0.9rem; margin-bottom: 0.5rem; color: var(--text-muted); }

.meta { color: var(--text-muted); }

section { margin-bottom: 2rem; }

.stats-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1rem;
  margin-top: 1rem;
}

.stat-card {
  background: var(--surface);
  border-radius: 8px;
  padding: 1rem;
  text-align: center;
  border: 1px solid var(--border);
}

.stat-card .count { display: block; font-size: 2rem; font-weight: bold; }
.stat-card .label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; }

.stat-card.critical { border-left: 4px solid var(--critical); }
.stat-card.critical .count { color: var(--critical); }
.stat-card.high { border-left: 4px solid var(--high); }
.stat-card.high .count { color: var(--high); }
.stat-card.medium { border-left: 4px solid var(--medium); }
.stat-card.medium .count { color: var(--medium); }
.stat-card.low { border-left: 4px solid var(--low); }
.stat-card.low .count { color: var(--low); }
.stat-card.info { border-left: 4px solid var(--info); }
.stat-card.info .count { color: var(--info); }

table {
  width: 100%;
  border-collapse: collapse;
  background: var(--surface);
  border-radius: 8px;
  overflow: hidden;
}

th, td {
  padding: 0.75rem 1rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

th { background: var(--bg); font-weight: 600; }
tr:last-child td { border-bottom: none; }

.finding {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.finding.critical { border-left: 4px solid var(--critical); }
.finding.high { border-left: 4px solid var(--high); }
.finding.medium { border-left: 4px solid var(--medium); }
.finding.low { border-left: 4px solid var(--low); }
.finding.info { border-left: 4px solid var(--info); }

.badge {
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  margin-right: 0.5rem;
}

.badge.critical { background: var(--critical); color: #fff; }
.badge.high { background: var(--high); color: #000; }
.badge.medium { background: var(--medium); color: #000; }
.badge.low { background: var(--low); color: #000; }
.badge.info { background: var(--info); color: #000; }

.description { margin-bottom: 1rem; }

.evidence, .remediation, .references {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
}

pre {
  background: var(--bg);
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
}

code { font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.9rem; }

.tags { margin-top: 1rem; }
.tag {
  display: inline-block;
  padding: 0.2rem 0.5rem;
  background: var(--border);
  border-radius: 4px;
  font-size: 0.75rem;
  margin-right: 0.5rem;
}

ul { list-style: none; }
li { margin-bottom: 0.25rem; }
a { color: var(--info); text-decoration: none; }
a:hover { text-decoration: underline; }

footer {
  margin-top: 3rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  text-align: center;
  color: var(--text-muted);
  font-size: 0.875rem;
}

@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  body { padding: 1rem; }
}
"#
    }
}
