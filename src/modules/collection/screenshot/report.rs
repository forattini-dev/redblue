/// HTML Report Generator
///
/// Generates visual reports from screenshot captures
use super::{BatchResult, ScreenshotConfig, ScreenshotResult};
use std::fs;
use std::path::PathBuf;

/// Report generator
pub struct ReportGenerator {
    config: ScreenshotConfig,
}

impl ReportGenerator {
    pub fn new(config: ScreenshotConfig) -> Self {
        Self { config }
    }

    /// Generate HTML report from batch results
    pub fn generate(&self, results: &BatchResult) -> Result<PathBuf, String> {
        let report_path = self.config.output_dir.join("report.html");

        let html = self.build_html(results);

        fs::write(&report_path, &html).map_err(|e| format!("Failed to write report: {}", e))?;

        Ok(report_path)
    }

    /// Build HTML content
    fn build_html(&self, results: &BatchResult) -> String {
        let mut html = String::new();

        // HTML header
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>redblue Screenshot Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        .header .subtitle {
            opacity: 0.9;
        }
        .stats {
            display: flex;
            justify-content: center;
            gap: 2rem;
            padding: 1.5rem;
            background: #16213e;
        }
        .stat {
            text-align: center;
        }
        .stat .value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        .stat .label {
            font-size: 0.9rem;
            opacity: 0.7;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 1.5rem;
            padding: 2rem;
            max-width: 1800px;
            margin: 0 auto;
        }
        .card {
            background: #16213e;
            border-radius: 12px;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(102, 126, 234, 0.3);
        }
        .card-image {
            width: 100%;
            height: 200px;
            object-fit: cover;
            background: #0f0f1a;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
        }
        .card-image img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .card-content {
            padding: 1rem;
        }
        .card-url {
            font-size: 0.9rem;
            color: #667eea;
            word-break: break-all;
            margin-bottom: 0.5rem;
        }
        .card-title {
            font-size: 1rem;
            margin-bottom: 0.5rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .card-meta {
            font-size: 0.8rem;
            color: #888;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .card-meta span {
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }
        .status-success {
            color: #4ade80;
        }
        .status-error {
            color: #f87171;
        }
        .status-redirect {
            color: #facc15;
        }
        .technologies {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }
        .tech-badge {
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            background: #1f2937;
            border-radius: 4px;
            color: #9ca3af;
        }
        .filters {
            padding: 1rem 2rem;
            background: #16213e;
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 0.5rem 1rem;
            background: #1f2937;
            border: none;
            border-radius: 6px;
            color: #eee;
            cursor: pointer;
            transition: background 0.2s;
        }
        .filter-btn:hover, .filter-btn.active {
            background: #667eea;
        }
        .no-screenshot {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            padding: 2rem;
        }
        .no-screenshot svg {
            width: 48px;
            height: 48px;
            opacity: 0.3;
            margin-bottom: 0.5rem;
        }
        .footer {
            text-align: center;
            padding: 2rem;
            opacity: 0.6;
            font-size: 0.9rem;
        }
        @media (max-width: 768px) {
            .gallery {
                grid-template-columns: 1fr;
                padding: 1rem;
            }
            .stats {
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 redblue</h1>
        <p class="subtitle">Screenshot Capture Report</p>
    </div>
"#);

        // Statistics
        html.push_str(&format!(
            r#"
    <div class="stats">
        <div class="stat">
            <div class="value">{}</div>
            <div class="label">Total URLs</div>
        </div>
        <div class="stat">
            <div class="value status-success">{}</div>
            <div class="label">Successful</div>
        </div>
        <div class="stat">
            <div class="value status-error">{}</div>
            <div class="label">Failed</div>
        </div>
        <div class="stat">
            <div class="value">{:.1}s</div>
            <div class="label">Total Time</div>
        </div>
    </div>
"#,
            results.results.len(),
            results.successful,
            results.failed,
            results.total_time_ms as f64 / 1000.0
        ));

        // Filters
        html.push_str(
            r#"
    <div class="filters">
        <button class="filter-btn active" onclick="filterCards('all')">All</button>
        <button class="filter-btn" onclick="filterCards('success')">Success</button>
        <button class="filter-btn" onclick="filterCards('error')">Failed</button>
    </div>
"#,
        );

        // Gallery
        html.push_str(
            r#"
    <div class="gallery">
"#,
        );

        for result in &results.results {
            html.push_str(&self.build_card(result));
        }

        html.push_str(
            r#"
    </div>
"#,
        );

        // Footer
        html.push_str(&format!(
            r#"
    <div class="footer">
        Generated by redblue Screenshot Module<br>
        {} URLs processed in {:.1}s
    </div>
"#,
            results.results.len(),
            results.total_time_ms as f64 / 1000.0
        ));

        // JavaScript for filtering
        html.push_str(
            r#"
    <script>
        function filterCards(filter) {
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');

            document.querySelectorAll('.card').forEach(card => {
                if (filter === 'all') {
                    card.style.display = '';
                } else if (filter === 'success') {
                    card.style.display = card.dataset.success === 'true' ? '' : 'none';
                } else if (filter === 'error') {
                    card.style.display = card.dataset.success === 'false' ? '' : 'none';
                }
            });
        }
    </script>
</body>
</html>
"#,
        );

        html
    }

    /// Build card HTML for a single result
    fn build_card(&self, result: &ScreenshotResult) -> String {
        let success = result.success();
        let _status_class = if success {
            "status-success"
        } else {
            "status-error"
        };

        let status_code = result
            .status_code
            .map(|c| format!("{}", c))
            .unwrap_or_else(|| "N/A".to_string());

        let status_text = if let Some(code) = result.status_code {
            match code {
                200..=299 => "status-success",
                300..=399 => "status-redirect",
                _ => "status-error",
            }
        } else {
            "status-error"
        };

        let title = result.title.as_deref().unwrap_or("No title");
        let server = result.server.as_deref().unwrap_or("Unknown");

        // Image or placeholder
        let image_html = if let Some(ref thumb_path) = result.thumbnail_path {
            let filename = thumb_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("screenshot.jpg");
            format!(
                r#"<img src="{}" alt="Screenshot" loading="lazy">"#,
                filename
            )
        } else if let Some(ref screenshot_path) = result.screenshot_path {
            let filename = screenshot_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("screenshot.jpg");
            format!(
                r#"<img src="{}" alt="Screenshot" loading="lazy">"#,
                filename
            )
        } else {
            r#"<div class="no-screenshot">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                <span>No screenshot</span>
            </div>"#.to_string()
        };

        // Technologies badges
        let tech_html: String = result
            .technologies
            .iter()
            .map(|t| format!(r#"<span class="tech-badge">{}</span>"#, t))
            .collect::<Vec<_>>()
            .join("");

        // Error message if any
        let error_html = if let Some(ref error) = result.error {
            format!(
                r#"<div class="card-meta status-error" style="margin-top: 0.5rem">{}</div>"#,
                truncate(error, 50)
            )
        } else {
            String::new()
        };

        format!(
            r#"
        <div class="card" data-success="{}">
            <div class="card-image">
                {}
            </div>
            <div class="card-content">
                <div class="card-url">
                    <a href="{}" target="_blank" style="color: inherit; text-decoration: none;">{}</a>
                </div>
                <div class="card-title">{}</div>
                <div class="card-meta">
                    <span class="{}">HTTP {}</span>
                    <span>{}</span>
                    <span>{}ms</span>
                </div>
                <div class="technologies">{}</div>
                {}
            </div>
        </div>
"#,
            success,
            image_html,
            result.url,
            truncate(&result.url, 60),
            title,
            status_text,
            status_code,
            server,
            result.load_time_ms,
            tech_html,
            error_html
        )
    }

    /// Generate JSON report
    pub fn generate_json(&self, results: &BatchResult) -> Result<PathBuf, String> {
        let report_path = self.config.output_dir.join("report.json");

        let mut json = String::from("{\n");
        json.push_str(&format!("  \"total\": {},\n", results.results.len()));
        json.push_str(&format!("  \"successful\": {},\n", results.successful));
        json.push_str(&format!("  \"failed\": {},\n", results.failed));
        json.push_str(&format!(
            "  \"total_time_ms\": {},\n",
            results.total_time_ms
        ));
        json.push_str("  \"results\": [\n");

        for (i, result) in results.results.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!(
                "      \"url\": \"{}\",\n",
                escape_json(&result.url)
            ));
            json.push_str(&format!(
                "      \"title\": {},\n",
                result
                    .title
                    .as_ref()
                    .map(|t| format!("\"{}\"", escape_json(t)))
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"status_code\": {},\n",
                result
                    .status_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"load_time_ms\": {},\n",
                result.load_time_ms
            ));
            json.push_str(&format!("      \"success\": {},\n", result.success()));
            json.push_str(&format!(
                "      \"screenshot_path\": {},\n",
                result
                    .screenshot_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .map(|s| format!("\"{}\"", escape_json(s)))
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str(&format!(
                "      \"error\": {}\n",
                result
                    .error
                    .as_ref()
                    .map(|e| format!("\"{}\"", escape_json(e)))
                    .unwrap_or_else(|| "null".to_string())
            ));
            json.push_str("    }");

            if i < results.results.len() - 1 {
                json.push_str(",");
            }
            json.push_str("\n");
        }

        json.push_str("  ]\n");
        json.push_str("}\n");

        fs::write(&report_path, &json)
            .map_err(|e| format!("Failed to write JSON report: {}", e))?;

        Ok(report_path)
    }

    /// Generate CSV report
    pub fn generate_csv(&self, results: &BatchResult) -> Result<PathBuf, String> {
        let report_path = self.config.output_dir.join("report.csv");

        let mut csv =
            String::from("url,title,status_code,load_time_ms,success,screenshot_path,error\n");

        for result in &results.results {
            csv.push_str(&format!(
                "\"{}\",\"{}\",{},{},{},{},{}\n",
                escape_csv(&result.url),
                escape_csv(result.title.as_deref().unwrap_or("")),
                result
                    .status_code
                    .map(|c| c.to_string())
                    .unwrap_or_default(),
                result.load_time_ms,
                result.success(),
                result
                    .screenshot_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .map(|s| format!("\"{}\"", escape_csv(s)))
                    .unwrap_or_default(),
                result
                    .error
                    .as_ref()
                    .map(|e| format!("\"{}\"", escape_csv(e)))
                    .unwrap_or_default()
            ));
        }

        fs::write(&report_path, &csv).map_err(|e| format!("Failed to write CSV report: {}", e))?;

        Ok(report_path)
    }
}

/// Truncate string with ellipsis
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Escape JSON string
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Escape CSV field
fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"")
}
