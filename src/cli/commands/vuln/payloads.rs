        if summary.exploitable_count > 0 {
            Output::warning(&format!("{} vulnerabilities have public exploits", summary.exploitable_count));
        }

        println!();
    }

    /// Output report as Markdown
    fn output_report_markdown(
        &self,
        url: &str,
        techs: &[DetectedTech],
        report: &CorrelationReport,
    ) {
        let summary = &report.summary;

        println!("# Vulnerability Report");
        println!();
        println!("**Target:** {}", url);
        println!("**Generated:** {}", chrono_now());
        println!();

        println!("## Executive Summary");
        println!();
        println!("| Metric | Count |");
        println!("|--------|-------|");
        println!("| Technologies Detected | {} |", techs.len());
        println!("| Total Vulnerabilities | {} |", summary.total_vulns);
        println!("| Critical | {} |", summary.critical_count);
        println!("| High | {} |", summary.high_count);
        println!("| Medium | {} |", summary.medium_count);
        println!("| CISA KEV | {} |", summary.kev_count);
        println!("| Public Exploits | {} |", summary.exploitable_count);
        println!();

        println!("## Detected Technologies");
        println!();
        for tech in techs {
            let version = tech.version.as_deref().unwrap_or("unknown");
            println!("- **{}** {}", tech.name, version);
        }
        println!();

        println!("## Top Risks");
        println!();
        let top = report.top_risks(10);
        for vuln in top {
            let kev_badge = if vuln.cisa_kev { " 🔴 **KEV**" } else { "" };
            let exp_badge = if vuln.has_exploit() { " ⚠️ **Exploit**" } else { "" };
            println!(
                "### {} (Risk: {}/100){}{}",
                vuln.id,
                vuln.risk_score.unwrap_or(0),
                kev_badge,
                exp_badge
            );
            println!();
            println!("**Severity:** {:?}  ", vuln.severity);
            if let Some(cvss) = vuln.cvss_v3 {
                println!("**CVSS v3:** {:.1}  ", cvss);
            }
            println!();
            println!("{}", vuln.description);
            println!();
        }
    }

    /// Output report as text
    fn output_report_text(
        &self,
        url: &str,
        techs: &[DetectedTech],
        report: &CorrelationReport,
    ) {
        let summary = &report.summary;

        Output::header("VULNERABILITY REPORT");
        println!();
        Output::item("Target", url);
        Output::item("Generated", &chrono_now());
        println!();

        Output::section("Executive Summary");
        Output::item("Technologies Detected", &techs.len().to_string());
        Output::item("Total Vulnerabilities", &summary.total_vulns.to_string());
        Output::item("Critical", &summary.critical_count.to_string());
        Output::item("High", &summary.high_count.to_string());
        Output::item("Medium", &summary.medium_count.to_string());
        Output::item("In CISA KEV", &summary.kev_count.to_string());
        Output::item("With Exploits", &summary.exploitable_count.to_string());
        println!();

        Output::section("Detected Technologies");
        for tech in techs {
            let version = tech.version.as_deref().unwrap_or("unknown");
            Output::item(&tech.name, version);
        }
        println!();

        Output::section("Top Risks");
        let top = report.top_risks(10);
        for vuln in top {
            self.display_vuln_summary(vuln);
        }
    }

    /// Fingerprint a target URL using HTTP client and fingerprint engine
    fn fingerprint_target(&self, url: &str) -> Result<Vec<DetectedTech>, String> {
        use crate::protocols::http::HttpClient;
        use std::collections::HashMap;

        // Make HTTP request to get headers
        let client = HttpClient::new();
        let response = client.get(url).map_err(|e| format!("HTTP request failed: {}", e))?;

        // Extract headers into a HashMap
        let mut headers: HashMap<String, String> = HashMap::new();
        for (key, value) in &response.headers {
            headers.insert(key.clone(), value.clone());
        }

        // Create fingerprint engine and extract from HTTP headers
        let mut engine = FingerprintEngine::new();
        engine.extract_from_http_headers(&headers);

        // Also extract from HTML body if present
        if !response.body.is_empty() {
            let body_str = String::from_utf8_lossy(&response.body);
            engine.extract_from_html(&body_str);
        }

        Ok(engine.into_results())
    }
}

/// Extract host from URL
fn extract_host(url: &str) -> Result<String, String> {
    let url = url.trim();

    // Remove protocol
    let without_proto = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };

    // Remove path
    let host = if let Some(pos) = without_proto.find('/') {
        &without_proto[..pos]
    } else {
        without_proto
    };

    // Remove port
    let host = if let Some(pos) = host.find(':') {
        &host[..pos]
    } else {
        host
    };

    if host.is_empty() {
        return Err("Invalid URL: could not extract host".to_string());
    }

    Ok(host.to_string())
}

/// Get current timestamp
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    let days = secs / 86400;
    let years_since_1970 = days / 365;
    let year = 1970 + years_since_1970;

    // Rough month/day calculation
    let remaining_days = days % 365;
    let month = (remaining_days / 30) + 1;
    let day = (remaining_days % 30) + 1;

    format!("{}-{:02}-{:02}", year, month.min(12), day.min(31))
}

/// Parse ecosystem string to Ecosystem enum
fn parse_ecosystem(s: &str) -> Option<Ecosystem> {
    match s.to_lowercase().as_str() {
        "npm" => Some(Ecosystem::Npm),
        "pypi" | "pip" | "python" => Some(Ecosystem::PyPI),
        "cargo" | "crates" | "rust" => Some(Ecosystem::Cargo),
        "go" | "golang" => Some(Ecosystem::Go),
        "maven" | "java" => Some(Ecosystem::Maven),
        "nuget" | "dotnet" | ".net" => Some(Ecosystem::NuGet),
        "packagist" | "composer" | "php" => Some(Ecosystem::Packagist),
        "rubygems" | "gem" | "ruby" => Some(Ecosystem::RubyGems),
        "pub" | "dart" | "flutter" => Some(Ecosystem::Pub),
        "hex" | "elixir" | "erlang" => Some(Ecosystem::Hex),
        _ => None,
    }
}

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Wrap text to specified width
fn wrap_text(s: &str, width: usize) -> String {
    let mut result = String::new();
    let mut current_line = String::new();

    for word in s.split_whitespace() {
        if current_line.len() + word.len() + 1 > width {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&current_line);
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&current_line);
    }

    result
}

fn vuln_summary_to_json(vuln: &Vulnerability) -> crate::serde_json::Value {
    json!({
        "id": vuln.id.clone(),
        "title": vuln.title.replace('\n', " "),
        "severity": format!("{:?}", vuln.severity),
        "risk_score": vuln.risk_score.unwrap_or(0),
        "cvss_v3": vuln.cvss_v3,
        "cisa_kev": vuln.cisa_kev,
        "has_exploit": vuln.has_exploit()
    })
}

fn vuln_detail_to_json(vuln: &Vulnerability) -> crate::serde_json::Value {
    json!({
        "id": vuln.id.clone(),
        "title": vuln.title.replace('\n', " "),
        "description": vuln.description.replace('\n', " "),
        "severity": format!("{:?}", vuln.severity),
        "risk_score": vuln.risk_score.unwrap_or(0),
        "cvss_v3": vuln.cvss_v3,
        "cvss_v2": vuln.cvss_v2,
        "cisa_kev": vuln.cisa_kev,
        "kev_due_date": vuln.kev_due_date.clone(),
        "has_exploit": vuln.has_exploit(),
        "exploit_count": vuln.exploits.len(),
        "cwes": vuln.cwes.clone(),
        "references": vuln.references.iter().take(5).cloned().collect::<Vec<_>>()
    })
}

fn kev_entry_to_json(
    entry: &crate::modules::recon::vuln::kev::KevEntry,
) -> crate::serde_json::Value {
    json!({
        "cve_id": entry.cve_id.clone(),
        "vulnerability_name": entry.vulnerability_name.replace('\n', " "),
        "vendor": entry.vendor_project.clone(),
        "product": entry.product.clone(),
        "date_added": entry.date_added.clone(),
        "due_date": entry.due_date.clone(),
        "known_ransomware_use": entry.known_ransomware_use
    })
}

fn exploit_entry_to_json(
    entry: &crate::modules::recon::vuln::exploitdb::ExploitDbEntry,
) -> crate::serde_json::Value {
    json!({
        "id": entry.id.clone(),
        "title": entry.title.replace('\n', " "),
        "platform": entry.platform.clone(),
        "type": entry.exploit_type.clone(),
        "date": entry.date.clone(),
        "cve_ids": entry.cve_ids.clone(),
        "verified": entry.verified
    })
}

fn cpe_mapping_to_json(
    cpe: &&crate::modules::recon::vuln::cpe::CpeMapping,
) -> crate::serde_json::Value {
    let example_cpe = generate_cpe(cpe.tech_name, Some("1.0")).unwrap_or_default();
    json!({
        "tech_name": cpe.tech_name,
        "vendor": cpe.vendor,
        "product": cpe.product,
        "example_cpe": example_cpe
    })
}

fn top_risk_to_json(vuln: &&Vulnerability) -> crate::serde_json::Value {
    json!({
        "id": vuln.id.clone(),
        "risk_score": vuln.risk_score.unwrap_or(0),
        "severity": format!("{:?}", vuln.severity),
        "kev": vuln.cisa_kev,
        "title": vuln.title.clone()
    })
}

fn vuln_search_payload(
    tech: &str,
    version: Option<&String>,
    source: &str,
    vulns: &[Vulnerability],
    limit: usize,
) -> Value {
    let vulnerabilities: Vec<Value> = vulns.iter().take(limit).map(vuln_summary_to_json).collect();
    json!({
        "technology": tech,
        "version": version.cloned(),
        "source": source,
        "total": vulns.len(),
        "showing": limit.min(vulns.len()),
        "vulnerabilities": vulnerabilities
    })
}

fn cve_not_found_payload(cve_id: &str) -> Value {
    json!({
        "status": "not_found",
        "error": "CVE not found",
        "cve_id": cve_id
    })
}

fn vuln_detail_payload(vuln: &Vulnerability) -> Value {
    vuln_detail_to_json(vuln)
}

fn kev_stats_payload(stats: &crate::modules::recon::vuln::kev::KevStats) -> Value {
    let top_vendors: Vec<Value> = stats
        .top_vendors
        .iter()
        .take(10)
        .map(|(vendor, count)| json!({"vendor": vendor, "count": count}))
        .collect();
    json!({
        "type": "kev_stats",
        "total": stats.total,
        "ransomware_count": stats.ransomware_count,
        "top_vendors": top_vendors
    })
}

fn kev_entries_payload(
    vendor: Option<&String>,
    product: Option<&String>,
    entries: &[crate::modules::recon::vuln::kev::KevEntry],
    limit: usize,
) -> Value {
    let listed: Vec<Value> = entries.iter().take(limit).map(kev_entry_to_json).collect();
    let mut payload = crate::serde_json::Map::new();
    payload.insert("type".to_string(), json!("kev_entries"));
    if let Some(vendor) = vendor {
        payload.insert("filter_vendor".to_string(), json!(vendor));
    }
    if let Some(product) = product {
        payload.insert("filter_product".to_string(), json!(product));
    }
    payload.insert("total".to_string(), json!(entries.len()));
    payload.insert("showing".to_string(), json!(limit.min(entries.len())));
    payload.insert("entries".to_string(), json!(listed));
    Value::Object(payload)
}

fn exploit_search_payload(
    query: &str,
    results: &[crate::modules::recon::vuln::exploitdb::ExploitDbEntry],
    limit: usize,
) -> Value {
    let exploits: Vec<Value> = results.iter().take(limit).map(exploit_entry_to_json).collect();
    json!({
        "query": query,
        "total": results.len(),
        "showing": limit.min(results.len()),
        "exploits": exploits
    })
}

fn cpe_mappings_payload(
    category: Option<&String>,
    search: Option<&String>,
    filtered: &[&crate::modules::recon::vuln::cpe::CpeMapping],
) -> Value {
    let mut by_category: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
    for cpe in filtered {
        let cat_name = format!("{:?}", cpe.category);
        by_category.entry(cat_name).or_default().push(*cpe);
    }
    let mut categories_json = crate::serde_json::Map::new();
    let mut category_names: Vec<_> = by_category.keys().cloned().collect();
    category_names.sort();
    for cat in category_names {
        let cpes = by_category.get(&cat).unwrap();
        let cpes_json: Vec<Value> = cpes.iter().map(cpe_mapping_to_json).collect();
        categories_json.insert(cat, json!(cpes_json));
    }

    let mut payload = crate::serde_json::Map::new();
    if let Some(category) = category {
        payload.insert("filter_category".to_string(), json!(category));
    }
    if let Some(search) = search {
        payload.insert("filter_search".to_string(), json!(search));
    }
    payload.insert("total".to_string(), json!(filtered.len()));
    payload.insert("categories".to_string(), Value::Object(categories_json));
    Value::Object(payload)
}

fn detected_tech_to_json(tech: &DetectedTech) -> Value {
    json!({
        "name": tech.name,
        "category": format!("{:?}", tech.category),
        "version": tech.version,
        "confidence": tech.confidence,
        "source": tech.source
    })
}

fn source_stat_to_json(stat: &crate::modules::recon::vuln::correlator::SourceStats) -> Value {
    json!({
        "source": stat.source,
        "found": stat.found,
        "duration_ms": stat.duration_ms,
        "error": stat.error
    })
}

fn tech_correlation_to_json(
    corr: &crate::modules::recon::vuln::correlator::TechCorrelation,
) -> Value {
    let vulnerabilities: Vec<Value> = corr.vulnerabilities.iter().map(vuln_summary_to_json).collect();
    json!({
        "technology": detected_tech_to_json(&corr.tech),
        "cpe": corr.cpe,
        "cve_count": corr.cve_count,
        "critical_count": corr.critical_count,
        "high_count": corr.high_count,
        "exploitable_count": corr.exploitable_count,
        "kev_count": corr.kev_count,
        "query_time_ms": corr.query_time_ms,
        "max_risk_score": corr.max_risk_score(),
        "max_severity": format!("{:?}", corr.max_severity()),
        "vulnerabilities": vulnerabilities
    })
}

fn correlation_report_payload(report: &CorrelationReport) -> Value {
    let summary = &report.summary;
    let tech_correlations: Vec<Value> = report
        .tech_correlations
        .iter()
        .map(tech_correlation_to_json)
        .collect();
    let source_stats: Vec<Value> = report.source_stats.iter().map(source_stat_to_json).collect();
    let top_risks: Vec<Value> = report.top_risks(10).iter().map(top_risk_to_json).collect();

    json!({
        "summary": {
            "techs_scanned": summary.techs_scanned,
            "techs_vulnerable": summary.techs_vulnerable,
            "total_vulns": summary.total_vulns,
            "critical_count": summary.critical_count,
            "high_count": summary.high_count,
            "medium_count": summary.medium_count,
            "low_count": summary.low_count,
            "exploitable_count": summary.exploitable_count,
            "kev_count": summary.kev_count,
            "avg_risk_score": summary.avg_risk_score,
            "max_risk_score": summary.max_risk_score
        },
        "total_time_ms": report.total_time_ms,
        "clean_techs": report.clean_techs,
        "source_stats": source_stats,
        "tech_correlations": tech_correlations,
        "top_risks": top_risks
    })
}

fn vuln_correlation_payload(url: &str, techs: &[DetectedTech], report: &CorrelationReport) -> Value {
    let detected_techs: Vec<Value> = techs.iter().map(detected_tech_to_json).collect();
    json!({
        "target": url,
        "detected_technologies": detected_techs,
        "correlation": correlation_report_payload(report)
    })
}

fn vuln_scan_payload(
    url: &str,
    deep: bool,
    techs: &[DetectedTech],
    report: &CorrelationReport,
) -> Value {
    json!({
        "target": url,
        "deep": deep,
        "detected_technologies": techs.iter().map(detected_tech_to_json).collect::<Vec<_>>(),
        "report": correlation_report_payload(report)
    })
}

fn vuln_report_payload(url: &str, techs: &[DetectedTech], report: &CorrelationReport) -> Value {
    json!({
        "target": url,
        "generated_at": chrono_now(),
        "detected_technologies": techs.iter().map(detected_tech_to_json).collect::<Vec<_>>(),
        "report": correlation_report_payload(report)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::common::Severity;
    use crate::modules::recon::fingerprint::FingerprintSource;
    use crate::modules::recon::vuln::correlator::{CorrelationSummary, SourceStats, TechCorrelation};

    fn sample_vuln(id: &str) -> Vulnerability {
        let mut vuln = Vulnerability::new(id, "Sample vuln", "demo");
        vuln.severity = Severity::High;
        vuln.risk_score = Some(72);
        vuln
    }

    fn sample_tech() -> DetectedTech {
        DetectedTech {
            name: "nginx".to_string(),
            version: Some("1.24.0".to_string()),
            category: TechCategory::WebServer,
            confidence: 0.95,
            source: FingerprintSource::HttpHeader,
        }
    }

    #[test]
    fn vuln_search_payload_includes_showing_count() {
        let vulns = vec![sample_vuln("CVE-2024-0001"), sample_vuln("CVE-2024-0002")];
        let payload = vuln_search_payload("nginx", None, "nvd", &vulns, 1);
        assert_eq!(payload["total"], json!(2));
        assert_eq!(payload["showing"], json!(1));
    }

    #[test]
    fn cve_not_found_payload_marks_status() {
        let payload = cve_not_found_payload("CVE-2024-9999");
        assert_eq!(payload["status"], json!("not_found"));
        assert_eq!(payload["cve_id"], json!("CVE-2024-9999"));
    }

    #[test]
    fn correlation_report_payload_contains_summary_and_top_risks() {
        let mut corr = TechCorrelation::new(sample_tech());
        corr.vulnerabilities.push(sample_vuln("CVE-2024-0001"));
        corr.calculate_stats();

        let mut collection = VulnCollection::new();
        collection.add(sample_vuln("CVE-2024-0001"));

        let report = CorrelationReport {
            tech_correlations: vec![corr],
            all_vulnerabilities: collection,
            source_stats: vec![SourceStats {
                source: "nvd".to_string(),
                found: 1,
                duration_ms: 42,
                error: None,
            }],
            total_time_ms: 99,
            clean_techs: vec!["redis".to_string()],
            summary: CorrelationSummary {
                techs_scanned: 2,
                techs_vulnerable: 1,
                total_vulns: 1,
                critical_count: 0,
                high_count: 1,
                medium_count: 0,
                low_count: 0,
                exploitable_count: 0,
                kev_count: 0,
                avg_risk_score: 72.0,
                max_risk_score: 72,
            },
        };

        let payload = correlation_report_payload(&report);
        assert_eq!(payload["summary"]["techs_scanned"], json!(2));
        assert_eq!(payload["source_stats"].as_array().unwrap()[0]["source"], json!("nvd"));
        assert_eq!(payload["top_risks"].as_array().unwrap()[0]["id"], json!("CVE-2024-0001"));
    }
}
