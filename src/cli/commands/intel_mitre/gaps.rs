//! Coverage gap analysis for MITRE ATT&CK
//!
//! Analyze detection coverage gaps based on data sources.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::recon::mitre::{CoverageAnalyzer, GapPriority, MitreClient};

/// Show coverage gaps based on data sources
pub fn show_gaps(ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    if !is_json {
        Output::header("MITRE ATT&CK Coverage Gap Analysis");
        println!();
        Output::spinner_start("Fetching ATT&CK data from STIX...");
    }

    // Fetch STIX data (respecting --refresh flag)
    let mut client = MitreClient::new();
    let attack_data = if ctx.has_flag("refresh") {
        client.fetch_fresh()
    } else {
        client.fetch()
    }
    .map_err(|e| format!("Failed to fetch ATT&CK data: {}", e))?;

    if !is_json {
        Output::spinner_done();
    }

    // Create coverage analyzer
    let mut analyzer = CoverageAnalyzer::new(&attack_data);

    // Apply platform filter
    if let Some(platform) = ctx.get_flag_with_config("platform") {
        analyzer.filter_platforms(vec![platform]);
    }

    // Add data sources if provided
    if let Some(ds_str) = ctx.get_flag_with_config("data-sources") {
        for ds in ds_str.split(',') {
            analyzer.add_data_source(ds.trim());
        }
    }

    if !is_json {
        Output::spinner_start("Analyzing coverage...");
    }

    let report = analyzer.analyze();

    if !is_json {
        Output::spinner_done();
    }

    // Parse priority filter
    let priority_filter: Option<GapPriority> =
        ctx.get_flag_with_config("priority")
            .and_then(|p| match p.to_lowercase().as_str() {
                "critical" => Some(GapPriority::Critical),
                "high" => Some(GapPriority::High),
                "medium" => Some(GapPriority::Medium),
                "low" => Some(GapPriority::Low),
                _ => None,
            });

    // Filter gaps by priority
    let gaps: Vec<_> = if let Some(priority) = priority_filter {
        report
            .gaps
            .iter()
            .filter(|g| g.priority == priority)
            .collect()
    } else {
        report.gaps.iter().collect()
    };

    if is_json {
        let tactic_coverage: Vec<_> = report
            .tactic_coverage
            .iter()
            .map(|coverage| {
                json!({
                    "tactic": coverage.tactic_name.clone(),
                    "total": coverage.total,
                    "covered": coverage.covered,
                    "percentage": coverage.percentage
                })
            })
            .collect();
        let gaps_json: Vec<_> = gaps
            .iter()
            .map(|gap| {
                json!({
                    "technique_id": gap.technique_id.clone(),
                    "technique_name": gap.technique_name.clone(),
                    "priority": gap.priority.as_str(),
                    "tactics": gap.tactics.clone(),
                    "platforms": gap.platforms.clone()
                })
            })
            .collect();
        Output::json_value(&json!({
            "overall_coverage": report.overall_coverage,
            "total_techniques": report.total_techniques,
            "covered_count": report.covered_count,
            "gap_count": gaps.len(),
            "tactic_coverage": tactic_coverage,
            "gaps": gaps_json
        }));
        return Ok(());
    }

    // Display summary
    Output::section("Coverage Summary");
    Output::item(
        "Overall Coverage",
        &format!("{:.1}%", report.overall_coverage),
    );
    Output::item("Total Techniques", &report.total_techniques.to_string());
    Output::item("Covered", &report.covered_count.to_string());
    Output::item("Gaps", &gaps.len().to_string());
    println!();

    // Display tactic coverage
    Output::section("Tactic Coverage");
    for tc in &report.tactic_coverage {
        let bar_len = (tc.percentage / 5.0) as usize;
        let bar = "█".repeat(bar_len.min(20)) + &"░".repeat(20 - bar_len.min(20));
        let color = if tc.percentage >= 70.0 {
            "\x1b[32m"
        } else if tc.percentage >= 40.0 {
            "\x1b[33m"
        } else {
            "\x1b[31m"
        };
        println!(
            "  {:<20} {}{}\x1b[0m {:>5.1}% ({}/{})",
            tc.tactic_name, color, bar, tc.percentage, tc.covered, tc.total
        );
    }
    println!();

    // Display gaps by priority
    if gaps.is_empty() {
        Output::success("No gaps found with current data sources and filters!");
        return Ok(());
    }

    let critical: Vec<_> = gaps
        .iter()
        .filter(|g| g.priority == GapPriority::Critical)
        .collect();
    let high: Vec<_> = gaps
        .iter()
        .filter(|g| g.priority == GapPriority::High)
        .collect();
    let medium: Vec<_> = gaps
        .iter()
        .filter(|g| g.priority == GapPriority::Medium)
        .collect();

    if !critical.is_empty() && priority_filter.is_none()
        || priority_filter == Some(GapPriority::Critical)
    {
        Output::section(&format!("Critical Priority Gaps ({})", critical.len()));
        for gap in critical.iter().take(10) {
            println!(
                "  \x1b[31m●\x1b[0m {} - {}",
                gap.technique_id, gap.technique_name
            );
            println!("    Tactics: {}", gap.tactics.join(", "));
        }
        if critical.len() > 10 {
            Output::info(&format!("  ... and {} more", critical.len() - 10));
        }
        println!();
    }

    if !high.is_empty() && priority_filter.is_none() || priority_filter == Some(GapPriority::High) {
        Output::section(&format!("High Priority Gaps ({})", high.len()));
        for gap in high.iter().take(10) {
            println!(
                "  \x1b[33m●\x1b[0m {} - {}",
                gap.technique_id, gap.technique_name
            );
        }
        if high.len() > 10 {
            Output::info(&format!("  ... and {} more", high.len() - 10));
        }
        println!();
    }

    if !medium.is_empty() && priority_filter.is_none()
        || priority_filter == Some(GapPriority::Medium)
    {
        Output::section(&format!("Medium Priority Gaps ({})", medium.len()));
        for gap in medium.iter().take(5) {
            println!(
                "  \x1b[90m●\x1b[0m {} - {}",
                gap.technique_id, gap.technique_name
            );
        }
        if medium.len() > 5 {
            Output::info(&format!("  ... and {} more", medium.len() - 5));
        }
        println!();
    }

    // Display recommendations
    if !report.recommendations.is_empty() {
        Output::section("Recommendations");
        for (i, rec) in report.recommendations.iter().take(3).enumerate() {
            println!("  {}. {}", i + 1, rec.title);
            println!("     {}", rec.description);
            println!("     Impact: {:.1}% coverage improvement", rec.impact);
            println!();
        }
    }

    Ok(())
}
