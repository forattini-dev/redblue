//! Export commands for MITRE ATT&CK Navigator layers
//!
//! Generate and export ATT&CK Navigator layers.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::intel::{Findings, NavigatorLayer, TechniqueMapper};
use crate::modules::recon::mitre::MitreClient;

/// Export mapped techniques to ATT&CK Navigator layer
pub fn export_navigator(ctx: &CliContext) -> Result<(), String> {
  Output::header("ATT&CK Navigator Layer Export");
  println!();

  let mapper = TechniqueMapper::new();
  let mut findings = Findings::default();
  let mut output_file: Option<String> = None;
  let mut layer_name = String::from("redblue Findings");

  // Helper to parse a key=value pair
  let parse_kv =
    |arg: &str, findings: &mut Findings, output: &mut Option<String>, name: &mut String| {
      if let Some(eq_pos) = arg.find('=') {
        let (key, value) = arg.split_at(eq_pos);
        let value = &value[1..];

        match key {
          "output" | "o" | "file" => {
            *output = Some(value.to_string());
          }
          "name" | "layer" => {
            *name = value.to_string();
          }
          "ports" | "p" => {
            for part in value.split(',') {
              if let Ok(port) = part.trim().parse::<u16>() {
                findings.ports.push(port);
              }
            }
          }
          "cves" | "cve" => {
            for cve in value.split(',') {
              let cve = cve.trim().to_string();
              let desc = format!("{} vulnerability", cve);
              findings.cves.push((cve, desc));
            }
          }
          "tech" | "t" | "fingerprint" | "fp" => {
            for tech in value.split(',') {
              findings.fingerprints.push(tech.trim().to_string());
            }
          }
          "banner" | "b" => {
            findings.banners.push(value.to_string());
          }
          _ => {}
        }
      }
    };

  if let Some(ref target) = ctx.target {
    parse_kv(target, &mut findings, &mut output_file, &mut layer_name);
  }
  for arg in &ctx.args {
    parse_kv(arg, &mut findings, &mut output_file, &mut layer_name);
  }

  if findings.ports.is_empty()
    && findings.cves.is_empty()
    && findings.fingerprints.is_empty()
    && findings.banners.is_empty()
  {
    Output::warning("No findings provided. Use flags to specify what to export:");
    println!();
    Output::info("  output=file.json       Output file path (required)");
    Output::info("  name=\"Layer Name\"      Layer name (optional)");
    Output::info("  ports=22,80,443        Map open ports");
    Output::info("  cves=CVE-2021-44228    Map CVE IDs");
    Output::info("  tech=wordpress         Map technologies");
    Output::info("  banner=\"Apache/2\"      Map service banner");
    println!();
    Output::info(
      "Example: rb intel mitre export output=findings.json ports=22,80,443 tech=wordpress",
    );
    return Ok(());
  }

  let output_path = output_file.unwrap_or_else(|| "attack-layer.json".to_string());

  // Show what we're mapping
  Output::section("Input Findings");
  if !findings.ports.is_empty() {
    Output::item(
      "Ports",
      &findings
        .ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", "),
    );
  }
  if !findings.cves.is_empty() {
    Output::item(
      "CVEs",
      &findings
        .cves
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<Vec<_>>()
        .join(", "),
    );
  }
  if !findings.fingerprints.is_empty() {
    Output::item("Technologies", &findings.fingerprints.join(", "));
  }
  if !findings.banners.is_empty() {
    Output::item("Banners", &findings.banners.join(", "));
  }
  println!();

  Output::spinner_start("Mapping to ATT&CK techniques...");
  let result = mapper.map_findings(&findings);
  Output::spinner_done();

  if result.techniques.is_empty() {
    Output::info("No techniques mapped for these findings. Nothing to export.");
    return Ok(());
  }

  Output::success(&format!(
    "Mapped {} techniques across {} tactics",
    result.unique_technique_ids().len(),
    result.by_tactic.len()
  ));
  println!();

  Output::spinner_start("Generating Navigator layer...");
  let layer = NavigatorLayer::from_mapping_result(&result, &layer_name, "target");
  Output::spinner_done();

  Output::spinner_start(&format!("Writing to {}...", output_path));
  layer.to_file(&output_path)?;
  Output::spinner_done();

  // Show summary
  Output::section("Export Summary");
  Output::item("Output File", &output_path);
  Output::item("Layer Name", &layer_name);
  Output::item("Techniques", &layer.techniques.len().to_string());
  Output::item("Format", "ATT&CK Navigator v4.4");
  println!();

  Output::success("Layer exported successfully!");
  println!();
  Output::info("Import the layer at: https://mitre-attack.github.io/attack-navigator/");

  Ok(())
}

/// Generate ATT&CK Navigator layer for a group or tactic
pub fn generate_navigator(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_output_format();
  let is_json = format == crate::cli::format::OutputFormat::Json;

  let group = ctx.get_flag_with_config("group");
  let tactic = ctx.get_flag_with_config("tactic");

  if group.is_none() && tactic.is_none() {
    return Err("Specify --group <name> or --tactic <name> to generate layer".to_string());
  }

  if !is_json {
    Output::header("MITRE ATT&CK Navigator Layer Generation");
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

  // Generate layer based on input
  let layer = if let Some(group_id) = group {
    if !is_json {
      Output::spinner_start(&format!("Generating layer for group: {}...", group_id));
    }

    crate::modules::recon::mitre::layer_from_group(&attack_data, &group_id, 100)
      .ok_or_else(|| format!("Group '{}' not found", group_id))?
  } else if let Some(tactic_id) = tactic {
    if !is_json {
      Output::spinner_start(&format!("Generating layer for tactic: {}...", tactic_id));
    }

    crate::modules::recon::mitre::layer_from_tactic(&attack_data, &tactic_id, 100)
      .ok_or_else(|| format!("Tactic '{}' not found", tactic_id))?
  } else {
    return Err("Must specify --group or --tactic".to_string());
  };

  if !is_json {
    Output::spinner_done();
  }

  let output_path = ctx.target.clone();

  if is_json {
    println!("{}", layer.to_json());
    return Ok(());
  }

  if let Some(ref path) = output_path {
    Output::spinner_start(&format!("Writing layer to {}...", path));
    std::fs::write(path, layer.to_json()).map_err(|e| format!("Failed to write file: {}", e))?;
    Output::spinner_done();

    Output::section("Layer Generated");
    Output::item("File", path);
    Output::item("Name", &layer.name);
    Output::item("Techniques", &layer.techniques.len().to_string());
    Output::item("Format", "ATT&CK Navigator v4.5");
    println!();

    Output::success("Layer exported successfully!");
    Output::info("Import at: https://mitre-attack.github.io/attack-navigator/");
  } else {
    Output::section("Layer Info");
    Output::item("Name", &layer.name);
    Output::item("Description", &layer.description);
    Output::item("Techniques", &layer.techniques.len().to_string());
    println!();

    Output::section("Techniques in Layer");
    for tech in layer.techniques.iter().take(15) {
      println!(
        "  • {} (score: {})",
        tech.technique_id,
        tech
          .score
          .map(|s| s.to_string())
          .unwrap_or_else(|| "N/A".to_string())
      );
    }
    if layer.techniques.len() > 15 {
      Output::info(&format!("  ... and {} more", layer.techniques.len() - 15));
    }
    println!();

    Output::info("Use --output <file.json> to save the layer file");
  }

  Ok(())
}
