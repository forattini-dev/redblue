//! Cache management for MITRE ATT&CK data
//!
//! Show cache status or clear the cached STIX data.

use crate::cli::output::Output;
use crate::cli::render;
use crate::cli::CliContext;
use crate::json;
use crate::modules::recon::mitre::types::CacheInfo;
use crate::modules::recon::mitre::MitreClient;

/// Manage ATT&CK data cache
pub fn manage_cache(ctx: &CliContext) -> Result<(), String> {
  // Check for --clear flag
  if ctx.has_flag("clear") {
    if !ctx.wants_machine_output() {
      Output::spinner_start("Clearing ATT&CK cache...");
    }

    MitreClient::clear_cache()?;

    let payload = clear_payload();
    if render::render_machine_output(ctx, "rb intel mitre cache --clear", &payload)? {
      return Ok(());
    } else {
      Output::spinner_done();
      Output::success("ATT&CK cache cleared successfully");
    }
    return Ok(());
  }

  // Show cache status
  let client = MitreClient::new();
  let info = client.cache_info();

  let payload = cache_info_payload(&info);
  if render::render_machine_output(ctx, "rb intel mitre cache", &payload)? {
    return Ok(());
  }

  Output::header("MITRE ATT&CK Cache Status");
  println!();

  Output::section("Cache Info");
  if let Some(ref path) = info.path {
    Output::item("Path", &path.display().to_string());
  } else {
    Output::item("Path", "(not available on this platform)");
  }

  if info.exists {
    Output::item("Size", &info.size_display());
    Output::item("Age", &info.age_display());

    if info.expired {
      Output::warning("Cache has expired - will refresh on next use");
    } else {
      Output::success("Cache is valid");
    }
  } else {
    Output::info("No cache exists - will fetch from GitHub on first use");
  }

  println!();
  Output::info("Use --clear to remove cached data");
  Output::info("Use --refresh with any command to force a fresh download");

  Ok(())
}

fn clear_payload() -> crate::serde_json::Value {
  json!({ "status": "cleared" })
}

fn cache_info_payload(info: &CacheInfo) -> crate::serde_json::Value {
  json!({
    "path": info.path.as_ref().map(|path| path.display().to_string()),
    "exists": info.exists,
    "size_bytes": info.size_bytes,
    "age_secs": info.age_secs,
    "expired": info.expired
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn clear_payload_reports_cleared_status() {
    let payload = clear_payload();
    assert_eq!(payload["status"].as_str(), Some("cleared"));
  }

  #[test]
  fn cache_info_payload_serializes_cache_state() {
    let info = CacheInfo {
      path: Some(std::path::PathBuf::from("/tmp/attack-cache.json")),
      exists: true,
      size_bytes: 4096,
      age_secs: 120,
      expired: false,
    };

    let payload = cache_info_payload(&info);

    assert_eq!(payload["path"].as_str(), Some("/tmp/attack-cache.json"));
    assert_eq!(payload["exists"].as_bool(), Some(true));
    assert_eq!(payload["size_bytes"].as_u64(), Some(4096));
    assert_eq!(payload["age_secs"].as_u64(), Some(120));
    assert_eq!(payload["expired"].as_bool(), Some(false));
  }
}
