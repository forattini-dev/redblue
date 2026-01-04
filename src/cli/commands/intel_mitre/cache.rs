//! Cache management for MITRE ATT&CK data
//!
//! Show cache status or clear the cached STIX data.

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::recon::mitre::MitreClient;

/// Manage ATT&CK data cache
pub fn manage_cache(ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    // Check for --clear flag
    if ctx.has_flag("clear") {
        if !is_json {
            Output::spinner_start("Clearing ATT&CK cache...");
        }

        MitreClient::clear_cache()?;

        if is_json {
            println!("{{\"status\": \"cleared\"}}");
        } else {
            Output::spinner_done();
            Output::success("ATT&CK cache cleared successfully");
        }
        return Ok(());
    }

    // Show cache status
    let client = MitreClient::new();
    let info = client.cache_info();

    if is_json {
        println!("{{");
        if let Some(ref path) = info.path {
            println!("  \"path\": \"{}\",", path.display());
        } else {
            println!("  \"path\": null,");
        }
        println!("  \"exists\": {},", info.exists);
        println!("  \"size_bytes\": {},", info.size_bytes);
        println!("  \"age_secs\": {},", info.age_secs);
        println!("  \"expired\": {}", info.expired);
        println!("}}");
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
