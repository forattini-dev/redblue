//! Engine mode handlers for `rb database engine <verb>`
//!
//! Page-based storage engine operations:
//! - open: Open or create a database
//! - info: Display metadata
//! - stats: Show cache statistics
//! - checkpoint: Force WAL flush
//! - checkpoint: Force WAL flush

use std::fs;
use std::path::Path;

use crate::cli::commands::print_help;
use crate::cli::{output::Output, CliContext};
use crate::json;
use crate::storage::engine::{Database, DatabaseConfig};

use super::DatabaseCommand;

impl DatabaseCommand {
    /// Route engine mode verbs
    pub fn execute_engine(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "open" => engine_open(ctx),
            "info" => engine_info(ctx),
            "stats" => engine_stats(ctx),
            "checkpoint" => engine_checkpoint(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Err("Invalid verb".to_string())
            }
        }
    }
}

/// Open or create a database file
fn engine_open(ctx: &CliContext) -> Result<(), String> {
    let db_path = ctx.target.as_ref().ok_or(
        "Missing database path.\nUsage: rb database engine open <path> [--password secret]",
    )?;

    let path = Path::new(db_path);
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";
    let read_only = ctx.has_flag("read-only");

    // Check for password
    let password = ctx.get_flag("password");

    if !is_json {
        Output::spinner_start("Opening database");
    }

    let config = DatabaseConfig {
        read_only,
        create: true,
        ..Default::default()
    };

    let db = if let Some(_pwd) = &password {
        // Note: Encrypted opening requires encryption layer integration
        // For now, we use standard open with config
        Database::open_with_config(path, config)
    } else {
        Database::open_with_config(path, config)
    };

    let db = db.map_err(|e| format!("Failed to open database: {}", e))?;

    if !is_json {
        Output::spinner_done();
    }

    let file_size = db.file_size().unwrap_or(0);
    let page_count = db.page_count();

    if is_json {
        Output::json_value(&json!({
            "status": "opened",
            "path": db_path,
            "page_count": page_count,
            "file_size_bytes": file_size,
            "read_only": read_only,
        }));
    } else {
        Output::success(&format!("Database opened: {}", db_path));
        Output::summary_line(&[
            ("Pages", &page_count.to_string()),
            ("Size", &format!("{} KB", file_size / 1024)),
            ("Mode", if read_only { "read-only" } else { "read-write" }),
        ]);
    }

    // Close properly
    db.close()
        .map_err(|e| format!("Failed to close database: {}", e))?;

    Ok(())
}

/// Display database metadata and structure
fn engine_info(ctx: &CliContext) -> Result<(), String> {
    let db_path = ctx
        .target
        .as_ref()
        .ok_or("Missing database path.\nUsage: rb database engine info <path>")?;

    let path = Path::new(db_path);
    if !path.exists() {
        return Err(format!("Database file not found: {}", db_path));
    }

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    let config = DatabaseConfig {
        read_only: true,
        create: false,
        ..Default::default()
    };

    let db = Database::open_with_config(path, config)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let file_size = db.file_size().unwrap_or(0);
    let page_count = db.page_count();
    let wal_path = db.wal_path();
    let wal_exists = wal_path.exists();
    let wal_size = if wal_exists {
        fs::metadata(wal_path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    if is_json {
        Output::json_value(&json!({
            "path": db_path,
            "page_count": page_count,
            "file_size_bytes": file_size,
            "page_size_bytes": 4096,
            "wal_exists": wal_exists,
            "wal_size_bytes": wal_size,
        }));
    } else {
        Output::header(&format!("Database: {}", db_path));
        println!();
        Output::subheader("Storage");
        println!("  Pages:     {}", page_count);
        println!("  Page size: 4096 bytes");
        println!("  File size: {} KB", file_size / 1024);
        println!();
        Output::subheader("WAL (Write-Ahead Log)");
        println!("  Exists:    {}", if wal_exists { "yes" } else { "no" });
        if wal_exists {
            println!("  Size:      {} KB", wal_size / 1024);
        }
    }

    Ok(())
}

/// Show detailed cache and transaction statistics
fn engine_stats(ctx: &CliContext) -> Result<(), String> {
    let db_path = ctx
        .target
        .as_ref()
        .ok_or("Missing database path.\nUsage: rb database engine stats <path>")?;

    let path = Path::new(db_path);
    if !path.exists() {
        return Err(format!("Database file not found: {}", db_path));
    }

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    let config = DatabaseConfig {
        read_only: true,
        create: false,
        ..Default::default()
    };

    let db = Database::open_with_config(path, config)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let stats = db.cache_stats();
    let page_count = db.page_count();
    let hit_rate = if stats.hits + stats.misses > 0 {
        (stats.hits as f64 / (stats.hits + stats.misses) as f64) * 100.0
    } else {
        0.0
    };

    if is_json {
        Output::json_value(&json!({
            "cache": json!({
                "hits": stats.hits,
                "misses": stats.misses,
                "evictions": stats.evictions,
                "hit_rate_percent": hit_rate,
            }),
            "pages": page_count,
        }));
    } else {
        Output::header(&format!("Database Stats: {}", db_path));
        println!();
        Output::subheader("Page Cache (SIEVE)");
        println!("  Hits:      {}", stats.hits);
        println!("  Misses:    {}", stats.misses);
        println!("  Evictions: {}", stats.evictions);
        println!("  Hit rate:  {:.2}%", hit_rate);
        println!();
        Output::subheader("Storage");
        println!("  Pages:     {}", page_count);
    }

    Ok(())
}

/// Force a WAL checkpoint to flush pending writes
fn engine_checkpoint(ctx: &CliContext) -> Result<(), String> {
    let db_path = ctx
        .target
        .as_ref()
        .ok_or("Missing database path.\nUsage: rb database engine checkpoint <path>")?;

    let path = Path::new(db_path);
    if !path.exists() {
        return Err(format!("Database file not found: {}", db_path));
    }

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if !is_json {
        Output::spinner_start("Checkpointing database");
    }

    let config = DatabaseConfig {
        read_only: false,
        create: false,
        ..Default::default()
    };

    let db = Database::open_with_config(path, config)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let result = db
        .checkpoint()
        .map_err(|e| format!("Checkpoint failed: {}", e))?;

    if !is_json {
        Output::spinner_done();
    }

    if is_json {
        Output::json_value(&json!({
            "status": "completed",
            "pages_checkpointed": result.pages_checkpointed,
            "transactions_processed": result.transactions_processed,
        }));
    } else {
        Output::success("Checkpoint completed");
        Output::summary_line(&[
            ("Pages flushed", &result.pages_checkpointed.to_string()),
            ("Transactions", &result.transactions_processed.to_string()),
        ]);
    }

    db.close()
        .map_err(|e| format!("Failed to close database: {}", e))?;

    Ok(())
}
