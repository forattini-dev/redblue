//! Shared resolver for the four describe/get execution modes introduced in 0.2.13.
//!
//! Every `describe` and `get` verb supports the same contract:
//!
//! ```text
//! rb <domain> describe <target>                 → Live     (collect inline, discard)
//! rb <domain> describe <target> --persist       → LivePersist (collect + write DB)
//! rb <domain> describe <target> --from-db       → FromDb   (read existing DB, fail if missing)
//! rb <domain> describe <target> --from-json -   → FromJson (read payload from stdin)
//! rb <domain> describe <target> --cache-only    → alias for --from-db
//! ```
//!
//! Flags `--persist`, `--from-db`, `--cache-only`, and `--from-json` are
//! mutually exclusive. The default (no flags) is `Live`.

use crate::cli::CliContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribeMode {
  /// Collect inline, print result, discard everything. Default since 0.2.13.
  Live,
  /// Collect inline, write to the persisted DB, print result.
  LivePersist,
  /// Read from an existing DB. Fail if absent. Zero network I/O.
  FromDb,
  /// Read a payload already serialized to stdin or a file path.
  /// The `String` is the source: `-` for stdin, or a filesystem path.
  FromJson(String),
}

/// Resolve the requested execution mode from CLI flags.
///
/// Returns an error if more than one of `--persist`, `--from-db`,
/// `--cache-only`, `--from-json` is set — the modes are mutually exclusive.
pub fn resolve_describe_mode(ctx: &CliContext) -> Result<DescribeMode, String> {
  let persist = ctx.has_flag("persist") || ctx.has_flag("save");
  let from_db = ctx.has_flag("from-db") || ctx.has_flag("cache-only");
  let from_json_source = ctx.get_flag("from-json");

  let selected_count = [persist, from_db, from_json_source.is_some()]
    .iter()
    .filter(|&&v| v)
    .count();

  if selected_count > 1 {
    return Err(
      "Conflicting modes: --persist, --from-db (--cache-only), and --from-json are mutually exclusive."
        .to_string(),
    );
  }

  if let Some(source) = from_json_source {
    return Ok(DescribeMode::FromJson(source));
  }

  if from_db {
    return Ok(DescribeMode::FromDb);
  }

  if persist {
    return Ok(DescribeMode::LivePersist);
  }

  Ok(DescribeMode::Live)
}

/// Read the payload for `DescribeMode::FromJson` — supports stdin (`-`) or a
/// filesystem path. Returns raw bytes for the caller to parse.
pub fn read_from_json_source(source: &str) -> Result<Vec<u8>, String> {
  use std::io::Read;

  if source == "-" {
    let mut buf = Vec::new();
    std::io::stdin()
      .read_to_end(&mut buf)
      .map_err(|e| format!("Failed to read --from-json payload from stdin: {}", e))?;
    return Ok(buf);
  }

  std::fs::read(source)
    .map_err(|e| format!("Failed to read --from-json payload from {}: {}", source, e))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn ctx_with(flags: &[(&str, Option<&str>)]) -> CliContext {
    let mut ctx = CliContext::default();
    for (k, v) in flags {
      ctx.flags.insert(
        (*k).to_string(),
        v.map(|s| s.to_string()).unwrap_or_default(),
      );
    }
    ctx
  }

  #[test]
  fn default_is_live() {
    let ctx = ctx_with(&[]);
    assert_eq!(resolve_describe_mode(&ctx).unwrap(), DescribeMode::Live);
  }

  #[test]
  fn persist_maps_to_live_persist() {
    let ctx = ctx_with(&[("persist", None)]);
    assert_eq!(
      resolve_describe_mode(&ctx).unwrap(),
      DescribeMode::LivePersist
    );
  }

  #[test]
  fn save_is_alias_for_persist() {
    let ctx = ctx_with(&[("save", None)]);
    assert_eq!(
      resolve_describe_mode(&ctx).unwrap(),
      DescribeMode::LivePersist
    );
  }

  #[test]
  fn from_db_maps() {
    let ctx = ctx_with(&[("from-db", None)]);
    assert_eq!(resolve_describe_mode(&ctx).unwrap(), DescribeMode::FromDb);
  }

  #[test]
  fn cache_only_is_alias_for_from_db() {
    let ctx = ctx_with(&[("cache-only", None)]);
    assert_eq!(resolve_describe_mode(&ctx).unwrap(), DescribeMode::FromDb);
  }

  #[test]
  fn from_json_carries_source() {
    let ctx = ctx_with(&[("from-json", Some("-"))]);
    assert_eq!(
      resolve_describe_mode(&ctx).unwrap(),
      DescribeMode::FromJson("-".to_string())
    );
  }

  #[test]
  fn conflicting_modes_error() {
    let ctx = ctx_with(&[("persist", None), ("from-db", None)]);
    assert!(resolve_describe_mode(&ctx).is_err());
  }
}
