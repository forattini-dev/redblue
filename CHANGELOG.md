# Changelog

All notable behavior and API changes to redblue are recorded here.

This changelog is retroactive for 0.2.10 onward — earlier releases can be
reconstructed from `git log`. The format follows the spirit of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); dates are in
`YYYY-MM-DD`.

## Unreleased

## 0.2.13 — 2026-04-20

The headline theme is **stateless by default**. Every describe/get verb
now collects inline, persistence is strictly opt-in, and the default DB
location moved out of the working directory.

### Added
- **SDK `REDBLUE_FORCE_BINARY` env var** — hard override of binary
  resolution. Equivalent to passing `binaryPath` to `createClient`.
  Reports `source: 'forced-env'` in `getBinaryInfo()` output.
- **`describe` / `get` 4-mode contract** — `--persist`, `--from-db`
  (alias `--cache-only`), and `--from-json <path|->` flags registered
  on `dns`, `recon`, `tls`, and `web` commands.
  - Default: `Live` — collect inline, print, discard.
  - `--persist` / `--save`: live + write the DB.
  - `--from-db` / `--cache-only`: read existing DB, fail if absent.
  - `--from-json -`: ingest a pre-collected payload from stdin or a file.
- **`storage::default_db_dir()` / `default_db_path()`** — canonical
  resolver for the on-disk DB location.
  - `REDBLUE_DB_DIR` env var → `config.database.db_dir` →
    `$XDG_DATA_HOME/redblue/dbs/` → `~/.local/share/redblue/dbs/` →
    `$LOCALAPPDATA/redblue/dbs/`.
  - CWD is no longer used as a bare default sink.
- **`storage::INCOMPATIBLE_DB_PREFIX` / `is_incompatible_db_error()`** —
  sentinel-prefixed errors so readers can fall through to a live path
  instead of aborting on legacy/foreign `.rdb` files.

### Changed
- **HTTP error on malformed response** now includes a hex + ASCII dump
  of the first 64 bytes and detects when those bytes look like an
  HTTP/2 frame (prefix `00 00` or `PRI * HTTP/2.0`). In that case the
  message explains that HTTP/2 fallback is not yet implemented and
  points at `rb tls security audit` to confirm ALPN. Full H2→H1.1
  automatic fallback is tracked for 0.2.14.
- **`rb dns record describe <domain>`** runs live lookups (A / AAAA /
  MX / NS / TXT / CNAME) by default. Pass `--from-db` to query the DB.
- **`rb dns record get <domain>:<type>`** delegates to `dns record
  lookup` live by default.
- **`rb recon domain describe <domain>`** runs WHOIS + live DNS lookup
  for the common record types by default.
- **`rb web asset describe <host>`** runs `headers` + `security` +
  `fingerprint` inline by default.
- **`rb tls security describe <host>`** delegates to `tls security
  audit` live by default.
- **`UnifiedStore::load_from_file`** error messages now include the
  offending bytes (hex + UTF-8 preview) and are tagged with the
  `INCOMPATIBLE_DB:` prefix.
- **Per-command `get_db_path` helpers** (`dns.rs`, `tls.rs`,
  `web/db.rs`, `network.rs`) check the new default location first and
  fall back to a legacy CWD lookup so pre-0.2.13 files still resolve.
- **`storage::client::PersistenceManager::get_db_path`** drops its CWD
  default for writes entirely; always uses `default_db_dir()`.

### Deprecated
- Legacy CWD-based DB layout (`<domain>.rdb` in the current directory).
  Still readable for backward compat; new writes always go to
  `default_db_dir()`.

## 0.2.12 — 2026-04-19

### Added
- `recon domain subdomains` performance overhaul (three-phase enum).
- `dns record email`, `tls security audit`, `network host fingerprint`
  emit structured JSON under `-o json`.

### Changed
- Error messages across RESTful commands now include the next actionable
  command.

## 0.2.11 — 2026-04-19

### Added
- **Typed SDK errors** — `RedblueError`, `RedblueBinaryNotFoundError`,
  `RedblueRouteError`, `RedblueParseError`, `RedblueTimeoutError`,
  `RedblueChecksumError`, `RedblueNetworkError`. Each exposes a stable
  `.code` and category-specific fields (`route`, `stdout`, `stderr`,
  `timeout`, `binaryPath`, `statusCode`, `url`, etc.).
- **`ensureInstalled` status contract** — return shape now includes
  `status: 'ready' | 'downloaded' | 'stale' | 'offline'` and an
  optional `latestVersion` field. `skipIfFresh: true` (default) avoids
  the GitHub release-check round-trip when a local binary already
  exists.
- **`preferSystemBinary` / `REDBLUE_PREFER_SYSTEM_BINARY=1`** — opt-out
  that restores the pre-0.2.11 binary resolution order.

### Changed
- **SDK binary resolution order** — package-local
  (`node_modules/redblue-cli/.redblue/bin/rb`) now wins over managed
  (`~/.local/bin/rb`) by default. Ensures consumers always run the
  binary their SDK version shipped with.
- `describe` bundles documented on `recon/domain` and `web/asset`.

## 0.2.10 — 2026-04-18

### Changed
- **Default for `database.auto_persist` flipped from `true` to `false`.**
  Scans no longer write `.rdb` files unless `--persist` / `--save` is
  passed explicitly. This was the first step in the move toward
  stateless defaults; the describe/get regression caused by the cutover
  was addressed in 0.2.13.

## 0.2.9 — 2026-04-18

### Added
- `rb system stress` resource stress testing (cpu, mem, io, all).
- Release workflow auto-regenerates `Cargo.lock` on version bumps.
