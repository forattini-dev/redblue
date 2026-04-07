# redblue Remaining Plan (Only What Is Missing)

This plan tracks only the remaining work to finish the CLI/SDK architecture migration.
Order is intentional. Cross-platform work stays last.

## Goal

Close the migration with:

- explicit and reliable machine-output contracts
- minimal legacy routing/compat behavior
- wrapper/SDK behavior driven by manifest as single source of truth
- final cleanup and verification gates

## Execution Order

### 1) Finish Output Contract Migration

Scope:

- remove remaining ad hoc JSON output branches in CLI command layer
- ensure `--json` keeps stdout machine-only and diagnostics on stderr
- keep route-level machine metadata conservative and accurate

Concrete targets:

- migrate remaining manual output paths in:
  - `src/cli/commands/health.rs`
  - `src/cli/commands/fuzz.rs`
- verify no remaining `Output::json(...)` command-local formatting in `src/cli/commands`

Done when:

- command-local JSON printing is eliminated from command handlers
- `--json` routes emit parseable JSON on stdout only
- regression tests cover stdout purity for migrated critical routes

---

### 2) Reduce Legacy Parser/Dispatch Surface

Scope:

- shrink compatibility path for legacy command order (`domain verb resource`)
- keep canonical grammar as primary path everywhere

Concrete targets:

- reduce/limit translation logic centered in:
  - `src/cli/commands/mod.rs`
- keep explicit canonical correction messages
- add tests for failing/edge route resolution behavior

Done when:

- canonical path is the default in all practical flows
- legacy translation is minimal and explicit
- route correction/suggestion behavior is stable and tested

---

### 3) Complete Route Metadata Coverage

Scope:

- ensure all `impl Command for ...` provide route-level metadata (or explicit rationale)

Concrete targets:

- close metadata gaps in commands that still rely on defaults
- align aliases/machine-output policy at route level

Done when:

- all active command modules have explicit route metadata coverage
- manifest reflects route machine contract consistently

---

### 4) Wrapper: Remove Remaining Hardcode Paths

Scope:

- continue moving wrapper behavior to manifest-only interpretation
- keep compatibility behavior in explicit translation points only

Concrete targets:

- tighten `sdk/redblue-sdk.js` around:
  - route lookup
  - help/completion
  - validation/selector extraction
- gate machine execution paths with route metadata (`json_support`, preferred flag/value)

Done when:

- wrapper route/validation/help decisions are manifest-derived
- no duplicated semantic source competes with manifest
- wrapper tests cover canonical, alias, invalid, and global-option-prefixed flows

---

### 5) SDK Generation Completion

Scope:

- move from mostly dynamic client composition to generated manifest-driven surfaces

Concrete targets:

- define generation pipeline and artifacts
- align `sdk/index.d.ts` with generated route surface
- keep runtime fallback only as controlled compatibility layer

Done when:

- SDK route helpers are generated from manifest
- typed declarations map to real route contract
- drift checks fail fast when manifest and SDK differ

---

### 6) Final Migration Gates (Before Cross-Platform)

Scope:

- close acceptance gates for architecture migration before platform expansion

Required verification:

- `cargo fmt`
- `cargo check`
- targeted Rust tests for migrated parser/output paths
- `node --test sdk/test/redblue-sdk.test.js`

Done when:

- all checks above pass
- plan items 1-5 are complete
- remaining open items are only cross-platform `system host`

---

### 7) Cross-Platform `system host` (Last)

Scope:

- implement and document non-Linux capability behavior as final stage

Concrete targets:

- macOS collector strategy and implementation baseline
- Windows collector strategy and implementation baseline
- explicit capability gaps in payload (never silent omission)

Done when:

- `system host` remains JSON-safe on all supported platforms
- capability reporting is explicit on Linux/macOS/Windows
- cross-platform docs and tests are in place

## Fast Tracking Checklist

- [x] Step 1 complete
- [x] Step 2 complete
- [x] Step 3 complete
- [x] Step 4 complete
- [x] Step 5 complete
- [ ] Step 6 complete
- [x] Step 7 complete

## Current Status (2026-04-07)

- Step 1: completed (`health`/`fuzz` migrated off ad hoc command-local JSON emission).
- Step 2: completed (legacy order translation narrowed to avoid swapping when resource token is already canonical).
- Step 3: completed (all `impl Command for ...` now provide explicit `metadata` and `route_metadata` coverage).
- Step 4: completed (wrapper machine JSON execution hard-gated by route metadata contract).
- Step 5: completed (SDK generation pipeline added via `scripts/generate-sdk-surface.js` with generated artifacts and drift check).
- Step 6: pending by request (final verification gate deferred; remaining closeout is running the full gate suite when build/test is resumed).
- Step 7: completed (macOS/Windows collector baseline added for `system host`, with explicit unavailable collector reasons in payload and updated docs/tests).

Remaining to close Step 6 when build/test is resumed:

- run targeted Rust tests for migrated parser/output paths
- run `node --test sdk/test/redblue-sdk.test.js`
