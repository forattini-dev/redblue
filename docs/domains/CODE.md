# CODE Domain Documentation

## Overview

Source code security analysis including secrets detection and dependency vulnerability scanning. Replaces **gitleaks**, **trufflehog**, and **snyk**.

**Domain:** `code`
**Status:** ⏳ Phase 4 (Planned)

---

## Implementation Status (Nov 2025)

- No code-domain modules have landed yet; `src/modules/` contains no `code/` subtree and the CLI verbs are intentionally absent to avoid shipping placeholders.
- Requirements captured in the old roadmap translate to two primary deliverables:
  1. **Secrets scanning** – streaming scanners for Git worktrees and archives, entropy heuristics, provider-specific detectors, and `.rdb` persistence.
  2. **Dependency auditing** – parser backends for Cargo, npm, pip, go.mod, etc., with local advisory databases (no external APIs).
- Before implementation begins, define a zero-dependency rules engine, wordlists, and test fixtures to keep the domain compliant with project guardrails.

### Next Steps
1. Draft an RFC outlining detector architecture (patterns vs entropy, allowlists, suppression handling).
2. Stand up a minimal `code` module scaffold with feature flags disabled by default until scanners are production-ready.
3. Plan storage schema additions (e.g., `code_secrets`, `code_dependencies` segments) so results integrate cleanly with existing reports.

---

## Commands

### `rb code secrets scan <path>`
Secret and API key detection in source code (gitleaks-style).

### `rb code dependencies scan <file>`
Dependency vulnerability analysis (snyk-style).

## Tool Equivalents
- `gitleaks` → `rb code secrets scan`
- `trufflehog` → `rb code secrets scan`
- `snyk` → `rb code dependencies scan`
