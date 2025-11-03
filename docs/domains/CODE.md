# CODE Domain Documentation

## Overview

Source code security analysis including secrets detection and dependency vulnerability scanning. Replaces **gitleaks**, **trufflehog**, and **snyk**.

**Domain:** `code`
**Status:** ⏳ Phase 4 (Planned)

## Commands

### `rb code secrets scan <path>`
Secret and API key detection in source code (gitleaks-style).

### `rb code dependencies scan <file>`
Dependency vulnerability analysis (snyk-style).

## Tool Equivalents
- `gitleaks` → `rb code secrets scan`
- `trufflehog` → `rb code secrets scan`
- `snyk` → `rb code dependencies scan`
