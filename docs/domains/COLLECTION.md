# COLLECTION Domain Documentation

## Overview

Visual reconnaissance and screenshot capture for web applications. Replaces **aquatone**, **eyewitness**, and **gowitness**.

**Domain:** `collection`
**Status:** ⏳ Phase 4 (Planned)

---

## Implementation Status (Nov 2025)

- No screenshot automation has shipped yet; there is no `collection` module under `src/modules/`, and the CLI keeps these verbs disabled to avoid promising phantom features.
- Browser automation will need a headless Chrome/Chromium controller built on `std::process::Command` + DevTools Protocol sockets (without external crates) or a pure-Rust rasterizer; both options require careful sandboxing and documentation.
- Storage must accommodate binary artifacts (PNG/WebP) alongside metadata; design a segment format (`collection_screenshots`) before writing code.

### Next Steps
1. Decide on the rendering backend (headless Chrome via `--remote-debugging-port` is the leading option) and document operational guardrails.
2. Prototype a capture pipeline that streams PNG buffers to disk and records metadata (URL, resolution, timestamp) into `.rdb`.
3. Add troubleshooting guidance (missing Chrome, sandbox restrictions) once the pipeline is validated.

---

## Commands

### `rb collection screenshot capture <url>`
Single screenshot capture using Chrome DevTools Protocol.

### `rb collection screenshot batch <file>`
Batch screenshot processing from URL list.

**Flags:**
- `--width <px>` - Viewport width (default: 1440)
- `--height <px>` - Viewport height (default: 900)
- `--full-page` - Capture full page
- `--threads <n>` - Concurrent captures (default: 5)

## Tool Equivalents
- `aquatone` → `rb collection screenshot batch`
- `eyewitness` → `rb collection screenshot batch`
- `gowitness` → `rb collection screenshot capture`
