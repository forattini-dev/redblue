# COLLECTION Domain Documentation

## Overview

Visual reconnaissance and screenshot capture for web applications. Replaces **aquatone**, **eyewitness**, and **gowitness**.

**Domain:** `collection`
**Status:** ⏳ Phase 4 (Planned)

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
