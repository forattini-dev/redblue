# BENCH Domain Documentation

## Overview

Load testing and performance benchmarking for web applications. Replaces **wrk**, **k6**, and **ab**.

**Domain:** `bench`
**Status:** ⏳ Phase 4 (Planned)

## Commands

### `rb bench load test <url>`
HTTP load testing with concurrent requests.

### `rb bench stress <url> --rps <n>`
Stress testing with specified requests per second.

**Flags:**
- `--rps <n>` - Requests per second
- `--duration <sec>` - Test duration
- `--threads <n>` - Concurrent threads

## Tool Equivalents
- `wrk` → `rb bench load test`
- `k6` → `rb bench stress`
- `ab` → `rb bench load test`
