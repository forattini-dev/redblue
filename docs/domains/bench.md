# BENCH Domain Documentation

## TL;DR
Outlines the planned load-testing domain, current lack of implementation, and the steps needed to build a zero-dependency benchmark runner.

## Overview

Load testing and performance benchmarking for web applications. Replaces **wrk**, **k6**, and **ab**.

**Domain:** `bench`
**Status:** ⏳ Phase 4 (Planned)

---

## Implementation Status (Nov 2025)

- Load-testing features are still on the roadmap; no `bench` modules exist under `src/modules/`, and the CLI deliberately omits these verbs until we have a production-ready engine.
- Planned architecture calls for an async-free, std-only worker pool similar to `src/modules/benchmark/` helpers already used for internal profiling (`load-generator.rs`, `pool.rs`). Those components should be repurposed when the domain goes live.
- Before implementation, define metrics collection (latency histograms, percentiles), reporting formats, and `.rdb` storage schema (`bench_results` segment) to avoid bolting on telemetry later.

### Next Steps
1. Write a design RFC covering request workers, rate limiting, and TLS reuse so the zero-dependency constraint is preserved.
2. Extend the existing benchmark module into a proper domain by wiring new CLI verbs and integrating with the storage/report pipeline.
3. Prepare deterministic fixtures/tests (local HTTP server) to validate throughput calculations without external dependencies.

---

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
