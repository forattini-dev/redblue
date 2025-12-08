# Proposal: Add HTTP/2 Support to Bench Load Generator

## Why
- Current load tests only exercise HTTP/1.1, so the client becomes the bottleneck when we try to saturate modern services that favor multiplexed connections.
- Operators asked for a way to keep the workload heavier on the target rather than on the redblue runner (see conversation on 2025-11-06).
- HTTP/2 is already implemented in `src/protocols/http2`, but it is not wired into the benchmarking pipeline, forcing us to reimplement connection logic in the load generator.

## What
1. Allow `rb bench load run` to select the HTTP protocol (`http1`, `http2`, or `auto`).
2. Reuse the pooled connection strategy for HTTP/2 so that each simulated user can multiplex requests without spawning extra sockets.
3. Emit protocol information in the live dashboard / summary so operators know which transport was used.

## Impact
- `src/modules/benchmark` (load generator + pool) gains HTTP/2 integration.
- `src/cli/commands/bench.rs` exposes a new `--protocol` flag (default `auto`).
- Adds a spec under `bench-load` describing protocol selection requirements.
- No external dependencies; reuses in-tree HTTP/2 stack.

## Out of Scope
- HTTP/3 / QUIC load testing (tracked separately by `add-http3-support`).
- Server push and streaming semantics (future work once basic support lands).

## Follow-up / Limitations
- Request bodies are buffered entirely in memory; streaming uploads (chunked or very large payloads) still need dedicated handling.
- Automated tests for the HTTP/2 pipeline are pending; existing integration suites (`tests/http2_live_test.rs`, `tests/hpack_standalone.rs`) already fail on main and need cleanup before we can add new coverage.
