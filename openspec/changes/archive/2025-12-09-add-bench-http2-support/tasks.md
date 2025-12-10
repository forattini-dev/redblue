# Implementation Tasks: Add HTTP/2 Support to Bench Load Generator

## 1. Spec & CLI
- [x] 1.1 Update bench load CLI to accept `--protocol auto|http1|http2` and surface the chosen protocol in help text.
- [x] 1.2 Update live dashboard / summaries to display the active protocol.
- [x] 1.3 Add CLI options for HTTP method and body payload (inline or file) and expose them in the summary.

## 2. Load Generator Core
- [x] 2.1 Extend load config to carry protocol preference (default auto).
- [x] 2.2 Implement HTTP/2 execution path using the existing `Http2Client` for pooled connections.
- [x] 2.3 Ensure HTTP/1.1 behavior stays the default when HTTP/2 is unavailable.
- [x] 2.5 Support sending request bodies for both HTTP/1.1 and HTTP/2 code paths (shared worker logic).
- [x] 2.6 Track time-to-first-byte separately from total response time and persist both in stats/livesnapshot. ✅
- [x] 2.7 Treat body read timeouts as warnings/errors instead of successful samples. ✅
- [x] 2.4 Add basic unit/integration coverage for protocol selection. ✅

## 3. Validation
- [x] 3.1 Run `cargo check` and `cargo test` for the touched crates. ✅ (cargo check passes; 9 new load-generator tests pass; 905/935 total tests pass)
- [x] 3.2 Document any remaining limitations (e.g., missing POST support) in proposal follow-up.
