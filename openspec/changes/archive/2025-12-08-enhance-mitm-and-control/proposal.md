# Change: Enhance MITM, Control & Replication (RBB)

## Why

The current MITM and exploitation capabilities have reached a "Proof of Concept" stage but lack the robustness required for professional engagements. Specifically:
1.  **Modern Web Defenses:** CSP and Security Headers block our injection hooks.
2.  **Reliability:** The proxy handles large responses poorly (streaming issues).
3.  **Visibility:** We lack a real-time dashboard to see hooked browsers and traffic flow.
4.  **Persistence:** Manual replication of the tool to compromised hosts is tedious.

This proposal aims to mature the "RedBlue Browser" (RBB) ecosystem and the core interception engine.

## What Changes

### 1. MITM Engine Hardening
- **Header Stripping:** Automatically remove `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security` (downgrade), and `X-XSS-Protection` from intercepted responses.
- **Robust Streaming:** Replace the "one-shot read" logic with a proper buffered reader that scans for injection points (`</body>`) across TCP chunk boundaries without breaking large downloads.
- **WebSocket Support:** Ensure the proxy correctly handles `Connection: Upgrade` headers to allow WebSocket traffic (often used by modern apps) to flow through, even if we don't inspect the frames deeply yet.

### 2. RBB (RedBlue Browser) Control Center
- **Rename:** Formalize the module as **RBB** (RedBlue Browser).
- **TUI Dashboard:** Create a new TUI view (`rb mitm ui`) or integrate into `rb shell` to:
    - List connected (hooked) browsers.
    - Show real-time request/response logs with status codes.
    - Send commands to hooked browsers (e.g., "alert", "redirect", "phishing prompt").

### 3. Infrastructure & Replication
- **Built-in HTTP Server:** Implement `rb http serve` to host the `hook.js` payload and other static assets directly from the binary, removing the need for Python/Apache.
- **Auto-Replication:** Add a `--replicate` flag to exploitation commands. When a session is established:
    - Attempt to upload the `rb` binary to the target.
    - Attempt to upload the current `.vault` (if authorized).
    - Establish a persistent foothold.

### 4. Recon Visualization
- **ASCII Graphing:** Implement a text-based tree/graph visualization in the TUI for Recon data (Subdomains -> IPs), bridging the gap with tools like Amass/Maltego but staying within the terminal.

## Impact

- **Security:** Improves success rate of authorized Phishing/MITM simulations.
- **Usability:** Reduces setup time (no external server needed) and provides real-time feedback.
- **Codebase:** Significant refactor of `src/modules/proxy/mitm.rs` and extensions to `src/cli/tui.rs`.

## Risks

- **Complexity:** Streaming injection is tricky; getting chunked encoding wrong breaks the browsing experience.
- **Detection:** Aggressive header stripping is noisy and easily detected by blue team monitoring.
