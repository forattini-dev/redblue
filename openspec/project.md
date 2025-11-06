# Project Context

## Purpose

**redblue** is a single all-in-one security binary that completely replaces 30+ security tools (nmap, masscan, nikto, ffuf, subfinder, amass, etc.) for Red/Blue Team operations.

**Core Philosophy:**
- ONE binary = 30+ tools (no external dependencies)
- Size: ~2.7MB (smaller than a single security tool)
- ZERO external binaries called (we implement protocols ourselves)
- Native Rust performance (no subprocess overhead)
- Everything from scratch using ONLY Rust std

**Goals:**
1. Replace entire security toolkit with single self-contained binary
2. Implement all network protocols from scratch (DNS, HTTP, TLS, TCP/UDP, ICMP)
3. Zero external dependencies (no nmap, openssl, curl, etc.)
4. Excellent DevX with kubectl-style CLI
5. Educational value - read code to learn how protocols work

## Tech Stack

**Language:**
- Rust 2021 Edition (1.70+)
- 100% safe Rust (no unsafe unless absolutely required for syscalls)

**Dependencies:**
- `libc = "0.2"` - FFI bindings to kernel syscalls (PTY, terminal control, socket options)
- `openssl` (vendored) - Temporary for TLS 1.3 + HTTP/2 (will be replaced with from-scratch implementation)

**NO external protocol crates:**
- ❌ hyper, reqwest - We implement HTTP ourselves
- ❌ trust-dns - We implement DNS ourselves
- ❌ rustls, openssl (as protocol) - We implement TLS ourselves
- ❌ tokio, async runtimes - We use std threads

**Build Configuration:**
- LTO enabled (Link-Time Optimization)
- Single codegen unit for maximum optimization
- Strip debug symbols
- Panic = abort for smaller binary
- opt-level = 3 (maximum optimization)

## Project Conventions

### Code Style

**File Naming - MANDATORY kebab-case:**
```
✅ CORRECT: port-scanner.rs, tls-audit.rs, web-security.rs
❌ WRONG: port_scanner.rs (snake_case), PortScanner.rs (PascalCase)
```

**Project Name:**
- ✅ Always: `redblue` (all lowercase)
- ❌ NEVER: RedBlue, Redblue, REDBLUE, Red-Blue
- Only exception: binary alias `rb`

**Language:**
- ✅ English ONLY - all code, comments, docs, commits
- ❌ NEVER Portuguese or any other language

**Documentation:**
- ✅ ONLY ONE file: README.md
- ❌ NEVER create .md files proactively (QUICKSTART.md, GUIDE.md, etc.)
- Only create new docs when explicitly requested by user

**Formatting:**
- Use `cargo fmt` (rustfmt)
- Line length: 100 chars
- 4-space indentation
- No trailing whitespace

### Architecture Patterns

**Module Organization:**
```
src/
├── cli/              # kubectl-style CLI
│   ├── commands/     # Command implementations
│   ├── parser.rs     # Argument parsing
│   └── output.rs     # Colored output
├── protocols/        # FROM SCRATCH implementations
│   ├── dns.rs       # RFC 1035
│   ├── http.rs      # RFC 2616
│   ├── tls.rs       # RFC 5246/8446
│   └── whois.rs     # RFC 3912
├── modules/          # Security modules
│   ├── network/     # Port scanning, discovery
│   ├── recon/       # WHOIS, subdomains
│   ├── web/         # CMS scanning, fuzzing
│   └── exploit/     # Payloads, shells
├── intelligence/     # Fingerprinting
├── storage/         # Database operations
└── utils/           # Helpers
```

**CLI Pattern (kubectl-style):**
```
rb [domain] [resource] [verb] [target] [flags]

Examples:
rb network ports scan 192.168.1.1 --preset common
rb dns record lookup example.com --type MX
rb web asset security http://example.com
rb recon domain whois example.com
```

**Domains:**
- network, dns, web, recon, tls, exploit, cloud, database, code, collection, bench

**Resources:**
- ports, host, trace, record, domain, asset, security, payload, data, secrets

**Verbs:**
- Active: scan, range, ping, discover, run, mtr, audit, vuln, takeover
- Collector: list, show, export, query, report (read from storage only)

### Testing Strategy

**Test Organization:**
```
tests/
├── *_test.rs           # Integration tests
└── protocol_tests/     # RFC compliance tests
```

**Testing Requirements:**
1. All protocol implementations MUST have RFC compliance tests
2. Integration tests for each CLI command
3. No mock data - all tests use real implementations
4. Test with actual network protocols (DNS, HTTP, etc.)

**Running Tests:**
```bash
cargo test              # All tests
cargo test --lib        # Unit tests only
cargo test --test '*'   # Integration tests
```

### Git Workflow

**Branching:**
- `main` - Production-ready code
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates

**Commit Messages:**
```
<type>: <subject>

[optional body]

Examples:
feat: implement TLS 1.3 handshake from scratch
fix: correct DNS query packet format for AAAA records
docs: add comprehensive TLS domain documentation
test: add RFC 8448 TLS 1.3 test vectors
refactor: convert snake_case files to kebab-case
```

**Commit Types:**
- feat, fix, docs, test, refactor, perf, chore, style

## Domain Context

**Security Tool Domain:**
- Red Team: Offensive security testing, exploitation, post-exploitation
- Blue Team: Defense, monitoring, auditing, vulnerability assessment
- DevSecOps: Integration with CI/CD, automated scanning
- CTF: Capture The Flag competitions
- Bug Bounty: Vulnerability research and reporting

**Network Protocols Expertise:**
- DNS (RFC 1035) - Query/response format, record types
- HTTP/1.1 (RFC 2616) - GET/POST, headers, methods
- HTTP/2 (RFC 7540) - Binary framing, multiplexing
- TLS 1.2 (RFC 5246) - Handshake, cipher suites
- TLS 1.3 (RFC 8446) - 0-RTT, perfect forward secrecy
- WHOIS (RFC 3912) - Registration data
- TCP/UDP - Raw socket programming
- ICMP - Ping, traceroute

**Replaced Tools:**
- Port scanning: nmap, masscan, rustscan
- DNS: dig, nslookup, fierce, amass, subfinder
- Web: curl, ffuf, gobuster, nikto, whatweb
- TLS: sslyze, testssl.sh, sslscan
- OSINT: theHarvester, recon-ng, assetfinder
- Exploitation: msfvenom, netcat, various payload generators

## Important Constraints

### ABSOLUTE RULES (ZERO TOLERANCE)

**1. ZERO MOCKS - IMMEDIATE REMOVAL:**
```rust
// ❌ FORBIDDEN - Will be deleted immediately
let mock_data = vec![0u8; 12];
let dummy_response = "fake response";
// TODO: replace with real implementation
return vec![0u8; 32];

// ✅ REQUIRED - Real implementations only
fn calculate_verify_data(&self) -> Vec<u8> {
    let hash = sha256::sha256(&self.handshake_messages);
    prf::prf_tls12(&self.master_secret, b"client finished", &hash, 12)
}
```

**Why:** Mocks hide bugs, create false confidence, waste time

**2. ZERO External Protocol Dependencies:**
```toml
# ❌ NEVER add these
hyper = "*"       # We implement HTTP
reqwest = "*"     # We implement HTTP
trust-dns = "*"   # We implement DNS
rustls = "*"      # We implement TLS
tokio = "*"       # We use std threads

# ✅ ONLY allowed
libc = "0.2"      # Syscall FFI bindings
```

**3. We REPLACE, Not WRAP:**
```bash
# ❌ WRONG - Calling external tools
std::process::Command::new("nmap").args(["-p", "80"]).spawn()
std::process::Command::new("openssl").args(["s_client"]).spawn()

# ✅ CORRECT - Implement from scratch
let socket = TcpStream::connect((host, port))?;
let tls = Tls13Client::new().handshake(&socket)?;
```

**4. Mandatory kebab-case for ALL files**

**5. English ONLY - no Portuguese or other languages**

**6. Single documentation file: README.md**

### Performance Constraints

- Binary size target: <3MB (currently 2.7MB)
- Port scan (1-1000): ~2-3s with 200 threads
- Memory: <50MB for typical operations
- No async runtime overhead (use std threads)

### Security & Ethics

**ONLY for authorized use:**
- ✅ Authorized penetration testing
- ✅ CTF competitions
- ✅ Bug bounty programs
- ✅ Own systems security audits
- ✅ Education and research

**NEVER for:**
- ❌ Unauthorized scanning
- ❌ Malicious attacks
- ❌ DoS/DDoS
- ❌ Any illegal activity

**Always obtain written authorization before testing systems you don't own.**

## External Dependencies

**Build-time:**
- Rust toolchain 1.70+ (rustc, cargo)
- No C compiler required (pure Rust)

**Runtime:**
- ZERO external binaries
- ZERO system libraries (except libc which is always present)
- ZERO dynamic dependencies

**Network Services (for testing/validation):**
- DNS servers: 8.8.8.8, 1.1.1.1 (Google/Cloudflare public DNS)
- WHOIS servers: whois.verisign-grs.com, whois.iana.org, etc.
- CT Log servers: For certificate transparency lookups
- Wayback Machine API: For historical URL harvesting
- URLScan/OTX APIs: For OSINT data collection

**Development Tools:**
- `cargo fmt` - Code formatting
- `cargo clippy` - Linting
- `cargo build --release` - Optimized builds
- Git - Version control

**Optional (for contributors):**
- Wireshark/tcpdump - Protocol debugging
- RFC documents - Protocol specifications
- curl/dig - Comparing output with reference implementations
