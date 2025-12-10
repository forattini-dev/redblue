# TLS Domain Documentation

## TL;DR
Tracks our pure-Rust TLS stack, the shipped audits/cipher commands, and the outstanding TLS 1.3 debugging work.

## Overview

The `tls` domain provides comprehensive TLS/SSL security testing, cipher enumeration, and vulnerability scanning capabilities. This domain replaces tools like **openssl s_client**, **testssl.sh**, **sslyze**, and **sslscan**.

**Domain:** `tls`

**Resource:** `security`

**Status:** ✅ Phase 2 (90% Complete)

---

## Implementation Status (Nov 2025)

### TLS 1.2 Stack – Complete
- Pure Rust RSA PKCS#1 v1.5, big integer math, AES-128-CBC, SHA-256, HMAC, and the TLS 1.2 PRF now live under `src/crypto/`.
- `src/modules/network/tls.rs` drives the full handshake: ClientHello → Certificate parsing → ClientKeyExchange → ChangeCipherSpec → Finished.
- Release binaries weigh ~2.6 MB with `[dependencies]` empty; no external crypto crates or system binaries are required.
- End-to-end coverage resides in `tests/crypto_integration_test.rs` plus targeted unit suites (RFC 5246, RFC 6234, RFC 8017) and passes via `cargo test`.

### AES-128-GCM & TLS 1.3 Ciphersuites
- `src/crypto/aes_gcm.rs` implements AES-128-GCM with constant-time tag checks and NIST SP 800-38D vectors (`tests/aes128_gcm_nist.rs`, `tests/aes128_gcm_basic.rs`).
- TLS 1.3 integration adds `CipherSuite::TlsAes128GcmSha256 (0x1301)` alongside AES-256 and ChaCha20 suites, matching browser capabilities.
- Counter handling follows RFC 8446 (inc32 on the low 32 bits) and GHASH/AAD assembly mirrors the specification; RFC sample mismatches were traced to vector issues rather than the cipher.

### Cryptographic Workload Snapshot
- ~1.7 k lines of crypto across AES, RSA, GHASH, PRF, and helpers; ~2.2 k including TLS stream glue.
- 25 dedicated tests (unit + integration) cover HKDF, SHA-256, AES-GCM, RSA padding, and handshake key schedules.
- Build validation: `cargo build --release`, `cargo test aes128`, `cargo test --test aes128_gcm_nist`, `cargo test --test crypto_integration_test`.

### TLS 1.3 Investigation
- Verified pieces: SHA-256 transcript hashing (matches `sha256sum`), HKDF-Extract/Expand-Label (RFC 8448 vectors), ChaCha20-Poly1305, AES-GCM, and Poly1305 (`tests/tls13_rfc8448_vectors.rs`, `tests/chacha20_test_vectors.rs`).
- Current failure: Google TLS 1.3 hosts reject our decrypted EncryptedExtensions with “bad record MAC” even when swapping in the `aes-gcm` crate—pointing at ciphertext usage rather than primitive correctness.
- Transcript comparisons with OpenSSL confirm structural parity (session IDs differ—allowed). Cipher choice (`0x1302`) and message ordering align.
- Root cause highlight: an in-house X25519 bug produced incorrect shared secrets; temporarily using `x25519-dalek` unlocked the rest of the stack. We still need a pure Rust X25519 fix before shipping.

### Next Actions
- Capture byte-for-byte logs from `hkdf_expand_label()` and diff the constructed `HkdfLabel` against OpenSSL output.
- Port RFC 8448 Section 3 encrypted records into `tests/tls13_encrypted_extensions.rs` using AES-128-GCM to exercise decrypt paths with known secrets.
- Collect Wireshark traces plus SSLKEYLOGFILE output from redblue and curl for side-by-side decryption attempts.
- Test against additional TLS 1.3 endpoints (`tls13.ulfheim.net`, `cloudflare.com`) to confirm whether the failure is provider-specific.

---

## Resource: `tls security`

**Description:** TLS/SSL security auditing, cipher suite enumeration, and vulnerability detection for HTTPS services.

### Commands

#### 1. `audit` - Full TLS Security Audit

Perform a comprehensive TLS security audit including version detection, cipher enumeration, vulnerability scanning, and certificate validation (sslyze replacement).

**Syntax:**
```bash
rb tls security audit <host[:port]> [FLAGS]
```

**Arguments:**
- `<host[:port]>` - Target hostname or IP address with optional port (required)
  - Default port: `443`

**Flags:**
- `--timeout <seconds>` - Connection timeout in seconds (default: 10)
- `--port <port>` - Target port (default: 443)
- `-o, --output <format>` - Output format: `text`, `json` (default: text)
- `--persist` - Save results to binary database (.rdb file)
- `--no-persist` - Don't save results (overrides config)

**What It Audits:**

1. **TLS Protocol Versions** - TLS 1.3, 1.2, 1.1, 1.0, SSL 3.0
2. **Cipher Suites** - Strong (AES-GCM, ChaCha20), Medium (AES-CBC), Weak (RC4, 3DES)
3. **Vulnerabilities** - POODLE, BEAST, Heartbleed, CRIME, FREAK, Logjam, DROWN, Sweet32
4. **Certificate Validation** - Chain validity, expiration, self-signed detection

**Examples:**

```bash
# Basic TLS audit
rb tls security audit google.com

# Audit with custom port
rb tls security audit example.com:8443

# JSON output with persistence
rb tls security audit api.example.com -o json --persist
```

**Sample Output:**

```
Running TLS audit... ✓

🔒 TLS Security Audit: google.com:443

Supported TLS Versions
  ✓ TLS 1.3
  ✓ TLS 1.2
  ✗ TLS 1.1 (Connection refused)
  ✗ TLS 1.0 (Connection refused)

Supported Cipher Suites (15)
  ● STRONG TLS_AES_128_GCM_SHA256 (0x1301)
  ● STRONG TLS_AES_256_GCM_SHA384 (0x1302)
  ● STRONG TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  ● STRONG TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
  ... (11 more)

✓ No known vulnerabilities detected

Certificate Validation
  ✓ Certificate chain is valid
  Chain length: 3 certificate(s)
```

---

#### 2. `ciphers` - Cipher Suite Enumeration

Enumerate all supported TLS cipher suites grouped by strength (sslscan replacement).

**Syntax:**
```bash
rb tls security ciphers <host[:port]> [FLAGS]
```

**Arguments:**
- `<host[:port]>` - Target hostname or IP address (required)

**Flags:**
- `--timeout <seconds>` - Connection timeout (default: 10)
- `--port <port>` - Target port (default: 443)
- `-o, --output <format>` - Output format: `text`, `json`
- `--persist` - Save results to database

**Cipher Strength:**

- **Strong (Green ✓):** AES-GCM, ChaCha20-Poly1305, ECDHE/DHE
- **Medium (Yellow ●):** AES-CBC, SHA256, RSA key exchange
- **Weak (Red ✗):** RC4, 3DES, export ciphers, NULL encryption

**Examples:**

```bash
# Basic cipher enumeration
rb tls security ciphers google.com

# Custom port
rb tls security ciphers example.com:8443

# Save to database
rb tls security ciphers target.com --persist
```

**Sample Output:**

```
Enumerating cipher suites... ✓

🔐 TLS Cipher Enumeration: google.com:443

Cipher Suites Summary (Total: 15)
  ● Strong:  12
  ● Medium:  3
  ● Weak:    0

Strong Ciphers
  ✓ TLS_AES_128_GCM_SHA256 (0x1301)
  ✓ TLS_AES_256_GCM_SHA384 (0x1302)
  ✓ TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  ... (9 more)

Medium Strength Ciphers
  ● TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)
  ● TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028)
  ● TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)
```

---

#### 3. `vuln` - TLS Vulnerability Scanner

Scan for known TLS/SSL vulnerabilities (testssl.sh replacement).

**Syntax:**
```bash
rb tls security vuln <host[:port]> [FLAGS]
```

**Arguments:**
- `<host[:port]>` - Target hostname or IP address (required)

**Flags:**
- `--timeout <seconds>` - Connection timeout (default: 10)
- `--port <port>` - Target port (default: 443)
- `-o, --output <format>` - Output format: `text`, `json`
- `--persist` - Save results to database

**Vulnerabilities Detected:**

| Vulnerability | CVE | Severity |
|---------------|-----|----------|
| POODLE | CVE-2014-3566 | CRITICAL |
| BEAST | CVE-2011-3389 | HIGH |
| Heartbleed | CVE-2014-0160 | CRITICAL |
| CRIME | CVE-2012-4929 | MEDIUM |
| FREAK | CVE-2015-0204 | HIGH |
| Logjam | CVE-2015-4000 | HIGH |
| DROWN | CVE-2016-0800 | CRITICAL |
| Sweet32 | CVE-2016-2183 | MEDIUM |

**Examples:**

```bash
# Basic vulnerability scan
rb tls security vuln google.com

# Scan custom port
rb tls security vuln mail.example.com:465

# JSON output
rb tls security vuln example.com -o json
```

**Sample Output (Secure):**

```
Scanning for TLS vulnerabilities... ✓

🛡️ TLS Vulnerability Scan: google.com:443

✓ No known TLS vulnerabilities detected
  The TLS configuration appears secure
```

**Sample Output (Vulnerable):**

```
🛡️ TLS Vulnerability Scan: vulnerable.example.com:443

Vulnerability Summary (Total: 5)
  🔴 Critical:  2
  🔴 High:      2
  🟡 Medium:    1

CRITICAL Vulnerabilities (2)
  🔴 POODLE (CVE-2014-3566)
    SSL 3.0 is enabled and vulnerable to padding oracle attack.
    Remediation: Disable SSL 3.0 entirely

  🔴 DROWN (CVE-2016-0800)
    SSLv2 protocol is enabled, allowing cross-protocol attacks.
    Remediation: Disable SSLv2 and SSLv3

HIGH Vulnerabilities (2)
  🔴 BEAST (CVE-2011-3389)
    TLS 1.0 with CBC ciphers is vulnerable.
    Remediation: Disable TLS 1.0 or use AES-GCM only

  🔴 Weak Cipher Suites
    RC4 and 3DES ciphers are enabled.
    Remediation: Remove weak ciphers from configuration

MEDIUM Vulnerabilities (1)
  🟡 TLS 1.0 Enabled
    TLS 1.0 is deprecated.
    Remediation: Set minimum to TLS 1.2

Overall Security Grade: F
```

---

## Configuration

```yaml
tls:
  default_port: 443
  timeout: 10
  min_tls_version: "1.2"
  auto_persist: false
```

---

## Common Use Cases

### 1. Quick Security Check

```bash
rb tls security audit api.example.com
rb tls security vuln api.example.com
```

### 2. Compliance Audit (PCI-DSS)

```bash
rb tls security audit payment.example.com --persist
rb database data export payment.example.com.rdb
```

### 3. Bug Bounty Testing

```bash
for sub in $(cat subdomains.txt); do
  rb tls security vuln "$sub" --persist
done
```

### 4. Server Hardening Validation

```bash
# Before hardening
rb tls security audit server.example.com -o json > before.json

# After hardening
rb tls security audit server.example.com -o json > after.json

# Compare
diff before.json after.json
```

---

## Tool Equivalents

| Traditional Tool | redblue Command | Notes |
|-----------------|----------------|-------|
| **openssl s_client** | `rb tls security audit` | Full TLS testing |
| **testssl.sh** | `rb tls security vuln` | Vulnerability scanning |
| **sslyze** | `rb tls security audit` | Comprehensive auditing |
| **sslscan** | `rb tls security ciphers` | Cipher enumeration |

---

## Security Best Practices

**Recommended Configuration:**
- ✅ TLS 1.2+ minimum (TLS 1.3 preferred)
- ✅ Strong ciphers only (AES-GCM, ChaCha20)
- ✅ Forward secrecy (ECDHE)
- ❌ No SSL 3.0, TLS 1.0, TLS 1.1
- ❌ No weak ciphers (RC4, 3DES, export)

**Example Nginx:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
```

---

## See Also

- [WEB Domain](/domains/web.md) - HTTP security headers
- [NETWORK Domain](/domains/network.md) - Port scanning
- [RECON Domain](/domains/recon.md) - Certificate Transparency

**External Resources:**
- SSL Labs: https://www.ssllabs.com/ssltest/
- Mozilla SSL Config: https://ssl-config.mozilla.org/

---

**Supported Ports:** 443 (HTTPS), 465 (SMTPS), 993 (IMAPS), 995 (POP3S), 8443, or custom.
