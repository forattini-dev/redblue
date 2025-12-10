# AUTH Domain Documentation

## TL;DR
The `auth` domain provides tools for credential testing against various services, mimicking common bruteforce and dictionary attack techniques.

## Overview

The `auth` domain focuses on testing authentication mechanisms, primarily through credential bruteforcing and dictionary attacks against HTTP, SSH, FTP, and SMTP services. It includes features for rate limiting, lockout detection, and integration with wordlists.

**Domain:** `auth`

**Resource:** `test`

**Status:** ✅ Phase 3 (Implemented)

---

## Implementation Status (Nov 2025)

### Current Capabilities
- HTTP Basic/Digest/Form authentication testing.
- Integration with local wordlists (userlist, passlist).
- Configurable rate limiting and delay controls.
- Lockout detection (based on status codes and increasing delays).
- Credential pair iteration and success notification.
- Placeholder implementations for SSH, FTP, and SMTP testing (behind feature flags).

### Known Gaps
- Advanced form parsing for complex login flows.
- More sophisticated lockout detection heuristics.
- Support for more authentication protocols (e.g., NTLM, Kerberos).

---

## Resource: `auth test`

**Description:** Test credentials against target services.

### Commands

#### 1. `http` - HTTP Authentication Testing

Test HTTP Basic, Digest, or Form-based authentication against a target URL.

**Syntax:**
```bash
rb auth test http <target-url> -u <userlist> -p <passlist> [FLAGS]
```

**Arguments:**
- `<target-url>` - Target HTTP/HTTPS URL (required)

**Flags:**
- `-u, --userlist <file>` - Path to a wordlist of usernames (required)
- `-p, --passlist <file>` - Path to a wordlist of passwords (required)
- `--type <method>` - Authentication method: `basic`, `digest`, `form`
  - Default: `basic`
- `--delay <ms>` - Delay between attempts in milliseconds
  - Default: `0` (no delay)
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`

**Features:**
- **HTTP Basic Authentication**: Tests credentials using the standard Basic Auth header.
- **HTTP Digest Authentication**: (Placeholder) Will support Digest Auth challenge-response.
- **Form-based Login**: (Placeholder) Will support POSTing credentials to a form, including CSRF token extraction.
- **Rate Limiting**: Configurable delay to avoid triggering server-side rate limits.
- **Lockout Detection**: Detects common HTTP status codes (401, 403, 429) that indicate an account lockout or temporary block.
- **Credential Iterator**: Efficiently generates username-password pairs from wordlists.

**Examples:**

```bash
# Test HTTP Basic Auth against an admin panel
rb auth test http https://example.com/admin/ -u users.txt -p common_passwords.txt --type basic

# Test with a delay to avoid rate limits
rb auth test http http://intranet.local/login -u users.txt -p pass.txt --delay 500

# JSON output
rb auth test http https://example.com/api/login -u users.txt -p pass.txt -o json
```

**Sample Output (Text - Success):**

```
🔓 Auth Test: https://example.com/admin/

  Auth Type: Basic
  Userlist: users.txt (100 entries)
  Passlist: common_passwords.txt (1000 entries)

Starting credential testing...

Attempting user: admin, pass: password123
Attempting user: admin, pass: P@ssw0rd!
...

✅ Found credentials: admin:P@ssw0rd!
```

**Sample Output (Text - Lockout):**

```
🔓 Auth Test: https://example.com/admin/

  Auth Type: Basic
  Userlist: users.txt (100 entries)
  Passlist: common_passwords.txt (1000 entries)

Starting credential testing...

Attempting user: admin, pass: 12345
Attempting user: admin, pass: 54321
...
⚠️  Lockout detected (HTTP 429 Too Many Requests). Increasing delay.
```

---

## Configuration

The AUTH domain uses project-level configuration from `.redblue.yaml`:

```yaml
auth:
  # Default thread count for credential testing
  threads: 5

  # Default delay between requests in milliseconds
  delay_ms: 100

  # Max attempts before pausing/reporting lockout
  max_attempts_per_account: 5
```

---

## Technical Details

### HTTP Authentication

**Basic Auth:** Uses `Authorization: Basic <base64(user:pass)>` header.
**Digest Auth:** (Planned) Implements HTTP Digest challenge-response.
**Form-based:** (Planned) Submits POST requests with form parameters, handles CSRF tokens.

### Rate Limiting & Lockout

- Exponential backoff strategy.
- Monitors HTTP status codes (401, 403, 429) for lockout indicators.
- Configurable delays and max attempts to prevent account lockouts.

---

## See Also

- [WORDLIST Domain](./WORDLIST.md) - Wordlist generation and management
- [NETWORK Domain](./NETWORK.md) - Network discovery and port scanning

---
