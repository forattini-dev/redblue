# Change: Add Wordlist-Powered Attack Capabilities

## Why

With native gzip decompression and SecLists integration now complete, redblue can leverage 2.5GB of security wordlists for offensive operations. Currently, wordlists are downloaded but not used by any attack module. This change adds the core attack capabilities that make wordlists valuable: web fuzzing (ffuf/gobuster replacement), subdomain brute-force (amass/subfinder replacement), and credential testing (hydra-lite replacement).

## What Changes

- **Web Fuzzing Module** (`rb web fuzz`): Directory/file discovery using wordlists
  - Replaces: ffuf, gobuster, feroxbuster, dirsearch, dirb
  - Multi-threaded requests with configurable concurrency
  - Response filtering by status code, size, word count
  - Recursive directory scanning
  - Custom headers, cookies, authentication support

- **Subdomain Brute-Force** (`rb recon subdomain bruteforce`): DNS-based subdomain enumeration
  - Replaces: amass brute, fierce, dnsrecon
  - Uses DNS wordlists from SecLists
  - Wildcard detection to avoid false positives
  - Multi-resolver support for speed
  - Integration with existing passive subdomain enumeration

- **Credential Testing** (`rb auth test`): Basic authentication testing
  - Replaces: hydra (basic), medusa (basic), ncrack (basic)
  - HTTP Basic/Digest auth testing
  - Form-based login testing
  - SSH password testing (optional, requires feature flag)
  - Rate limiting and lockout detection

- **Wordlist Management Enhancements**:
  - Native tar extraction (for rockyou.txt.tar.gz)
  - Wordlist statistics and preview
  - Custom wordlist generation (mutations, combinations)
  - Wordlist search/filtering

## Impact

- Affected specs: web, recon, auth (new capability)
- Affected code:
  - `src/modules/web/fuzzer.rs` - New web fuzzer implementation
  - `src/modules/recon/subdomain.rs` - Add brute-force capability
  - `src/modules/auth/` - New authentication testing module
  - `src/wordlists/` - Enhanced wordlist management
  - `src/cli/commands/` - New CLI commands
  - `src/compression/tar.rs` - Native tar extraction
