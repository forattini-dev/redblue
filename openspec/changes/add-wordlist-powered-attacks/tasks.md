# Tasks: Wordlist-Powered Attack Capabilities

## 1. Web Fuzzing Module

### 1.1 Core Fuzzer Engine
- [ ] 1.1.1 Create `src/modules/web/fuzzer/mod.rs` with base fuzzer struct
- [ ] 1.1.2 Implement multi-threaded request dispatcher
- [ ] 1.1.3 Add response collector with deduplication
- [ ] 1.1.4 Implement request throttling/rate limiting

### 1.2 Request Building
- [ ] 1.2.1 URL pattern parsing (FUZZ keyword replacement)
- [ ] 1.2.2 Custom header injection
- [ ] 1.2.3 Cookie support
- [ ] 1.2.4 POST body fuzzing support
- [ ] 1.2.5 Authentication header support (Basic, Bearer)

### 1.3 Response Filtering
- [ ] 1.3.1 Filter by status code (include/exclude)
- [ ] 1.3.2 Filter by response size (min/max)
- [ ] 1.3.3 Filter by word count
- [ ] 1.3.4 Filter by line count
- [ ] 1.3.5 Regex matching in response body
- [ ] 1.3.6 Auto-calibration (baseline detection)

### 1.4 Advanced Features
- [ ] 1.4.1 Recursive directory scanning
- [ ] 1.4.2 Extension fuzzing (-x php,html,js)
- [ ] 1.4.3 Output formats (JSON, CSV, plain)
- [ ] 1.4.4 Resume capability (save/restore state)
- [ ] 1.4.5 Proxy support (HTTP/SOCKS5)

### 1.5 CLI Integration
- [ ] 1.5.1 Create `src/cli/commands/fuzz.rs`
- [ ] 1.5.2 Implement `rb web fuzz <url> -w <wordlist>` command
- [ ] 1.5.3 Add progress display with ETA
- [ ] 1.5.4 Real-time results output

## 2. Subdomain Brute-Force

### 2.1 DNS Brute-Force Engine
- [ ] 2.1.1 Create `src/modules/recon/subdomain-bruteforce.rs`
- [ ] 2.1.2 Implement concurrent DNS resolver pool
- [ ] 2.1.3 Wildcard detection (*.domain.com check)
- [ ] 2.1.4 Retry logic with exponential backoff

### 2.2 Resolver Management
- [ ] 2.2.1 Multi-resolver support (8.8.8.8, 1.1.1.1, etc.)
- [ ] 2.2.2 Resolver health monitoring
- [ ] 2.2.3 Automatic failover on resolver timeout
- [ ] 2.2.4 Custom resolver list support

### 2.3 Result Processing
- [ ] 2.3.1 IP resolution for found subdomains
- [ ] 2.3.2 CNAME chain following
- [ ] 2.3.3 Duplicate elimination
- [ ] 2.3.4 Integration with passive enumeration results

### 2.4 CLI Integration
- [ ] 2.4.1 Implement `rb recon subdomain bruteforce <domain> -w <wordlist>`
- [ ] 2.4.2 Add `--resolvers` flag for custom DNS servers
- [ ] 2.4.3 Add `--wildcard-check` flag
- [ ] 2.4.4 Progress display with statistics

## 3. Credential Testing Module

### 3.1 Core Testing Engine
- [ ] 3.1.1 Create `src/modules/auth/mod.rs`
- [ ] 3.1.2 Create `src/modules/auth/http-auth.rs` for HTTP auth
- [ ] 3.1.3 Implement credential pair iterator (user:pass)
- [ ] 3.1.4 Add rate limiting to avoid lockouts

### 3.2 HTTP Authentication
- [ ] 3.2.1 HTTP Basic authentication testing
- [ ] 3.2.2 HTTP Digest authentication testing
- [ ] 3.2.3 Form-based login testing (POST with CSRF token extraction)
- [ ] 3.2.4 Success/failure detection heuristics

### 3.3 Protocol Support (Future)
- [ ] 3.3.1 SSH password testing (behind feature flag)
- [ ] 3.3.2 FTP authentication testing
- [ ] 3.3.3 SMTP authentication testing

### 3.4 Safety Features
- [ ] 3.4.1 Lockout detection (429, 403, increasing delays)
- [ ] 3.4.2 Account lockout warning
- [ ] 3.4.3 Configurable delay between attempts
- [ ] 3.4.4 Max attempts per account limit

### 3.5 CLI Integration
- [ ] 3.5.1 Implement `rb auth test <target> -u <userlist> -p <passlist>`
- [ ] 3.5.2 Add `--type` flag (basic, digest, form)
- [ ] 3.5.3 Add `--delay` flag for rate limiting
- [ ] 3.5.4 Credential found notification

## 4. Wordlist Enhancements

### 4.1 Native Tar Extraction
- [ ] 4.1.1 Create `src/compression/tar.rs` with USTAR format parser
- [ ] 4.1.2 Implement tar header parsing (name, size, type)
- [ ] 4.1.3 Handle tar.gz files (gzip decompress then tar extract)
- [ ] 4.1.4 Single file extraction from archive

### 4.2 Wordlist Statistics
- [ ] 4.2.1 Implement `rb wordlist info <file>` command
- [ ] 4.2.2 Show line count, unique count, avg length
- [ ] 4.2.3 Character set analysis (alphanumeric, special)
- [ ] 4.2.4 Top N entries preview

### 4.3 Wordlist Operations
- [ ] 4.3.1 Filter by pattern (grep-like)
- [ ] 4.3.2 Filter by length (min/max)
- [ ] 4.3.3 Deduplicate entries
- [ ] 4.3.4 Sort options (alpha, length, frequency)

### 4.4 Wordlist Generation
- [ ] 4.4.1 Basic mutations (capitalize, l33t, append numbers)
- [ ] 4.4.2 Combination attack (word1 + word2)
- [ ] 4.4.3 Rule-based generation (hashcat-style basic rules)
- [ ] 4.4.4 Custom pattern generation

## 5. Documentation & Testing

### 5.1 Integration Tests
- [ ] 5.1.1 Web fuzzer tests against mock server
- [ ] 5.1.2 Subdomain brute-force tests with controlled DNS
- [ ] 5.1.3 Credential testing with mock auth server

### 5.2 Documentation
- [ ] 5.2.1 Update README.md with new commands
- [ ] 5.2.2 Add usage examples for each module
- [ ] 5.2.3 Document wordlist best practices
