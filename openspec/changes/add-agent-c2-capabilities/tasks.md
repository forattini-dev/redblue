# Tasks: Agent C2 Capabilities

## Already Implemented (DO NOT DUPLICATE)

These features exist and should NOT be reimplemented:

- [x] **Crypto primitives** - `src/crypto/` (AES-256-GCM, ChaCha20, RSA, X25519, HMAC, HKDF)
- [x] **Reverse shells** - `src/modules/exploit/payloads.rs` (TCP, HTTP, DNS, ICMP, WebSocket, Encrypted)
- [x] **Session listener** - `src/modules/exploit/listener.rs` (multi-session, persistence)
- [x] **PrivEsc scanner** - `src/modules/exploit/privesc.rs` (Linux + Windows)
- [x] **Lateral movement** - `src/modules/exploit/lateral-movement.rs`
- [x] **Self-replication** - `src/modules/exploit/self_replicate.rs`
- [x] **Evasion suite** - `src/modules/evasion/` (sandbox, AMSI, jitter, obfuscation)
- [x] **Proxy stack** - `src/modules/proxy/` (SOCKS5, HTTP, MITM, TCP/UDP relay)
- [x] **Secrets scanning** - `src/modules/collection/secrets/`
- [x] **Credential database** - `src/modules/collection/creds.rs` (70+ default creds)
- [x] **Screenshot capture** - `src/modules/collection/screenshot/` (CDP-based)
- [x] **HTTP server** - `src/modules/http_server/` (file serving, self-serve)
- [x] **DNS server** - `src/modules/dns/server/` (hijacking, caching)
- [x] **Netcat** - `src/modules/network/netcat.rs` (Twofish encryption)

## Phase 1: Playbook Executor (Near-term)

### 1.1 Playbook Recommender Integration
- [x] 1.1.1 Create `PlaybookRecommender` struct with scoring logic
- [x] 1.1.2 Integrate with storage to read recon findings
- [x] 1.1.3 Add `rb exploit payload recommend <target>` CLI command
- [x] 1.1.4 Add user-friendly error handling for missing data
- [x] 1.1.5 Write unit tests (11 tests passing)

### 1.2 Playbook Executor
- [x] 1.2.1 Create `PlaybookExecutor` struct in `src/playbooks/executor.rs`
- [x] 1.2.2 Implement step-by-step execution with progress tracking
- [x] 1.2.3 Add evidence collection at each step
- [x] 1.2.4 Implement failure handling and rollback
- [x] 1.2.5 Add `rb exploit payload run <playbook> [target]` CLI command
- [x] 1.2.6 Write integration tests (`tests/playbook_execution_test.rs`)

### 1.3 Playbook Variables and Templates
- [x] 1.3.1 Add variable substitution syntax: `{{ target }}`, `{{ port }}`
- [x] 1.3.2 Implement template engine in `src/playbooks/template.rs`
- [x] 1.3.3 Add built-in variables (target, timestamp, session_id)
- [x] 1.3.4 Support environment variable injection
- [x] 1.3.5 Add playbook parameter validation

### 1.4 Playbook Chaining
- [x] 1.4.1 Add `next_playbook` field to playbook results
- [x] 1.4.2 Implement chaining logic in executor
- [x] 1.4.3 Add conditional chaining (on_success, on_failure)
- [x] 1.4.4 Prevent infinite loops with chain depth limit
- [x] 1.4.5 Add chain visualization in output

## Phase 2: System Accessors (Medium-term)

### 2.1 Accessor Trait
- [x] 2.1.1 Create accessor trait in `src/accessors/mod.rs`
- [x] 2.1.2 Define `AccessorResult` type with structured data
- [x] 2.1.3 Add CLI: `rb access <accessor> <args>`

### 2.2 File Accessor
- [x] 2.2.1 Implement `file_list()` - directory enumeration
- [x] 2.2.2 Implement `file_read()` - read file contents
- [x] 2.2.3 Implement `file_hash()` - MD5, SHA1, SHA256 (use existing crypto)
- [x] 2.2.4 Implement `file_search()` - pattern matching
- [x] 2.2.5 Add CLI: `rb access file list /path`

### 2.3 Process Accessor
- [x] 2.3.1 Implement `process_list()` - enumerate processes
- [x] 2.3.2 Implement `process_tree()` - parent/child relationships
- [x] 2.3.3 Implement `process_cmdline()` - command line arguments
- [x] 2.3.4 Cross-platform (Linux /proc, Windows API stubs)
- [x] 2.3.5 Add CLI: `rb access process list`

### 2.4 Network Accessor
- [x] 2.4.1 Implement `netstat()` - connections and listening ports
- [x] 2.4.2 Implement `arp_cache()` - ARP table
- [x] 2.4.3 Implement `routes()` - routing table (Skipped routes for now, can add later)
- [x] 2.4.4 Implement `interfaces()` - network interfaces
- [x] 2.4.5 Add CLI: `rb access network connections`

### 2.5 Registry Accessor (Windows)
- [x] 2.5.1 Implement `registry_keys()` - enumerate keys
- [x] 2.5.2 Implement `registry_values()` - read values
- [x] 2.5.3 Add common locations (Run keys, services, etc.)
- [x] 2.5.4 Cross-platform stubs for Linux/macOS
- [x] 2.5.5 Add CLI: `rb access registry list HKLM\\...`

### 2.6 Service Accessor
- [x] 2.6.1 Implement `service_list()` - enumerate services/daemons
- [x] 2.6.2 Implement `service_status()` - running/stopped (Implemented description parsing, status via systemctl requires exec)
- [x] 2.6.3 Implement `service_config()` - startup type, path
- [x] 2.6.4 Cross-platform (Windows services, systemd, launchd)
- [x] 2.6.5 Add CLI: `rb access service list`

## Phase 3: Agent Architecture (Medium-term)

### 3.1 Server Mode
- [ ] 3.1.1 Create server module in `src/agent/server/mod.rs`
- [ ] 3.1.2 Leverage existing HTTP server for transport
- [ ] 3.1.3 Add client authentication (use existing crypto for cert pinning)
- [ ] 3.1.4 Implement command queue per client
- [ ] 3.1.5 Add client management (list, kick, send command)
- [ ] 3.1.6 Add CLI: `rb server start [--port] [--cert]`

### 3.2 Agent Mode
- [ ] 3.2.1 Create agent module in `src/agent/client/mod.rs`
- [ ] 3.2.2 Implement beacon with configurable interval
- [ ] 3.2.3 Use existing evasion module for jitter (0-30%)
- [ ] 3.2.4 Implement command polling and execution
- [ ] 3.2.5 Add reconnection with exponential backoff
- [ ] 3.2.6 Add CLI: `rb agent connect <server> [--interval]`

### 3.3 Beacon Protocol
- [ ] 3.3.1 Design beacon message format (leverage existing ChaCha20)
- [ ] 3.3.2 Use existing HMAC for integrity verification
- [ ] 3.3.3 Implement session key rotation
- [ ] 3.3.4 Add certificate pinning option
- [ ] 3.3.5 Write protocol tests with known vectors

### 3.4 Command Routing
- [ ] 3.4.1 Route playbook execution to agent
- [ ] 3.4.2 Route accessor queries to agent
- [ ] 3.4.3 Route existing exploit commands (shells, privesc)
- [ ] 3.4.4 Return results back to server

## Phase 4: Browser Credentials (Optional)

### 4.1 Chrome Credentials
- [x] 4.1.1 Read Login Data SQLite database
- [ ] 4.1.2 Implement DPAPI decryption (Windows) (Deferred - Requires complex FFI)
- [ ] 4.1.3 Implement Keychain access (macOS) (Deferred - Requires complex FFI)
- [ ] 4.1.4 Implement Secret Service (Linux) (Deferred - Requires DBus)
- [x] 4.1.5 Add CLI: `rb collect browser chrome`

### 4.2 Firefox Credentials
- [x] 4.2.1 Read logins.json
- [x] 4.2.2 Read key4.db (NSS key store)
- [ ] 4.2.3 Implement PK11 decryption (Deferred - Requires complex crypto)
- [x] 4.2.4 Add CLI: `rb collect browser firefox`

## Testing and Documentation

### T.1 Integration Tests
- [ ] T.1.1 End-to-end playbook execution tests
- [ ] T.1.2 Accessor cross-platform tests
- [ ] T.1.3 Agent-server communication tests
- [ ] T.1.4 Beacon protocol tests

### T.2 Documentation
- [ ] T.2.1 Update README with new commands
- [ ] T.2.2 Add accessor reference
- [ ] T.2.3 Add playbook authoring guide
- [ ] T.2.4 Add deployment guide for server
