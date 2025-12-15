# Change: Complete Agent C2 Architecture (Velociraptor-Inspired)

## Why

redblue already has extensive C2 capabilities implemented:
- **Crypto**: AES-256-GCM, ChaCha20-Poly1305, RSA, X25519, HMAC, HKDF (5,297 lines)
- **Exploit**: Reverse shells (79K lines), Listener (45K lines), PrivEsc (56K lines), Lateral Movement (13K lines)
- **Evasion**: Sandbox detection, AMSI bypass, jitter, string obfuscation (13 files)
- **Collection**: Secrets scanning, credential database (70+ creds), screenshots
- **Proxy**: SOCKS5, HTTP, MITM, TCP/UDP relay
- **Servers**: HTTP server, DNS server

To match Velociraptor's power, we need to complete the architecture with:

1. **Agent-Server Architecture** - Beacon-based C2 protocol
2. **System Accessors** - File, process, network, registry, service interrogation
3. **Playbook Executor** - Structured attack flow execution

## What Changes

### 1. Playbook System Evolution (PARTIAL - recommender done)
- [x] Add playbook recommender (already implemented: `PlaybookRecommender`)
- [ ] Add playbook executor for step-by-step execution
- [ ] Add playbook chaining (one playbook triggers another)
- [ ] Add playbook variables and templates

### 2. System Accessors - NEW
Modules for interrogating target systems (Velociraptor-inspired):
- **File Accessor**: List, read, hash files; search by pattern
- **Process Accessor**: List processes, command lines, parent chains
- **Network Accessor**: Connections, listening ports, ARP cache
- **Registry Accessor**: Windows registry enumeration
- **Service Accessor**: Enumerate services/daemons, startup types

### 3. Agent Architecture - NEW
The missing piece to unify all existing capabilities:
- **Server Mode**: `rb server start` - Orchestration server
- **Agent Mode**: `rb agent connect <server>` - Connects to server with beacon
- **Beacon Protocol**: Configurable check-in intervals, jitter (evasion module exists)
- **Command Routing**: Execute playbooks, accessors, payloads remotely

### 4. Data Collection - Browser Credentials
The secrets module exists, but browser credential extraction is missing:
- **Chrome Credentials**: SQLite + DPAPI/Keychain decryption
- **Firefox Credentials**: logins.json + key4.db decryption
- **SSH Keys**: Already covered by secrets module

## Already Implemented (DO NOT DUPLICATE)

| Feature | Location | Lines |
|---------|----------|-------|
| Crypto primitives | `src/crypto/` | 5,297 |
| Reverse shells (TCP/HTTP/DNS/ICMP/WS/Encrypted) | `src/modules/exploit/payloads.rs` | 79,345 |
| Session listener | `src/modules/exploit/listener.rs` | 45,002 |
| PrivEsc scanner | `src/modules/exploit/privesc.rs` | 56,015 |
| Lateral movement | `src/modules/exploit/lateral-movement.rs` | 13,153 |
| Self-replication | `src/modules/exploit/self_replicate.rs` | 17,911 |
| Evasion suite | `src/modules/evasion/` | 13 files |
| SOCKS5/HTTP/MITM proxy | `src/modules/proxy/` | 19 files |
| Secrets scanning | `src/modules/collection/secrets/` | Full suite |
| Credential database | `src/modules/collection/creds.rs` | 70+ creds |
| Screenshot capture | `src/modules/collection/screenshot/` | CDP-based |
| Netcat + Twofish | `src/modules/network/netcat.rs` | Complete |
| HTTP server | `src/modules/http_server/` | File serving |
| DNS server | `src/modules/dns/server/` | Hijacking rules |

## Impact

- **Affected specs**: `playbooks`, `agent`, `accessors` (new capabilities)
- **Affected code**:
  - `src/playbooks/` - Executor, chaining, templates
  - `src/agent/` - NEW: Server/agent modes
  - `src/accessors/` - NEW: System interrogation modules
  - Integrate with existing `src/modules/exploit/`, `src/modules/evasion/`

## Velociraptor Feature Mapping

| Velociraptor | redblue Status |
|--------------|----------------|
| VQL (Query Language) | NOT NEEDED - use direct accessors |
| Accessors (file, registry, process) | **PROPOSED** |
| Artifacts | Playbooks (partial - executor needed) |
| Client/Server | **PROPOSED** |
| Encrypted gRPC | Crypto ready, transport **PROPOSED** |
| Throttler | Evasion module with jitter **DONE** |
| File Upload | HTTP server + self-serve **DONE** |
| Reverse Shells | 10+ types **DONE** |
| Credential collection | Secrets module **DONE**, browser **PROPOSED** |
| Evasion | Full suite **DONE** |

## Phased Approach

### Phase 1: Playbook Executor (Near-term)
- Complete playbook recommender integration (DONE)
- Add playbook executor with step-by-step execution
- Add playbook variables and templates
- Add playbook chaining

### Phase 2: System Accessors (Medium-term)
- Implement file accessor (list, read, hash, search)
- Implement process accessor (list, tree, cmdline)
- Implement network accessor (connections, ports)
- Implement registry accessor (Windows)
- Implement service accessor (enumeration)

### Phase 3: Agent Architecture (Medium-term)
- Implement server mode with client management
- Implement agent mode with beacon/jitter (leverage evasion module)
- Add beacon protocol over existing transports
- Integrate with existing listener infrastructure

### Phase 4: Browser Credentials (Optional)
- Chrome credential extraction (DPAPI)
- Firefox credential extraction (key4.db)

## Success Criteria

1. Operators can execute playbooks with `rb exploit payload run <playbook>`
2. System accessors return structured data from targets
3. Agents can be deployed and controlled remotely via existing listener
4. All communications leverage existing crypto modules
5. Beacon behavior uses existing evasion jitter
