# redblue CLI Command Reference

Complete map of all `rb` commands organized by domain.

```
rb <domain> <resource> <verb> [target] [flags]
```

---

## Offensive (AUTHORIZED USE ONLY)

### `attack` - Complete Attack Workflow

| Command | Description |
|---------|-------------|
| `rb attack target plan <url>` | Generate attack plan |
| `rb attack target run <url>` | Execute complete workflow |
| `rb attack target playbooks` | List available playbooks |
| `rb attack target apt <url>` | Simulate APT campaign |

### `agent` - C2 (Command & Control)

| Command | Description |
|---------|-------------|
| `rb agent c2 server [--port]` | Start C2 server |
| `rb agent c2 connect <url>` | Connect as agent |

### `access` - Remote Access

| Command | Description |
|---------|-------------|
| `rb access system file` | File operations |
| `rb access system process` | Process manipulation |
| `rb access system network` | Network operations |
| `rb access system service` | Service management |
| `rb access system registry` | Registry operations (Windows) |

### `exploit` - Exploitation Framework

| Command | Description |
|---------|-------------|
| `rb exploit payload plan` | Plan exploitation |
| `rb exploit payload suggest` | Suggest exploits |
| `rb exploit payload recommend` | Recommend payloads |
| `rb exploit payload run` | Execute exploit |
| `rb exploit payload privesc` | Privilege escalation |
| `rb exploit payload shell` | Reverse shell |
| `rb exploit payload http-shell` | HTTP-based shell |
| `rb exploit payload dns-shell` | DNS tunneling shell |
| `rb exploit payload multi-shell` | Multi-stage shell |
| `rb exploit payload encrypted-shell` | Encrypted C2 shell |
| `rb exploit payload icmp-shell` | ICMP-based shell |
| `rb exploit payload websocket-shell` | WebSocket shell |
| `rb exploit payload listener` | Start listener |
| `rb exploit payload start` | Start payload server |
| `rb exploit payload sessions` | Manage sessions |
| `rb exploit payload lateral` | Lateral movement |
| `rb exploit payload persist` | Persistence mechanisms |
| `rb exploit payload replicate` | Self-replication |
| `rb exploit payload playbooks` | Exploitation playbooks |
| `rb exploit payload apt` | APT simulation |

### `exploit browser` - Browser Exploitation (RBB)

| Command | Description |
|---------|-------------|
| `rb exploit browser serve` | Serve exploits |
| `rb exploit browser list` | List modules |
| `rb exploit browser exec` | Execute in session |

### `mitm` - Man-in-the-Middle

| Command | Description |
|---------|-------------|
| `rb mitm intercept start` | Start MITM |
| `rb mitm intercept proxy` | Transparent proxy |
| `rb mitm intercept dns` | DNS hijacking |
| `rb mitm intercept generate-ca` | Generate CA certificate |
| `rb mitm intercept export-ca` | Export CA |
| `rb mitm intercept shell` | Interactive shell |

---

## Evasion (AV/EDR Bypass)

### `evasion sandbox` - Sandbox Detection

| Command | Description |
|---------|-------------|
| `rb evasion sandbox check` | Check environment |
| `rb evasion sandbox score` | Detection score |
| `rb evasion sandbox delay` | Sleep evasion |

### `evasion obfuscate` - Obfuscation

| Command | Description |
|---------|-------------|
| `rb evasion obfuscate xor` | XOR encoding |
| `rb evasion obfuscate base64` | Base64 encoding |
| `rb evasion obfuscate rot` | ROT encoding |
| `rb evasion obfuscate deobfuscate` | Reverse |

### `evasion network` - Network Evasion

| Command | Description |
|---------|-------------|
| `rb evasion network jitter` | Traffic jitter |
| `rb evasion network timer` | Timing evasion |
| `rb evasion network shape` | Traffic shaping |

### `evasion config` - Presets

| Command | Description |
|---------|-------------|
| `rb evasion config show` | Show config |
| `rb evasion config default` | Default preset |
| `rb evasion config stealth` | Stealth preset |
| `rb evasion config aggressive` | Aggressive preset |

### `evasion build` - Binary Mutation

| Command | Description |
|---------|-------------|
| `rb evasion build info` | Binary info |
| `rb evasion build obfuscate` | Obfuscate binary |
| `rb evasion build deobfuscate` | Reverse |

### `evasion antidebug` - Anti-Debugging

| Command | Description |
|---------|-------------|
| `rb evasion antidebug check` | Check debugger |
| `rb evasion antidebug quick` | Quick check |
| `rb evasion antidebug paranoid` | Deep check |

### `evasion memory` - Memory Encryption

| Command | Description |
|---------|-------------|
| `rb evasion memory encrypt` | Encrypt memory |
| `rb evasion memory demo` | Demo |
| `rb evasion memory rotate` | Rotate keys |
| `rb evasion memory vault` | Secure vault |

### `evasion apihash` - API Hashing

| Command | Description |
|---------|-------------|
| `rb evasion apihash hash` | Hash API name |
| `rb evasion apihash list` | List hashes |
| `rb evasion apihash syscalls` | Direct syscalls |

### `evasion controlflow` - Control Flow Obfuscation

| Command | Description |
|---------|-------------|
| `rb evasion controlflow demo` | Demo |
| `rb evasion controlflow predicates` | Opaque predicates |
| `rb evasion controlflow substitute` | Instruction substitution |

### `evasion inject` - Process Injection

| Command | Description |
|---------|-------------|
| `rb evasion inject shellcode` | Inject shellcode |
| `rb evasion inject encode` | Encode payload |
| `rb evasion inject list` | List techniques |

### `evasion amsi` - AMSI Bypass (Windows)

| Command | Description |
|---------|-------------|
| `rb evasion amsi powershell` | PowerShell bypass |
| `rb evasion amsi csharp` | C# bypass |
| `rb evasion amsi obfuscated` | Obfuscated bypass |
| `rb evasion amsi providers` | List providers |

### `evasion strings` - String Encryption

| Command | Description |
|---------|-------------|
| `rb evasion strings encrypt` | Encrypt strings |
| `rb evasion strings sensitive` | Detect sensitive |
| `rb evasion strings demo` | Demo |

### `evasion tracks` - Track Covering

| Command | Description |
|---------|-------------|
| `rb evasion tracks scan` | Scan for tracks |
| `rb evasion tracks clear` | Clear traces |
| `rb evasion tracks sessions` | Clear sessions |
| `rb evasion tracks command` | Clear command history |

---

## Reconnaissance

### `recon domain` - Domain Intelligence

| Command | Description |
|---------|-------------|
| `rb recon domain full <domain>` | Full recon |
| `rb recon domain show <domain>` | Show stored data |
| `rb recon domain whois <domain>` | WHOIS lookup |
| `rb recon domain rdap <domain>` | RDAP query |
| `rb recon domain subdomains <domain>` | Subdomain enum |
| `rb recon domain harvest <domain>` | Harvest emails/data |
| `rb recon domain urls <domain>` | URL extraction |
| `rb recon domain osint <domain>` | OSINT gathering |
| `rb recon domain email <domain>` | Email discovery |
| `rb recon domain asn <domain>` | ASN lookup |
| `rb recon domain breach <domain>` | Breach check |
| `rb recon domain secrets <domain>` | Secret scanning |
| `rb recon domain dorks <domain>` | Google dorks |
| `rb recon domain social <domain>` | Social media |
| `rb recon domain vuln <domain>` | Vuln lookup |
| `rb recon domain dnsdumpster <domain>` | DNSDumpster query |
| `rb recon domain massdns <domain>` | MassDNS resolution |
| `rb recon domain list` | List stored |
| `rb recon domain get <domain>` | Get specific |
| `rb recon domain describe <domain>` | Detailed view |
| `rb recon domain graph <domain>` | Attack graph |

### `recon identity` - Identity OSINT

| Command | Description |
|---------|-------------|
| `rb recon identity username <user>` | Username lookup |
| `rb recon identity email <email>` | Email lookup |
| `rb recon identity breach <query>` | Breach check |

### `recon username` - Username Search (Legacy)

| Command | Description |
|---------|-------------|
| `rb recon username search <user>` | Search username |
| `rb recon username check <user>` | Check availability |

---

## Network

### `network ports` - Port Scanning

| Command | Description |
|---------|-------------|
| `rb network ports scan <target>` | TCP scan (presets) |
| `rb network ports range <t> <s> <e>` | Range scan |
| `rb network ports syn-scan <target>` | SYN scan (raw) |
| `rb network ports udp-scan <target>` | UDP scan |
| `rb network ports stealth <target>` | Stealth scan |
| `rb network ports subnet <cidr>` | Subnet scan |

### `network host` - Host Operations

| Command | Description |
|---------|-------------|
| `rb network host ping <target>` | ICMP ping |
| `rb network host discover <cidr>` | Host discovery |
| `rb network host fingerprint <target>` | OS fingerprint |
| `rb network host list` | List stored |
| `rb network host intel <target>` | Host intelligence |

### `network trace` - Traceroute

| Command | Description |
|---------|-------------|
| `rb network trace run <target>` | Traceroute |
| `rb network trace mtr <target>` | MTR (live) |

### `network health` - Port Health Monitoring

| Command | Description |
|---------|-------------|
| `rb network health check <target>` | Health check |
| `rb network health diff <target>` | Diff from last |
| `rb network health watch <target>` | Continuous watch |

### `network nc` - Netcat

| Command | Description |
|---------|-------------|
| `rb network nc listen <port>` | Listen mode |
| `rb network nc connect <host> <port>` | Connect mode |
| `rb network nc scan <target> <ports>` | Quick scan |
| `rb network nc relay <src> <dst>` | Port relay |
| `rb network nc broker` | Connection broker |

---

## DNS

### `dns record` - DNS Queries

| Command | Description |
|---------|-------------|
| `rb dns record lookup <domain>` | DNS lookup |
| `rb dns record all <domain>` | All record types |
| `rb dns record resolve <domain>` | Quick resolve |
| `rb dns record reverse <ip>` | Reverse DNS |
| `rb dns record bruteforce <domain>` | Subdomain brute |
| `rb dns record propagation <domain>` | Check propagation |
| `rb dns record email <domain>` | Email records |
| `rb dns record list` | List stored |
| `rb dns record get <domain>` | Get specific |
| `rb dns record describe <domain>` | Detailed view |

### `dns server` - DNS Server

| Command | Description |
|---------|-------------|
| `rb dns server start` | Start DNS server |
| `rb dns server hijack` | DNS hijacking |
| `rb dns server block` | DNS blocking |

---

## TLS/SSL

### `tls security` - TLS Testing

| Command | Description |
|---------|-------------|
| `rb tls security audit <host>` | Full audit |
| `rb tls security ciphers <host>` | Cipher enum |
| `rb tls security vuln <host>` | Vuln check |
| `rb tls security resume <host>` | Session resumption |
| `rb tls security mozilla <host>` | Mozilla compliance |
| `rb tls security list` | List stored |
| `rb tls security get <host>` | Get specific |
| `rb tls security describe <host>` | Detailed view |

### `tls intel` - TLS Intelligence

| Command | Description |
|---------|-------------|
| `rb tls intel scan <host>` | TLS fingerprint |
| `rb tls intel fingerprint <host>` | JA3/JA4 fingerprint |
| `rb tls intel infrastructure <host>` | Infra mapping |

---

## Web

### `web asset` - Web Testing

| Command | Description |
|---------|-------------|
| `rb web asset get <url>` | HTTP GET |
| `rb web asset http2 <url>` | HTTP/2 request |
| `rb web asset headers <url>` | Header analysis |
| `rb web asset security <url>` | Security headers |
| `rb web asset grade <url>` | Security grade |
| `rb web asset cert <host>` | Certificate info |
| `rb web asset fuzz <url>` | Directory fuzz |
| `rb web asset fingerprint <url>` | Tech fingerprint |
| `rb web asset scan <url>` | Full scan |
| `rb web asset vuln-scan <url>` | Vuln scan |
| `rb web asset wpscan <url>` | WordPress scan |
| `rb web asset drupal-scan <url>` | Drupal scan |
| `rb web asset joomla-scan <url>` | Joomla scan |
| `rb web asset cms-scan <url>` | Generic CMS scan |
| `rb web asset cms <url>` | CMS detection |
| `rb web asset linkfinder <url>` | Extract links from JS |
| `rb web asset crawl <url>` | Web crawler |
| `rb web asset scrape <url>` | Data scraping |
| `rb web asset links <url>` | Link extraction |
| `rb web asset images <url>` | Image extraction |
| `rb web asset meta <url>` | Meta extraction |
| `rb web asset forms <url>` | Form discovery |
| `rb web asset tables <url>` | Table extraction |
| `rb web asset har-export <url>` | Export HAR |
| `rb web asset har-view <file>` | View HAR |
| `rb web asset har-replay <file>` | Replay HAR |
| `rb web asset har-to-curl <file>` | HAR to cURL |
| `rb web asset list` | List stored |
| `rb web asset describe <url>` | Detailed view |

### `web fuzz` - Web Fuzzing

| Command | Description |
|---------|-------------|
| `rb web fuzz run <url>` | Run fuzzer |

---

## Intelligence

### `intel vuln` - Vulnerability Intelligence

| Command | Description |
|---------|-------------|
| `rb intel vuln search <tech> [ver]` | Search vulns |
| `rb intel vuln cve <CVE-ID>` | CVE details |
| `rb intel vuln kev` | CISA KEV catalog |
| `rb intel vuln exploit <query>` | Exploit-DB search |
| `rb intel vuln cpe` | CPE dictionary |
| `rb intel vuln correlate <url>` | Correlate techs |
| `rb intel vuln scan <url>` | Vuln scan |
| `rb intel vuln report <url>` | Generate report |

### `intel mitre` - MITRE ATT&CK

| Command | Description |
|---------|-------------|
| `rb intel mitre technique <T-ID>` | Technique details |
| `rb intel mitre tactic <TA-ID>` | Tactic details |
| `rb intel mitre group <G-ID>` | Threat group |
| `rb intel mitre software <S-ID>` | Malware/tool |
| `rb intel mitre search <query>` | Search ATT&CK |
| `rb intel mitre matrix` | Show matrix |
| `rb intel mitre coverage` | Coverage analysis |
| `rb intel mitre mitigations` | Mitigations |
| `rb intel mitre detection` | Detection rules |
| `rb intel mitre stats` | Statistics |
| `rb intel mitre map ports=22,80` | Map findings |
| `rb intel mitre ports <ports>` | Map ports |
| `rb intel mitre export output=file` | Navigator export |

### `intel ioc` - Indicators of Compromise

| Command | Description |
|---------|-------------|
| `rb intel ioc extract <target>` | Extract IOCs |
| `rb intel ioc export <file>` | Export IOCs |
| `rb intel ioc types` | List IOC types |
| `rb intel ioc demo` | Demo extraction |
| `rb intel ioc import <file>` | Import IOCs |
| `rb intel ioc search <query>` | Search IOCs |

### `intel taxii` - TAXII 2.1 Client

| Command | Description |
|---------|-------------|
| `rb intel taxii collections <url>` | List collections |
| `rb intel taxii sync <url>` | Sync threat feeds |

---

## Cloud

### `cloud storage` - Cloud Storage Security

| Command | Description |
|---------|-------------|
| `rb cloud storage scan <target>` | Scan buckets |
| `rb cloud storage enumerate <domain>` | Enum cloud assets |

### `cloud asset` - Cloud Takeover

| Command | Description |
|---------|-------------|
| `rb cloud asset takeover <domain>` | Check takeover |
| `rb cloud asset takeover-scan <file>` | Batch scan |
| `rb cloud asset services` | List services |

---

## Utilities

### `proxy` - Proxy Servers

| Command | Description |
|---------|-------------|
| `rb proxy http start` | HTTP CONNECT proxy |
| `rb proxy socks5 start` | SOCKS5 proxy |
| `rb proxy transparent start` | Transparent proxy |
| `rb proxy transparent iptables` | iptables rules |
| `rb proxy transparent nftables` | nftables rules |
| `rb proxy data list` | List captured |
| `rb proxy data requests` | Show requests |
| `rb proxy data responses` | Show responses |
| `rb proxy data show <id>` | Show specific |
| `rb proxy data stats` | Statistics |

### `http server` - HTTP Server

| Command | Description |
|---------|-------------|
| `rb http server serve <dir>` | Serve files |
| `rb http server payloads` | Serve payloads |

### `service manage` - Service Manager

| Command | Description |
|---------|-------------|
| `rb service manage install` | Install service |
| `rb service manage uninstall` | Uninstall service |
| `rb service manage start` | Start service |
| `rb service manage stop` | Stop service |
| `rb service manage restart` | Restart service |
| `rb service manage status` | Check status |
| `rb service manage list` | List services |

### `crypto vault` - File Encryption

| Command | Description |
|---------|-------------|
| `rb crypto vault hash <file>` | Hash file |
| `rb crypto vault encrypt <file>` | Encrypt file |
| `rb crypto vault decrypt <file>` | Decrypt file |
| `rb crypto vault info <file>` | File info |

### `wordlist` - Wordlist Management

| Command | Description |
|---------|-------------|
| `rb wordlist collection list` | List wordlists |
| `rb wordlist collection sources` | List sources |
| `rb wordlist collection search <q>` | Search wordlists |
| `rb wordlist collection info <name>` | Wordlist info |
| `rb wordlist collection status` | Download status |
| `rb wordlist collection init` | Initialize |
| `rb wordlist collection get <name>` | Download wordlist |
| `rb wordlist collection install <name>` | Install wordlist |
| `rb wordlist collection update` | Update all |
| `rb wordlist collection remove <name>` | Remove wordlist |
| `rb wordlist file info <file>` | File info |
| `rb wordlist file filter <file>` | Filter wordlist |

### `search data` - Global Search

| Command | Description |
|---------|-------------|
| `rb search data query <q>` | Search all data |
| `rb search data list` | List all entries |
| `rb search data stats` | Statistics |

### `config` - Configuration

| Command | Description |
|---------|-------------|
| `rb config init create` | Create config |
| `rb config database set-password` | Set DB password |
| `rb config database clear-password` | Clear password |
| `rb config database show` | Show config |

### `assess target` - Assessment Workflow

| Command | Description |
|---------|-------------|
| `rb assess target run <url>` | Full assessment |
| `rb assess target show <url>` | Show results |

### `collect browser` - Browser Collection

| Command | Description |
|---------|-------------|
| `rb collect browser chrome` | Chrome credentials |
| `rb collect browser firefox` | Firefox credentials |
| `rb collect browser all` | All browsers |

### `collection screenshot` - Screenshots

| Command | Description |
|---------|-------------|
| `rb collection screenshot capture` | Single capture |
| `rb collection screenshot batch` | Batch capture |
| `rb collection screenshot http` | HTTP screenshots |

### `bench load` - Load Testing

| Command | Description |
|---------|-------------|
| `rb bench load run <url>` | Run load test |
| `rb bench load stress <url>` | Stress test |

### `code` - Code Security

| Command | Description |
|---------|-------------|
| `rb code secrets scan <path>` | Secret scanning |
| `rb code dependencies scan <path>` | Dependency scan |

### `auth test` - Credential Testing

| Command | Description |
|---------|-------------|
| `rb auth test http <url>` | HTTP auth test |

### `docs kb` - Documentation

| Command | Description |
|---------|-------------|
| `rb docs kb search <query>` | Search docs |
| `rb docs kb index` | Index docs |

### `mcp server` - MCP Bridge

| Command | Description |
|---------|-------------|
| `rb mcp server start` | Start MCP server |

---

## Summary

| Domain | Resources | Verbs |
|--------|-----------|-------|
| `attack` | 1 | 4 |
| `agent` | 1 | 2 |
| `access` | 1 | 5 |
| `exploit` | 2 | 24 |
| `mitm` | 1 | 6 |
| `evasion` | 13 | 42 |
| `recon` | 3 | 27 |
| `network` | 5 | 17 |
| `dns` | 2 | 12 |
| `tls` | 2 | 12 |
| `web` | 2 | 32 |
| `intel` | 4 | 23 |
| `cloud` | 2 | 5 |
| `proxy` | 4 | 9 |
| `service` | 1 | 7 |
| `crypto` | 1 | 4 |
| `wordlist` | 2 | 11 |
| `search` | 1 | 3 |
| `config` | 2 | 4 |
| `assess` | 1 | 2 |
| `collect` | 1 | 3 |
| `collection` | 1 | 3 |
| `bench` | 1 | 2 |
| `code` | 2 | 2 |
| `auth` | 1 | 1 |
| `docs` | 1 | 2 |
| `mcp` | 1 | 1 |
| `http` | 1 | 2 |
| **Total** | **~55** | **~260** |

---

## Quick Reference

### Magic Scan (Auto-detect)
```bash
rb 192.168.1.1           # Scan IP
rb example.com           # Scan domain
rb https://example.com   # Scan URL
```

### Interactive Shell
```bash
rb shell <target>        # Enter TUI mode
rb shell file.rb-session # Open session file
```

### Global Help
```bash
rb help                  # Global help
rb <domain> help         # Domain help
rb <domain> <resource> help  # Resource help
```
