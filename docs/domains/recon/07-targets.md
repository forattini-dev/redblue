# High-Value Targets

What to look for during reconnaissance and why it matters.

## Target Categories

### Development Environments

```bash
# Find dev/staging subdomains
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | select(.subdomain | test("dev|staging|test|sandbox|uat"))'
```

**Why valuable:**
- Often have debugging enabled
- May contain test credentials
- Usually less security monitoring
- Sometimes have production data copies
- Often run outdated software

**Common patterns:**
```
dev.target.com
dev-api.target.com
staging.target.com
staging-v2.target.com
test.target.com
sandbox.target.com
uat.target.com
preprod.target.com
```

### Admin Panels

```bash
# Find admin URLs
rb recon domain urls target.com --include "admin|panel|dashboard|manage|backend" -o json
```

**Why valuable:**
- Direct access to management functions
- Often have authentication bypasses
- May expose sensitive operations
- Sometimes have default credentials

**Common patterns:**
```
admin.target.com
panel.target.com
dashboard.target.com
manage.target.com
backend.target.com
cms.target.com
portal.target.com
/admin/
/wp-admin/
/administrator/
```

### API Endpoints

```bash
# Find API endpoints
rb recon domain urls target.com --include "api|graphql|rest|v1|v2" -o json
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | select(.subdomain | test("api"))'
```

**Why valuable:**
- Direct backend access
- Often lack proper authentication
- May expose internal functions
- Documentation sometimes available
- Rate limiting often missing

**Common patterns:**
```
api.target.com
api-v1.target.com
api-v2.target.com
graphql.target.com
rest.target.com
/api/
/api/v1/
/api/v2/
/graphql
/rest/
```

### Internal Systems

```bash
# Find internal subdomains
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | select(.subdomain | test("internal|intranet|corp|private|vpn"))'
```

**Why valuable:**
- Access to internal network
- Often trusted by other systems
- May have sensitive data
- Usually less hardened

**Common patterns:**
```
internal.target.com
intranet.target.com
corp.target.com
private.target.com
vpn.target.com
gateway.target.com
```

### Email Infrastructure

```bash
# DNS records for email
rb dns record lookup target.com --type MX
rb dns record lookup target.com --type TXT

# Find mail subdomains
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | select(.subdomain | test("mail|smtp|imap|pop|exchange|webmail"))'
```

**Why valuable:**
- Phishing campaign targets
- May have webmail portals
- Often outdated software
- SPF/DMARC misconfigs

**Common patterns:**
```
mail.target.com
smtp.target.com
imap.target.com
pop.target.com
webmail.target.com
exchange.target.com
owa.target.com
```

### Cloud Storage

```bash
# Find cloud storage references
rb recon domain urls target.com -o json | \
  jq '.urls[] | select(.url | test("s3.amazonaws|blob.core.windows|storage.googleapis"))'

# Check for takeover
rb cloud asset takeover storage.target.com
```

**Why valuable:**
- May contain sensitive files
- Often misconfigured permissions
- Backup files exposed
- User uploads accessible

**Common patterns:**
```
target.s3.amazonaws.com
target.blob.core.windows.net
target.storage.googleapis.com
cdn.target.com
assets.target.com
static.target.com
files.target.com
```

## Data to Extract

### From WHOIS

```bash
rb recon domain whois target.com -o json | jq '{
  registrar: .registrar,
  org: .registrant_org,
  created: .creation_date,
  nameservers: .name_servers
}'
```

| Field | Strategic Use |
|-------|---------------|
| Registrar | Identify hosting patterns |
| Organization | Find related domains |
| Creation date | Age = more history |
| Nameservers | DNS provider vulnerabilities |
| Registrant email | Additional OSINT |

### From DNS

```bash
# TXT records often leak information
rb dns record lookup target.com --type TXT
```

| Record | What It Reveals |
|--------|-----------------|
| A/AAAA | Server IPs, hosting provider |
| MX | Email infrastructure |
| NS | DNS provider |
| TXT | Services used, verification tokens |
| CNAME | Third-party services |

**TXT record goldmines:**
```
v=spf1 include:_spf.google.com     # Uses Google Workspace
google-site-verification=...        # Google services
MS=...                              # Microsoft services
atlassian-domain-verification=...   # Atlassian (Jira, Confluence)
_dmarc...                           # Email security config
```

### From Subdomains

```bash
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | {name: .subdomain, ips: .ips, source: .source}'
```

| Pattern | Indicates |
|---------|-----------|
| dev-, test-, staging- | Development environments |
| api-, graphql- | API services |
| admin-, panel- | Admin interfaces |
| mail-, smtp- | Email systems |
| vpn-, gateway- | Network access points |
| old-, legacy-, v1- | Deprecated systems |

### From Historical URLs

```bash
# High-value file types
rb recon domain urls target.com --extensions js,json,xml,config,env,bak,sql,log
```

| Extension | Value |
|-----------|-------|
| .js | Client logic, API endpoints, secrets |
| .json | Configuration, API responses |
| .xml | Config files, SOAP endpoints |
| .env | Environment variables, credentials |
| .bak, .old | Backup files with sensitive data |
| .sql | Database dumps |
| .log | Debug info, errors |
| .config | Application configuration |

### From OSINT Harvest

```bash
rb recon domain harvest target.com -o json | jq '{
  emails: .emails,
  email_count: (.emails | length),
  subdomains: (.subdomains | length),
  ips: .ips
}'
```

| Data | Use |
|------|-----|
| Emails | Username patterns, phishing targets |
| Subdomains | Attack surface expansion |
| IPs | Infrastructure mapping |
| URLs | Entry points |

## Attack Surface Prioritization

### Critical (Immediate Investigation)

```bash
# Exposed admin panels
rb recon domain urls target.com --include "/admin/|/wp-admin/|/administrator/"

# Development with production data
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | select(.subdomain | test("dev|staging"))'

# Potential takeovers
rb cloud asset takeover-scan -w subs.txt --confidence high
```

### High (Test Soon)

```bash
# API endpoints
rb recon domain urls target.com --include "/api/"

# Authentication endpoints
rb recon domain urls target.com --include "login|auth|signin|oauth"

# File upload areas
rb recon domain urls target.com --include "upload|file|import"
```

### Medium (Investigate)

```bash
# JavaScript files (secrets, endpoints)
rb recon domain urls target.com --extensions js

# Configuration files
rb recon domain urls target.com --extensions json,xml,config

# Old versions
rb recon domain urls target.com --include "/v1/|/old/|/legacy/"
```

## Correlation Matrix

| Found | Cross-reference With |
|-------|---------------------|
| Subdomain | Port scan, HTTP headers, TLS audit |
| Email | Username format, LinkedIn, GitHub |
| IP address | Shodan, network scan, reverse DNS |
| Technology | CVE database, exploit-db |
| Old URL | Current state check, Wayback |
| JS file | Secret scanning, endpoint extraction |

## Next Steps

- [Recon Workflow](/domains/recon/06-workflow.md) - Complete methodology
- [WHOIS Lookup](/domains/recon/01-whois.md) - Domain registration info
- [Subdomain Enumeration](/domains/recon/02-subdomains.md) - Find subdomains
- [URL Discovery](/domains/recon/03-urls.md) - Historical URLs
