# Design: Vulnerability Intelligence System

## Context

redblue already has technology fingerprinting capabilities (`rb web asset fingerprint`), but the detection stops at identification. Security professionals need to correlate detected technologies with known vulnerabilities to prioritize remediation.

### Constraints
- **ZERO external crates** - All HTTP, JSON parsing from scratch (redblue philosophy)
- **Offline-capable** - Cache results for air-gapped environments
- **Rate-limit aware** - NVD has strict limits (5 req/30s without API key)
- **Version-accurate** - Must handle semver, vendor versioning, and ranges

### Stakeholders
- Red team: Need exploit availability for detected tech
- Blue team: Need patch prioritization by risk
- Compliance: Need CVE audit trails

## Goals / Non-Goals

### Goals
- Detect 50+ technologies with precise versions
- Query 5+ vulnerability sources
- Correlate fingerprints with CVEs in <30 seconds
- Prioritize by exploitability (CISA KEV, Exploit-DB)
- Generate actionable reports

### Non-Goals
- Real-time vulnerability monitoring (future work)
- Custom vulnerability database management
- Automated exploitation
- Compliance framework mapping (SOC2, PCI-DSS)

## Current Infrastructure Status

### Existing Fingerprinting (~9000 lines ready)

| Component | Location | Lines | Status |
|-----------|----------|-------|--------|
| HTTP Fingerprint | `src/intelligence/http-fingerprint.rs` | 563 | ✅ Server/WAF/CDN/Framework |
| Service Detection | `src/intelligence/service-detection.rs` | 334 | ✅ Has `cpe` field |
| Banner Analysis | `src/intelligence/banner-analysis.rs` | 861 | ✅ Version extraction |
| TLS Fingerprint | `src/intelligence/tls-fingerprint.rs` | 572 | ✅ JA3/JA4 |
| TCP Fingerprint | `src/intelligence/tcp-fingerprint.rs` | 679 | ✅ OS detection |
| WordPress Scanner | `src/modules/web/strategies/wordpress.rs` | 677 | ✅ Plugins/themes |
| Drupal Scanner | `src/modules/web/strategies/drupal.rs` | 607 | ✅ Modules |
| Joomla Scanner | `src/modules/web/strategies/joomla.rs` | 679 | ✅ Extensions |
| Ghost Scanner | `src/modules/web/strategies/ghost.rs` | 468 | ✅ Version/API |
| Laravel Scanner | `src/modules/web/strategies/laravel.rs` | 422 | ✅ Framework |
| JSON Parser | `src/utils/json.rs` | 521 | ✅ Full `JsonValue` |
| HTML Parser | `src/modules/web/dom.rs` | 1330 | ✅ CSS selectors |

### CLI Commands Already Working
```bash
rb web asset fingerprint <url>    # Detects: React, nginx, PHP, etc.
rb web asset get <url> --intel    # Server intelligence
rb web asset cms-scan <url>       # WordPress/Drupal/Joomla
rb web asset wpscan <url>         # WordPress deep scan
```

### What Needs Implementation

| Component | Priority | Effort | Dependencies |
|-----------|----------|--------|--------------|
| CPE Dictionary | 🔴 HIGH | 1-2 days | None |
| NVD API Client | 🔴 HIGH | 1 day | JSON parser ✅ |
| OSV API Client | 🔴 HIGH | 0.5 day | JSON parser ✅ |
| CISA KEV Client | 🟡 MEDIUM | 0.5 day | JSON parser ✅ |
| Exploit-DB Scraper | 🟡 MEDIUM | 1 day | HTML parser ✅ |
| Risk Calculator | 🟡 MEDIUM | 0.5 day | None |
| `rb vuln` CLI | 🔴 HIGH | 1 day | All above |
| Deduplication | 🟡 MEDIUM | 0.5 day | None |

## Decisions

### Decision 1: CPE as Primary Identifier
**What**: Use CPE (Common Platform Enumeration) as the canonical identifier for technology → vulnerability mapping.

**Why**: CPE is the industry standard used by NVD. Direct CPE queries are faster and more accurate than text-based searches.

**Alternatives considered**:
- Text-based search: Prone to false positives ("nginx" matches many unrelated entries)
- Package ecosystem only (npm/pip): Doesn't cover traditional software (nginx, apache)

**Implementation**: Maintain a CPE dictionary mapping common tech names to CPE patterns:
```rust
// Example CPE mapping
struct CpeMapping {
    tech_name: &'static str,
    vendor: &'static str,
    product: &'static str,
    cpe_pattern: &'static str,
}

const CPE_MAPPINGS: &[CpeMapping] = &[
    CpeMapping { tech_name: "nginx", vendor: "nginx", product: "nginx", cpe_pattern: "cpe:2.3:a:nginx:nginx:*" },
    CpeMapping { tech_name: "apache", vendor: "apache", product: "http_server", cpe_pattern: "cpe:2.3:a:apache:http_server:*" },
    CpeMapping { tech_name: "wordpress", vendor: "wordpress", product: "wordpress", cpe_pattern: "cpe:2.3:a:wordpress:wordpress:*" },
    // ... 50+ mappings
];
```

### Decision 2: Multi-Source Aggregation with Deduplication
**What**: Query multiple sources and deduplicate by canonical CVE ID.

**Why**: No single source has complete coverage. NVD is authoritative for CVEs, OSV is better for open-source packages, Vulners has better exploit references.

**Source priority order**:
1. NVD (primary - has CPE matching, CVSS)
2. OSV (for npm/pip/cargo packages)
3. CISA KEV (for exploited-in-wild flag)
4. Vulners (for exploit references)
5. Exploit-DB (for PoC links)
6. GHSA (for GitHub packages)

**Deduplication rules**:
- CVE ID is canonical (CVE-YYYY-XXXX)
- If OSV entry references a CVE, link them
- Merge references from all sources
- Take highest CVSS score across sources

### Decision 3: Version Range Matching
**What**: Implement semantic version comparison with support for NVD version ranges.

**Why**: NVD specifies vulnerable version ranges (e.g., `versionStartIncluding: 1.0.0, versionEndExcluding: 1.2.3`). Simple string matching misses vulnerabilities.

**Implementation**:
```rust
struct VersionRange {
    start_including: Option<Version>,
    start_excluding: Option<Version>,
    end_including: Option<Version>,
    end_excluding: Option<Version>,
}

impl VersionRange {
    fn contains(&self, version: &Version) -> bool {
        // Implement semver comparison
    }
}
```

**Fallback for non-semver**: Lexicographic comparison with vendor-specific rules.

### Decision 4: Risk Score Formula
**What**: Calculate a composite risk score for prioritization.

**Formula**:
```
risk_score = (cvss_base * 10)
           + (exploit_available ? 25 : 0)
           + (cisa_kev ? 30 : 0)
           + age_penalty(days_since_publish)
           + impact_modifier(rce: +20, auth_bypass: +15, info_leak: +5)
```

**Range**: 0-100, higher = more critical

**Why**: CVSS alone doesn't capture real-world exploitability. CISA KEV and exploit availability are strong indicators of active exploitation.

### Decision 5: Cache Strategy
**What**: SQLite-based cache for vulnerability data with TTL.

**Why**:
- NVD rate limits are strict
- Many targets share technologies
- Offline use cases

**Cache structure**:
```sql
CREATE TABLE vuln_cache (
    id TEXT PRIMARY KEY,           -- CVE-2024-1234
    tech_name TEXT,
    tech_version TEXT,
    data JSON,
    fetched_at INTEGER,
    source TEXT
);

CREATE INDEX idx_tech ON vuln_cache(tech_name, tech_version);
```

**TTL**: 24 hours for fresh data, stale-while-revalidate pattern.

### Decision 6: API Clients from Scratch
**What**: Implement HTTP clients for NVD, OSV, Vulners without external crates.

**Why**: redblue philosophy - zero external dependencies for protocols.

**Implementation**: Use existing `HttpClient` from `src/protocols/http.rs` with JSON parsing from scratch.

## Risks / Trade-offs

### Risk: NVD Rate Limiting
**Impact**: High - NVD limits to 5 requests per 30 seconds without API key
**Mitigation**:
- Batch CPE queries where possible
- Aggressive caching
- Support optional NVD API key for higher limits
- Queue requests with backoff

### Risk: Version Detection Accuracy
**Impact**: Medium - Incorrect versions lead to false positives/negatives
**Mitigation**:
- Multiple detection methods per technology
- Confidence scoring
- Manual override option
- Conservative matching (require exact version when uncertain)

### Risk: CPE Mapping Maintenance
**Impact**: Medium - New technologies need manual CPE mappings
**Mitigation**:
- Start with top 50 technologies by usage
- Community contributions
- Fallback to text search when no CPE mapping exists

### Trade-off: Coverage vs Speed
**Decision**: Default to querying top 2 sources (NVD + OSV), with `--deep` flag for all sources.
**Rationale**: 90% of use cases covered by NVD+OSV, full search adds 10-30 seconds.

## Data Model

```rust
/// Detected technology with version
#[derive(Debug, Clone)]
pub struct DetectedTech {
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub category: TechCategory,
    pub cpe: Option<String>,
    pub confidence: f32,        // 0.0 - 1.0
    pub detection_source: String,
}

#[derive(Debug, Clone)]
pub enum TechCategory {
    Server,
    Proxy,
    Cdn,
    Framework,
    Runtime,
    Cms,
    Library,
    Database,
    Other,
}

/// Vulnerability record
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,             // CVE-2024-1234 or OSV-...
    pub title: String,
    pub description: String,
    pub cvss_v3: Option<f32>,
    pub severity: Severity,
    pub published: String,
    pub references: Vec<String>,
    pub exploits: Vec<ExploitRef>,
    pub cisa_kev: bool,
    pub affected_versions: Vec<VersionRange>,
}

#[derive(Debug, Clone)]
pub struct ExploitRef {
    pub source: String,         // exploit-db, github, etc
    pub url: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Critical,  // CVSS >= 9.0
    High,      // CVSS 7.0-8.9
    Medium,    // CVSS 4.0-6.9
    Low,       // CVSS 0.1-3.9
    None,      // CVSS 0.0 or unknown
}
```

## Parsers Required

redblue implements ALL parsers from scratch (zero external dependencies). Here's what we have and need:

### Reference Implementations (in ./references/)
These implementations can be studied for parsing techniques:

| Reference | Language | Type | Key Files | Learning Points |
|-----------|----------|------|-----------|-----------------|
| **jq** | C | JSON | `src/jv.c`, `src/jv_parse.c` | Reference counting, value types, escape handling |
| **yq** | Go | YAML/XML | `pkg/yqlib/decoder_xml.go`, `decoder_yaml.go` | Decoder pattern, XML→tree conversion |
| **cheerio** | TypeScript | HTML | `src/parsers/parse5-adapter.ts` | DOM tree adapter, serialization |

### Existing Parsers
| Parser | Location | Lines | Status | Notes |
|--------|----------|-------|--------|-------|
| **JSON** | `src/utils/json.rs` | 521 | ✅ Complete | Full JSON with `JsonValue` type |
| **HTML** | `src/modules/web/dom.rs` | 1330 | ✅ Complete | DOM parser with CSS selectors |
| **YAML** | `src/config/yaml.rs` | 309 | ⚠️ Limited | Config-focused, needs generalization |

### New Parsers Needed
| Parser | Location | Priority | Use Case | Reference |
|--------|----------|----------|----------|-----------|
| **XML** | `src/utils/xml.rs` | HIGH | NVD feeds, some vendor advisories | `yq/decoder_xml.go` |
| **YAML (General)** | `src/utils/yaml.rs` | MEDIUM | OSV schema, config files | `yq/decoder_yaml.go` |
| **CSV** | `src/utils/csv.rs` | LOW | CISA KEV CSV format | Simple RFC 4180 |

### XML Parser Design
```rust
/// Minimal XML parser for vulnerability feeds
#[derive(Debug, Clone)]
pub enum XmlNode {
    Element {
        name: String,
        attributes: Vec<(String, String)>,
        children: Vec<XmlNode>,
    },
    Text(String),
    CData(String),
}

impl XmlNode {
    pub fn parse(xml: &str) -> Result<XmlNode, String>;
    pub fn find(&self, path: &str) -> Option<&XmlNode>;
    pub fn find_all(&self, tag: &str) -> Vec<&XmlNode>;
    pub fn text(&self) -> String;
    pub fn attr(&self, name: &str) -> Option<&str>;
}
```

## API Endpoints & Response Formats

### NVD REST API
```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
    &resultsPerPage=100
```
- **Format**: JSON
- **Parser**: `src/utils/json.rs`
- **Rate limit**: 5/30s (public), 50/30s (with API key)

**Response structure** (simplified):
```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-1234",
        "descriptions": [{"value": "..."}],
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
        },
        "configurations": [
          {"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:..."}]}]}
        ]
      }
    }
  ]
}
```

### OSV API
```
POST https://api.osv.dev/v1/query
{
    "package": {"name": "express", "ecosystem": "npm"},
    "version": "4.17.1"
}
```
- **Format**: JSON
- **Parser**: `src/utils/json.rs`
- **No rate limit** documented

**Response structure**:
```json
{
  "vulns": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "aliases": ["CVE-2024-1234"],
      "summary": "...",
      "severity": [{"type": "CVSS_V3", "score": "..."}],
      "affected": [{"package": {"ecosystem": "npm", "name": "express"}}]
    }
  ]
}
```

### CISA KEV
```
GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```
- **Format**: JSON
- **Parser**: `src/utils/json.rs`
- **Static file** - cache aggressively

**Response structure**:
```json
{
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-1234",
      "vendorProject": "nginx",
      "product": "nginx",
      "vulnerabilityName": "...",
      "dateAdded": "2024-01-01",
      "shortDescription": "...",
      "requiredAction": "Apply updates",
      "dueDate": "2024-01-15"
    }
  ]
}
```

### Vulners API
```
GET https://vulners.com/api/v3/search/lucene/
    ?query=nginx 1.18.0
    &apiKey=OPTIONAL
```
- **Format**: JSON
- **Parser**: `src/utils/json.rs`
- **Optional API key** for higher limits

### Exploit-DB
```
GET https://www.exploit-db.com/search?cve=2024-1234
```
- **Format**: HTML (no official API)
- **Parser**: `src/modules/web/dom.rs`
- **Scraping required** - parse search results page

**Extraction targets**:
- Exploit title: `table.table-list td:nth-child(5)`
- Exploit URL: `table.table-list td:nth-child(5) a[href]`
- Platform: `table.table-list td:nth-child(6)`

### GitHub Security Advisories (GHSA)
```
POST https://api.github.com/graphql
{
  "query": "query { securityVulnerabilities(ecosystem:NPM, package:\"express\") { ... }}"
}
```
- **Format**: JSON (GraphQL)
- **Parser**: `src/utils/json.rs`
- **Requires token** for higher rate limits

### Vendor Advisory Sites (Scraping)

Some vendor advisories require HTML scraping:

| Vendor | URL Pattern | Format |
|--------|-------------|--------|
| Apache | `https://httpd.apache.org/security/vulnerabilities_24.html` | HTML |
| Nginx | `https://nginx.org/en/security_advisories.html` | HTML |
| WordPress | `https://wordpress.org/news/category/security/` | HTML |
| Drupal | `https://www.drupal.org/security` | HTML |

For HTML scraping, use existing DOM parser with CSS selectors.

## Migration Plan

No migration needed - all new capabilities.

## Open Questions

1. **API Key Management**: How should users provide NVD/Vulners API keys?
   - Environment variables?
   - Config file?
   - CLI flags?

2. **Plugin Architecture**: Should vulnerability sources be pluggable for community extensions?

3. **Persistence**: Store vulnerability findings in redblue database (.rbdb) or separate?

4. **Alerting**: Should we add webhook support for new vulnerabilities on watched technologies?
