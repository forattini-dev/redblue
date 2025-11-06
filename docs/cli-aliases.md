# CLI Aliases & Shortcuts - Design Document

## TL;DR
Catalog of the shorthand commands we support, plus rules for creating new aliases without breaking the kubectl-style grammar.

## 🎯 Goal

Make redblue CLI blazing fast to type while maintaining readability.

**Current:**
```bash
rb intelligence fingerprint extract google.com  # Too verbose!
```

**Proposed:**
```bash
rb i fp extract google.com     # Fast!
rb intel fp extract google.com  # Readable!
```

---

## 📋 Alias System Design

### Alias Resolution Order

```
User input: "rb i fp extract google.com"
  ↓
1. Check exact match: "i" → NO
2. Check aliases: "i" → "intelligence" ✓
3. Use canonical: "intelligence"
  ↓
1. Check exact match: "fp" → NO
2. Check aliases: "fp" → "fingerprint" ✓
3. Use canonical: "fingerprint"
  ↓
Final: rb intelligence fingerprint extract google.com
```

### Alias Categories

1. **Single-letter** (`rb i` = `rb intelligence`)
   - Ultra-fast for experts
   - Only for most-used domains

2. **Short form** (`rb intel` = `rb intelligence`)
   - Readable but shorter
   - For all domains

3. **Common typos** (`rb ntwrk` = `rb network`)
   - Quality of life
   - Prevent frustration

---

## 🗺️ Complete Alias Map

### Domains

| Domain | Short | Single-Letter | Notes |
|--------|-------|---------------|-------|
| **intelligence** | intel | i | Most verbose, needs alias most |
| **network** | net | n | Very common |
| **database** | db | d | Universal abbreviation |
| **access** | acc | a | Post-exploitation |
| **exploit** | exp | e | (DEPRECATED, use access) |
| **recon** | - | r | Already short |
| **screenshot** | screen | s | Less common, lower priority |
| **collection** | collect | c | Future feature |
| **benchmark** | bench | b | Future feature |
| dns | - | - | Already 3 chars |
| web | - | - | Already 3 chars |
| tls | - | - | Already 3 chars |
| code | - | - | Already 4 chars |
| cloud | - | - | Already 5 chars |

### Resources

| Resource | Alias | Notes |
|----------|-------|-------|
| **fingerprint** | fp | Universal abbreviation |
| **ports** | - | Already 5 chars |
| **record** | rec | DNS records |
| **domain** | dom | Recon domain |
| **asset** | - | Already 5 chars |
| **security** | sec | Common abbreviation |
| **certificate** | cert | Universal |
| **payload** | pl | Exploit payloads |
| **listener** | listen | Already common |
| **screenshot** | screen, shot | Multiple options |
| **dependencies** | deps | Common in dev |
| **secrets** | - | Already 7 chars |

### Verbs

Most verbs are already short (scan, list, get, create), so few aliases needed:

| Verb | Alias | Notes |
|------|-------|-------|
| **describe** | desc | Common abbreviation |
| **enumerate** | enum | Common in security |
| **bruteforce** | brute | Shorter |
| **takeover** | to | Subdomain takeover |

---

## 📊 Usage Examples

### Intelligence Commands

```bash
# VERBOSE (full names)
rb intelligence fingerprint extract google.com
rb intelligence fingerprint compare site1.com site2.com
rb intelligence fingerprint search --ja3 abc123

# READABLE (short forms)
rb intel fp extract google.com
rb intel fp compare site1.com site2.com
rb intel fp search --ja3 abc123

# FAST (single-letter)
rb i fp extract google.com
rb i fp compare site1.com site2.com
rb i fp search --ja3 abc123
```

### Network Commands

```bash
# VERBOSE
rb network ports scan 192.168.1.1
rb network host discover 192.168.1.0/24

# READABLE
rb net ports scan 192.168.1.1
rb net host discover 192.168.1.0/24

# FAST
rb n ports scan 192.168.1.1
rb n host discover 192.168.1.0/24
```

### Database Commands

```bash
# VERBOSE
rb database data query example.com.rbdb

# READABLE
rb db data query example.com.rbdb

# FAST
rb d data query example.com.rbdb
```

### Access/Exploit Commands

```bash
# VERBOSE
rb access shell create 10.0.0.1:4444 --protocol tcp

# READABLE
rb acc shell create 10.0.0.1:4444 --protocol tcp

# FAST
rb a shell create 10.0.0.1:4444 --protocol tcp
```

### Recon Commands

```bash
# Already short!
rb recon domain whois example.com

# Alternative (single-letter)
rb r domain whois example.com
rb r dom whois example.com  # Even shorter resource
```

### Web Commands

```bash
# VERBOSE
rb web asset security http://example.com
rb web asset certificate google.com

# WITH ALIASES
rb web asset sec http://example.com
rb web asset cert google.com
```

---

## 🔧 Implementation Strategy

### 1. Create Alias Resolver

```rust
// src/cli/aliases.rs

use std::collections::HashMap;

pub struct AliasResolver {
    domain_aliases: HashMap<&'static str, &'static str>,
    resource_aliases: HashMap<&'static str, &'static str>,
    verb_aliases: HashMap<&'static str, &'static str>,
}

impl AliasResolver {
    pub fn new() -> Self {
        let mut domain_aliases = HashMap::new();

        // Intelligence aliases
        domain_aliases.insert("i", "intelligence");
        domain_aliases.insert("intel", "intelligence");

        // Network aliases
        domain_aliases.insert("n", "network");
        domain_aliases.insert("net", "network");
        domain_aliases.insert("ntwrk", "network"); // typo

        // Database aliases
        domain_aliases.insert("d", "database");
        domain_aliases.insert("db", "database");

        // Access aliases
        domain_aliases.insert("a", "access");
        domain_aliases.insert("acc", "access");

        // Exploit aliases (deprecated)
        domain_aliases.insert("e", "exploit");
        domain_aliases.insert("exp", "exploit");

        // Recon aliases
        domain_aliases.insert("r", "recon");

        // Screenshot aliases
        domain_aliases.insert("s", "screenshot");
        domain_aliases.insert("screen", "screenshot");

        // Collection aliases
        domain_aliases.insert("c", "collection");
        domain_aliases.insert("collect", "collection");

        // Benchmark aliases
        domain_aliases.insert("b", "bench");

        let mut resource_aliases = HashMap::new();

        // Common resource aliases
        resource_aliases.insert("fp", "fingerprint");
        resource_aliases.insert("rec", "record");
        resource_aliases.insert("dom", "domain");
        resource_aliases.insert("sec", "security");
        resource_aliases.insert("cert", "certificate");
        resource_aliases.insert("pl", "payload");
        resource_aliases.insert("listen", "listener");
        resource_aliases.insert("screen", "screenshot");
        resource_aliases.insert("shot", "screenshot");
        resource_aliases.insert("deps", "dependencies");

        let mut verb_aliases = HashMap::new();

        // Verb aliases
        verb_aliases.insert("desc", "describe");
        verb_aliases.insert("enum", "enumerate");
        verb_aliases.insert("brute", "bruteforce");
        verb_aliases.insert("to", "takeover");

        Self {
            domain_aliases,
            resource_aliases,
            verb_aliases,
        }
    }

    pub fn resolve_domain(&self, input: &str) -> &str {
        self.domain_aliases.get(input).unwrap_or(&input)
    }

    pub fn resolve_resource(&self, input: &str) -> &str {
        self.resource_aliases.get(input).unwrap_or(&input)
    }

    pub fn resolve_verb(&self, input: &str) -> &str {
        self.verb_aliases.get(input).unwrap_or(&input)
    }

    pub fn resolve_all(&self, domain: &str, resource: Option<&str>, verb: Option<&str>)
        -> (String, Option<String>, Option<String>)
    {
        let resolved_domain = self.resolve_domain(domain).to_string();
        let resolved_resource = resource.map(|r| self.resolve_resource(r).to_string());
        let resolved_verb = verb.map(|v| self.resolve_verb(v).to_string());

        (resolved_domain, resolved_resource, resolved_verb)
    }
}
```

### 2. Integrate into Parser

```rust
// src/cli/mod.rs (or parser.rs)

use crate::cli::aliases::AliasResolver;

pub fn dispatch(ctx: &CliContext) -> Result<(), String> {
    let resolver = AliasResolver::new();

    let domain = ctx.domain.as_deref().ok_or("Missing domain")?;

    // Resolve aliases
    let (resolved_domain, resolved_resource, resolved_verb) = resolver.resolve_all(
        domain,
        ctx.resource.as_deref(),
        ctx.verb.as_deref(),
    );

    // Create new context with resolved names
    let mut resolved_ctx = ctx.clone();
    resolved_ctx.domain = Some(resolved_domain);
    resolved_ctx.resource = resolved_resource;
    resolved_ctx.verb = resolved_verb;

    // Continue with normal dispatch using resolved names
    // ...
}
```

### 3. Update Help System

```rust
// Show aliases in help output

pub fn print_help(cmd: &dyn Command) {
    Output::header(&format!(
        "{} {} - {}",
        cmd.domain(),
        cmd.resource(),
        cmd.description()
    ));

    // Show aliases
    let aliases = get_aliases_for_command(cmd.domain(), cmd.resource());
    if !aliases.is_empty() {
        println!("\n{}ALIASES:{}", "\x1b[1m", "\x1b[0m");
        for (short, full) in aliases {
            println!("  {} → {}", short, full);
        }
        println!("\n  Example with aliases:");
        println!("    rb i fp extract google.com");
        println!("    rb intel fp extract google.com");
    }

    // ... rest of help
}
```

---

## 📝 Help Output Example

```bash
$ rb intelligence fingerprint help

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
intelligence fingerprint - Extract passive intelligence
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ALIASES:
  i → intelligence
  intel → intelligence
  fp → fingerprint

USAGE:
  rb intelligence fingerprint <verb> [target] [FLAGS]

  With aliases:
  rb i fp <verb> [target] [FLAGS]
  rb intel fp <verb> [target] [FLAGS]

VERBS:
  extract      Extract fingerprint from target
  compare      Compare two fingerprints
  search       Search fingerprint database

EXAMPLES:
  # Full names
  rb intelligence fingerprint extract google.com

  # Short form (recommended)
  rb intel fp extract google.com

  # Ultra-short (expert)
  rb i fp extract google.com
```

---

## 🎯 Benefits

### 1. Speed
```
Before: 42 chars → rb intelligence fingerprint extract google.com
After:  23 chars → rb i fp extract google.com
Saved:  45% fewer keystrokes!
```

### 2. Muscle Memory
```bash
# Common workflows become natural
rb n ports scan 192.168.1.1      # network scan
rb i fp extract 192.168.1.1      # fingerprint
rb db data query results.rbdb    # query database
```

### 3. Discoverability
- Help shows all aliases
- Autocomplete works with aliases
- Both short and long forms documented

### 4. Backward Compatibility
- Full names still work
- No breaking changes
- Gradual adoption

---

## 🚀 Rollout Plan

### Phase 1: Core Aliases (THIS SPRINT)
- [x] Design alias system
- [ ] Implement AliasResolver
- [ ] Integrate into parser
- [ ] Update help system
- [ ] Test with existing commands

### Phase 2: Documentation
- [ ] Update README with all aliases
- [ ] Create cheat sheet
- [ ] Update command examples

### Phase 3: Autocomplete (Future)
- [ ] zsh completion with aliases
- [ ] bash completion with aliases
- [ ] fish completion with aliases

---

## 📊 Most Common Commands (Optimized)

Based on typical security workflow:

```bash
# Port scanning
rb n ports scan <target>        # was: rb network ports scan

# DNS reconnaissance
rb dns rec lookup <domain>      # was: rb dns record lookup

# Web analysis
rb web asset sec <url>          # was: rb web asset security
rb web asset cert <domain>      # was: rb web asset certificate

# Intelligence gathering
rb i fp extract <target>        # was: rb intelligence fingerprint extract

# WHOIS
rb r dom whois <domain>         # was: rb recon domain whois

# Database queries
rb d data query <file>          # was: rb database data query

# Access (reverse shells)
rb a shell create <ip:port>     # was: rb access shell create
```

---

## ✅ Summary

**Problem:** Commands too verbose
**Solution:** 3-tier alias system (full → short → single-letter)
**Impact:** 45% fewer keystrokes, faster workflow
**Status:** Ready to implement

Next: Implement AliasResolver and integrate into parser.
