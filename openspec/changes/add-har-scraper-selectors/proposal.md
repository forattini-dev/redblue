# Proposal: HAR Recording, CSS Selectors & Scraper

## Summary

Add HAR (HTTP Archive) recording/playback, CSS selector engine (Cheerio-like), and expose scraper functionality via CLI and MCP server for recker integration.

## Motivation

Currently redblue has:
- `WebCrawler` - Full BFS crawler (not exposed in CLI)
- `UrlHarvester` - Historical URL fetching (not exposed in CLI)
- HTTP client with full request/response capture

Missing capabilities:
1. **Session Recording** - No way to record HTTP transactions for replay/analysis
2. **HTML Parsing** - No CSS selector support for extracting data
3. **CLI Access** - Crawler/harvester not accessible from command line
4. **MCP Integration** - Not available as tools for recker

## Proposed Changes

### 1. HAR Module (`src/protocols/har.rs`)
- HAR 1.2 spec compliant recording
- Request/response serialization
- Timing capture (DNS, connect, TLS, wait, receive)
- Content encoding handling
- Export to `.har` files
- Replay functionality

### 2. CSS Selector Engine (`src/protocols/selector.rs`)
- Cheerio-compatible API
- Support for common selectors:
  - Tag: `div`, `a`, `span`
  - Class: `.class-name`
  - ID: `#element-id`
  - Attribute: `[href]`, `[data-id="123"]`
  - Descendant: `div span`
  - Child: `div > span`
  - Pseudo: `:first-child`, `:nth-child(n)`
- Text extraction
- Attribute extraction
- Iteration over matches

### 3. Enhanced Scraper (`src/modules/web/scraper.rs`)
- Combine crawler + selectors + HAR
- Configurable extraction rules
- JSON/CSV output
- Rate limiting
- Robots.txt respect

### 4. CLI Commands
```bash
# Crawling with HAR recording
rb web crawl <url> [--depth N] [--har output.har]

# Scraping with selectors
rb web scrape <url> --select "CSS_SELECTOR" [--attr href|text|html]

# URL harvesting
rb recon urls <domain> [--source wayback|urlscan|all]

# HAR replay
rb web replay <file.har> [--delay ms]

# HAR analysis
rb web har-info <file.har>
```

### 5. MCP Server Tools
Expose as MCP tools for recker:
- `web_crawl` - Crawl website, return pages
- `web_scrape` - Scrape with CSS selectors
- `web_select` - Query HTML with selectors
- `har_record` - Start/stop HAR recording
- `har_replay` - Replay HAR file

## Impact

- **New files**: ~4-5 new source files
- **Modified files**: CLI commands, MCP server
- **Breaking changes**: None (additive only)
- **Dependencies**: None (pure Rust std)

## Alternatives Considered

1. **External crate for selectors** - Rejected (zero dependency policy)
2. **XPath instead of CSS** - Rejected (CSS more familiar, Cheerio-like)
3. **Only CLI, no MCP** - Rejected (recker integration is key use case)

## Timeline

Phase 1: HAR module + basic selectors
Phase 2: Enhanced scraper + CLI
Phase 3: MCP integration

## Open Questions

1. Should HAR files be compressed by default?
2. Should selectors support CSS4 features?
3. Rate limiting: fixed delay or adaptive?
