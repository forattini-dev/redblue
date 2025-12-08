# Design: HAR Recording, CSS Selectors & Scraper

## Context

redblue needs session recording for replay/debugging and CSS selectors for data extraction. This enables advanced web scraping workflows and integration with recker via MCP.

**Constraints:**
- ZERO external crates
- HAR 1.2 specification compliant
- Cheerio-compatible selector API
- Works via CLI and MCP
- Interactive shell experience (like recker)

## Goals / Non-Goals

### Goals
- HAR recording during any HTTP operation
- HAR replay with timing preservation
- CSS selector engine for HTML parsing
- Cheerio-like API (`select`, `attr`, `text`, `html`)
- Built-in extractors (links, images, meta, forms, tables)
- Declarative extraction schemas
- Interactive scraping commands in shell (`$`, `$text`, `$attr`, etc.)
- CLI commands for crawl/scrape/replay
- MCP tools for recker integration

### Non-Goals
- Full CSS4 selector support (only common selectors)
- JavaScript execution (no headless browser)
- WARC format (only HAR)
- WebSocket recording (HTTP only for now)
- Sourcemap parsing (future enhancement)

## Decisions

### Decision 1: HAR 1.2 Structure

**What:** Implement HAR 1.2 JSON format
**Why:** Industry standard, DevTools compatible

```rust
pub struct Har {
    pub log: HarLog,
}

pub struct HarLog {
    pub version: String,        // "1.2"
    pub creator: HarCreator,
    pub entries: Vec<HarEntry>,
    pub pages: Option<Vec<HarPage>>,
}

pub struct HarEntry {
    pub started_date_time: String,  // ISO 8601
    pub time: f64,                  // Total time in ms
    pub request: HarRequest,
    pub response: HarResponse,
    pub timings: HarTimings,
    pub server_ip_address: Option<String>,
    pub connection: Option<String>,
}

pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    pub query_string: Vec<HarQueryParam>,
    pub post_data: Option<HarPostData>,
    pub headers_size: i64,
    pub body_size: i64,
}

pub struct HarResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    pub content: HarContent,
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

pub struct HarTimings {
    pub blocked: f64,   // Time in queue
    pub dns: f64,       // DNS lookup
    pub connect: f64,   // TCP connect
    pub ssl: f64,       // TLS handshake
    pub send: f64,      // Sending request
    pub wait: f64,      // Waiting for response
    pub receive: f64,   // Receiving response
}

pub struct HarContent {
    pub size: i64,
    pub compression: Option<i64>,
    pub mime_type: String,
    pub text: Option<String>,
    pub encoding: Option<String>,  // "base64" for binary
}
```

### Decision 2: CSS Selector Engine Architecture

**What:** Recursive descent parser for CSS selectors
**Why:** Zero dependencies, covers 95% of use cases

**Supported Selectors (CSS3 subset):**
```
Tag:        div, a, span, p, h1, ...
Class:      .class-name
ID:         #element-id
Universal:  *
Attribute:
  - [href]           - Has attribute
  - [data-x="y"]     - Exact match
  - [href^="https"]  - Starts with
  - [href$=".pdf"]   - Ends with
  - [href*="api"]    - Contains
Combinators:
  - Descendant: div span (any descendant)
  - Child: div > span (direct child only)
  - Adjacent: div + span (immediately after)
  - Sibling: div ~ span (any sibling after)
Pseudo:
  - :first-child, :last-child
  - :nth-child(n), :nth-child(odd), :nth-child(even)
  - :not(selector)
  - :empty
Multiple:   div, span (either)
Compound:   div.class#id[attr] (all must match)
```

**Parser Structure:**
```rust
pub enum Selector {
    Tag(String),
    Class(String),
    Id(String),
    Universal,
    Attribute {
        name: String,
        op: Option<AttrOp>,
        value: Option<String>,
    },
    Descendant(Box<Selector>, Box<Selector>),
    Child(Box<Selector>, Box<Selector>),
    Adjacent(Box<Selector>, Box<Selector>),
    Sibling(Box<Selector>, Box<Selector>),
    And(Vec<Selector>),  // Compound: div.class
    Or(Vec<Selector>),   // Multiple: div, span
    PseudoClass(PseudoClass),
    Not(Box<Selector>),
}

pub enum AttrOp {
    Equals,      // =
    StartsWith,  // ^=
    EndsWith,    // $=
    Contains,    // *=
}
```

### Decision 3: HTML DOM Representation

**What:** Simple DOM tree for selector matching
**Why:** Need tree structure for combinators

```rust
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;

pub struct Element {
    pub tag: String,
    pub attributes: HashMap<String, String>,
    pub children: Vec<Node>,
    pub parent: Option<Weak<RefCell<Element>>>,
}

pub enum Node {
    Element(Rc<RefCell<Element>>),
    Text(String),
    Comment(String),
}

pub struct Document {
    pub root: Node,
    base_url: Option<String>,
}

impl Document {
    pub fn parse(html: &str) -> Result<Self, String>;
    pub fn with_base_url(html: &str, base_url: &str) -> Result<Self, String>;

    // Selection methods (Cheerio-like)
    pub fn select(&self, selector: &str) -> Selection;
    pub fn select_first(&self, selector: &str) -> Option<ElementRef>;
    pub fn select_all(&self, selector: &str) -> Vec<ElementRef>;

    // Quick extraction
    pub fn text(&self, selector: &str) -> String;
    pub fn texts(&self, selector: &str) -> Vec<String>;
    pub fn attr(&self, selector: &str, name: &str) -> Option<String>;
    pub fn attrs(&self, selector: &str, name: &str) -> Vec<String>;
    pub fn html(&self, selector: &str) -> Option<String>;

    // Utility
    pub fn title(&self) -> Option<String>;
    pub fn exists(&self, selector: &str) -> bool;
    pub fn count(&self, selector: &str) -> usize;
}
```

### Decision 4: Built-in Extractors (recker-inspired)

**What:** Pre-built extraction methods for common data
**Why:** Zero-config extraction of links, images, meta, etc.

```rust
impl Document {
    // === Built-in Extractors ===

    /// Extract all links with classification
    pub fn links(&self) -> Vec<ExtractedLink>;
    pub fn links_filtered(&self, selector: &str) -> Vec<ExtractedLink>;

    /// Extract all images
    pub fn images(&self) -> Vec<ExtractedImage>;

    /// Extract meta tags
    pub fn meta(&self) -> ExtractedMeta;

    /// Extract OpenGraph data
    pub fn open_graph(&self) -> OpenGraphData;

    /// Extract Twitter Card data
    pub fn twitter_card(&self) -> TwitterCardData;

    /// Extract JSON-LD structured data
    pub fn json_ld(&self) -> Vec<JsonLdData>;

    /// Extract forms with fields
    pub fn forms(&self) -> Vec<ExtractedForm>;
    pub fn forms_filtered(&self, selector: &str) -> Vec<ExtractedForm>;

    /// Extract tables as structured data
    pub fn tables(&self) -> Vec<ExtractedTable>;
    pub fn tables_filtered(&self, selector: &str) -> Vec<ExtractedTable>;

    /// Extract scripts (external and inline)
    pub fn scripts(&self) -> Vec<ExtractedScript>;

    /// Extract stylesheets
    pub fn styles(&self) -> Vec<ExtractedStyle>;
}

// Extractor types
pub struct ExtractedLink {
    pub href: String,
    pub text: String,
    pub rel: Option<String>,
    pub target: Option<String>,
    pub link_type: LinkType,  // internal, external, mailto, tel, anchor
}

pub struct ExtractedImage {
    pub src: String,
    pub alt: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub srcset: Option<String>,
    pub loading: Option<String>,
}

pub struct ExtractedMeta {
    pub title: Option<String>,
    pub description: Option<String>,
    pub keywords: Vec<String>,
    pub author: Option<String>,
    pub robots: Option<String>,
    pub canonical: Option<String>,
    pub viewport: Option<String>,
    pub charset: Option<String>,
}

pub struct ExtractedForm {
    pub action: Option<String>,
    pub method: Option<String>,
    pub name: Option<String>,
    pub fields: Vec<FormField>,
}

pub struct ExtractedTable {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub caption: Option<String>,
}
```

### Decision 5: Declarative Extraction Schema (recker-inspired)

**What:** Schema-based extraction for complex scraping
**Why:** Clean, reusable extraction definitions

```rust
use std::collections::HashMap;

pub enum FieldConfig {
    /// Simple selector (extracts text)
    Selector(String),

    /// Detailed field config
    Config {
        selector: String,
        attribute: Option<String>,    // Extract attribute instead of text
        multiple: bool,               // Extract all matches
        transform: Option<Transform>, // Post-processing
    },
}

pub enum Transform {
    Trim,
    ParseFloat,
    ParseInt,
    Regex(String),
    Replace(String, String),
    Split(String),
    Custom(fn(String) -> String),
}

impl Document {
    /// Extract structured data using schema
    ///
    /// # Example
    /// ```rust
    /// let product = doc.extract(&[
    ///     ("name", FieldConfig::Selector("h1.title".into())),
    ///     ("price", FieldConfig::Config {
    ///         selector: ".price".into(),
    ///         attribute: None,
    ///         multiple: false,
    ///         transform: Some(Transform::ParseFloat),
    ///     }),
    ///     ("images", FieldConfig::Config {
    ///         selector: ".gallery img".into(),
    ///         attribute: Some("src".into()),
    ///         multiple: true,
    ///         transform: None,
    ///     }),
    /// ]);
    /// ```
    pub fn extract(&self, schema: &[(&str, FieldConfig)]) -> HashMap<String, ExtractedValue>;
}

pub enum ExtractedValue {
    String(String),
    Number(f64),
    Array(Vec<ExtractedValue>),
    None,
}
```

### Decision 6: Interactive Shell Commands (recker-inspired)

**What:** Rich shell commands for interactive scraping
**Why:** Rapid exploration and testing of selectors

**Shell Commands:**
```
Scraping Commands:
  scrap <url>              Load and parse HTML document
  $ <selector>             Count and preview matching elements
  $text <selector>         Extract text content from elements
  $attr <name> <selector>  Extract attribute values
  $html <selector>         Get inner HTML of first match
  $links [selector]        List all links (default: a[href])
  $images [selector]       List all images (default: img[src])
  $scripts                 List all JavaScript files
  $css                     List all CSS files
  $table <selector>        Extract table data (headers + rows)
  $forms [selector]        List forms with fields
  $meta                    Show meta tags
  $og                      Show OpenGraph data
  $json-ld                 Show JSON-LD structured data
```

**Example Shell Session:**
```bash
rb › scrap https://news.ycombinator.com
✔ Loaded (234ms)
  Title: Hacker News
  Elements: 1247
  Size: 45.2kb

rb › $ .titleline
Found 30 element(s)
  1. Show HN: I built something cool
  2. Why Rust is taking over systems programming
  ...

rb › $text .titleline
1. Show HN: I built something cool
2. Why Rust is taking over systems programming
...
  30 text item(s) extracted

rb › $attr href .titleline a
1. https://example.com/article1
2. https://example.com/article2
...
  30 attribute(s) extracted

rb › $links
1. [internal] new → /newest
2. [internal] comments → /newcomments
3. [external] Show HN → https://show.hn/...
...
  150 link(s) found

rb › $table table
Table 1:
  Headers: Rank | Title | Score
  Rows: 30
  1. 1 | Alice | 950
  2. 2 | Bob | 890
  ...

rb › $meta
  title: Hacker News
  description: None
  canonical: None
  robots: None
```

### Decision 7: CLI Commands

**Commands:**

```bash
# === Crawling ===
rb web crawl <url> [OPTIONS]
  --depth <n>        Max crawl depth (default: 3)
  --max-pages <n>    Max pages to crawl (default: 100)
  --har <file>       Save HAR recording
  --same-origin      Only follow same-origin links (default: true)
  -o, --output       Output format: text|json|csv

# === Scraping with Selectors ===
rb web scrape <url> --select <selector> [OPTIONS]
  --select <sel>     CSS selector (required)
  --attr <name>      Extract attribute (default: text content)
  --all              Extract all matches (default: first only)
  --har <file>       Save HAR recording
  -o, --output       Output format: text|json

# === Built-in Extractors ===
rb web links <url>        Extract all links
rb web images <url>       Extract all images
rb web meta <url>         Extract meta tags
rb web forms <url>        Extract forms
rb web tables <url>       Extract tables

# === URL Harvesting (expose existing) ===
rb recon urls <domain> [OPTIONS]
  --source <src>     wayback|urlscan|commoncrawl|otx|all
  --filter <pat>     Include pattern
  --exclude <pat>    Exclude pattern
  -o, --output       Output format: text|json

# === HAR Operations ===
rb web har record <url> -o <file.har>
  # Record single request

rb web har replay <file.har> [OPTIONS]
  --delay <ms>       Delay between requests (default: original timing)
  --base-url <url>   Override base URL
  --validate         Compare responses with recorded

rb web har info <file.har>
  # Show summary: entries, total time, domains, sizes

rb web har export <file.har> --format curl|wget|python
  # Export as executable scripts
```

### Decision 8: MCP Server Tools

**Tools for recker:**

```rust
// Tool definitions for MCP server
pub fn register_scraper_tools(server: &mut McpServer) {
    // Crawl website
    server.register_tool(Tool {
        name: "web_crawl",
        description: "Crawl website and return discovered pages",
        parameters: json!({
            "url": { "type": "string", "required": true },
            "depth": { "type": "integer", "default": 3 },
            "max_pages": { "type": "integer", "default": 50 },
            "record_har": { "type": "boolean", "default": false }
        }),
    });

    // Scrape with CSS selector
    server.register_tool(Tool {
        name: "web_scrape",
        description: "Scrape webpage using CSS selector",
        parameters: json!({
            "url": { "type": "string", "required": true },
            "selector": { "type": "string", "required": true },
            "extract": { "type": "string", "enum": ["text", "html", "attr"], "default": "text" },
            "attr_name": { "type": "string" },
            "all": { "type": "boolean", "default": false }
        }),
    });

    // Query HTML directly (no fetch)
    server.register_tool(Tool {
        name: "html_select",
        description: "Query HTML string with CSS selector",
        parameters: json!({
            "html": { "type": "string", "required": true },
            "selector": { "type": "string", "required": true },
            "extract": { "type": "string", "default": "text" }
        }),
    });

    // Extract links
    server.register_tool(Tool {
        name: "web_links",
        description: "Extract all links from webpage",
        parameters: json!({
            "url": { "type": "string", "required": true },
            "filter": { "type": "string", "enum": ["all", "internal", "external"] }
        }),
    });

    // Extract tables
    server.register_tool(Tool {
        name: "web_tables",
        description: "Extract tables from webpage as structured data",
        parameters: json!({
            "url": { "type": "string", "required": true },
            "selector": { "type": "string" }
        }),
    });

    // HAR operations
    server.register_tool(Tool {
        name: "har_record",
        description: "Record HTTP request to HAR format",
        parameters: json!({
            "url": { "type": "string", "required": true },
            "method": { "type": "string", "default": "GET" }
        }),
    });

    server.register_tool(Tool {
        name: "har_analyze",
        description: "Analyze HAR file and return summary",
        parameters: json!({
            "har_content": { "type": "string", "required": true }
        }),
    });
}
```

### Decision 9: Integration with TUI Shell

**What:** Add scraping state to TuiApp
**Why:** Maintain loaded document for interactive exploration

```rust
// In src/cli/tui.rs
pub struct TuiApp {
    // ... existing fields ...

    // Scraping state
    current_doc: Option<Document>,
    current_doc_url: String,
}

impl TuiApp {
    fn execute_command(&mut self, cmd: &str) -> Result<(), String> {
        // ... existing commands ...

        // Scraping commands
        match parts[0] {
            "scrap" => self.cmd_scrap(&parts[1..])?,
            "$" => self.cmd_select(&parts[1..])?,
            "$text" => self.cmd_select_text(&parts[1..])?,
            "$attr" => self.cmd_select_attr(&parts[1..])?,
            "$html" => self.cmd_select_html(&parts[1..])?,
            "$links" => self.cmd_links(&parts[1..])?,
            "$images" => self.cmd_images(&parts[1..])?,
            "$table" => self.cmd_table(&parts[1..])?,
            "$meta" => self.cmd_meta()?,
            "$forms" => self.cmd_forms(&parts[1..])?,
            // ...
        }
    }
}
```

## File Structure

```
src/
├── protocols/
│   ├── har.rs           # HAR types, serialization, recorder
│   └── selector.rs      # CSS selector parser & matcher
├── modules/
│   └── web/
│       ├── crawler.rs   # (existing, enhance with HAR)
│       ├── scraper.rs   # Scraper with schema extraction
│       ├── dom.rs       # HTML parser, DOM tree
│       └── extractors.rs # Built-in extractors (links, images, etc.)
├── cli/
│   ├── tui.rs           # Add scraping commands
│   └── commands/
│       └── web.rs       # Add crawl, scrape, har commands
└── mcp/
    └── tools/
        └── scraper.rs   # MCP tool handlers
```

## Implementation Order

### Phase 1: Core (Priority)
1. `har.rs` - HAR types and JSON serialization (~300 lines)
2. `dom.rs` - HTML parser to DOM tree (~500 lines)
3. `selector.rs` - CSS selector parser and matcher (~600 lines)

### Phase 2: Extractors
4. `extractors.rs` - Built-in extractors (~400 lines)
5. Schema-based extraction in Document (~200 lines)

### Phase 3: Integration
6. Integrate HAR recorder with HttpClient
7. Enhance `crawler.rs` with HAR support
8. Create `scraper.rs` with config support

### Phase 4: CLI
9. Add shell commands (`scrap`, `$`, `$text`, etc.)
10. Add CLI commands (`rb web crawl`, `rb web scrape`)
11. Expose `rb recon urls` (existing UrlHarvester)

### Phase 5: MCP
12. Create MCP tool handlers
13. Register tools with MCP server
14. Test with recker

## Risks / Trade-offs

| Risk | Impact | Mitigation |
|------|--------|------------|
| CSS selector edge cases | Some selectors won't work | Focus on 95% common cases |
| Large HAR files | Memory/disk usage | Streaming write, optional compression |
| HTML parsing malformed | Crash or incorrect DOM | Lenient parser, skip malformed |
| DOM memory usage | Large pages slow | Lazy loading, streaming |

## Testing Strategy

1. **Unit tests** for selector parser (all selector types)
2. **Unit tests** for DOM parser (edge cases, malformed HTML)
3. **Integration tests** with real websites
4. **HAR validation** against Chrome DevTools output
5. **MCP tests** with mock recker calls

## Summary

This OpenSpec brings:
- **HAR 1.2** recording and replay
- **CSS Selectors** with Cheerio-like API
- **Built-in extractors** (links, images, meta, forms, tables)
- **Declarative schemas** for complex extraction
- **Interactive shell** with `$`, `$text`, `$attr`, etc.
- **CLI commands** for crawl/scrape/replay
- **MCP tools** for recker integration

Total estimated: ~2500 lines of new code, zero external dependencies.
