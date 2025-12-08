# Tasks: HAR Recording, CSS Selectors & Scraper

## Phase 1: Core

### HAR Module (`src/protocols/har.rs`)
- [ ] Define HAR 1.2 structs (Har, HarLog, HarEntry, HarRequest, HarResponse, HarTimings, HarContent)
- [ ] Define HarCreator, HarPage, HarHeader, HarQueryParam, HarPostData
- [ ] Implement JSON serialization (manual, no serde)
- [ ] Implement JSON deserialization for replay
- [ ] Add HarRecorder struct for capturing requests
- [ ] Add timing capture helpers (start/stop timestamps)
- [ ] Add save_to_file() and load_from_file() methods

### DOM Parser (`src/modules/web/dom.rs`)
- [ ] Define Element struct (tag, attributes, children, parent)
- [ ] Define Node enum (Element, Text, Comment)
- [ ] Define Document struct with base_url support
- [ ] Implement HTML tokenizer (handle tags, attributes, text, comments)
- [ ] Build DOM tree from tokens
- [ ] Handle self-closing tags (br, img, input, etc.)
- [ ] Handle malformed HTML gracefully (unclosed tags, etc.)
- [ ] Implement text() extraction (combined text content)
- [ ] Implement html() extraction (inner HTML)
- [ ] Implement outer_html() extraction
- [ ] Add attribute access methods (attr, attrs, has_attr)
- [ ] Add class helpers (has_class, classes)

### CSS Selector Engine (`src/protocols/selector.rs`)
- [ ] Define Selector AST types (Tag, Class, Id, Universal, Attribute, etc.)
- [ ] Define AttrOp enum (Equals, StartsWith, EndsWith, Contains)
- [ ] Define PseudoClass enum (FirstChild, LastChild, NthChild, Empty, Not)
- [ ] Implement selector parser (recursive descent)
- [ ] Parse tag selectors (div, a, span)
- [ ] Parse class selectors (.class-name)
- [ ] Parse ID selectors (#element-id)
- [ ] Parse universal selector (*)
- [ ] Parse attribute selectors ([href], [href="value"], [href^=""], etc.)
- [ ] Parse descendant combinator (div span)
- [ ] Parse child combinator (div > span)
- [ ] Parse adjacent sibling combinator (div + span)
- [ ] Parse general sibling combinator (div ~ span)
- [ ] Parse compound selectors (div.class#id[attr])
- [ ] Parse multiple selectors (div, span)
- [ ] Parse :first-child, :last-child pseudo-classes
- [ ] Parse :nth-child(n), :nth-child(odd), :nth-child(even)
- [ ] Parse :not(selector) pseudo-class
- [ ] Parse :empty pseudo-class
- [ ] Implement selector matching against Element
- [ ] Implement Document.select() returning Selection
- [ ] Implement Document.select_first() returning Option<ElementRef>
- [ ] Implement Document.select_all() returning Vec<ElementRef>

## Phase 2: Built-in Extractors

### Extractors (`src/modules/web/extractors.rs`)
- [ ] Define ExtractedLink struct (href, text, rel, target, link_type)
- [ ] Define LinkType enum (Internal, External, Mailto, Tel, Anchor)
- [ ] Implement links() extractor with URL classification
- [ ] Define ExtractedImage struct (src, alt, width, height, srcset, loading)
- [ ] Implement images() extractor
- [ ] Define ExtractedMeta struct (title, description, keywords, author, etc.)
- [ ] Implement meta() extractor (parse meta tags)
- [ ] Define OpenGraphData struct
- [ ] Implement open_graph() extractor (og: meta tags)
- [ ] Define TwitterCardData struct
- [ ] Implement twitter_card() extractor (twitter: meta tags)
- [ ] Define JsonLdData type (parsed JSON-LD)
- [ ] Implement json_ld() extractor (script type="application/ld+json")
- [ ] Define ExtractedForm struct (action, method, name, fields)
- [ ] Define FormField struct (name, type, value, required, options)
- [ ] Implement forms() extractor
- [ ] Define ExtractedTable struct (headers, rows, caption)
- [ ] Implement tables() extractor
- [ ] Define ExtractedScript struct (src, type, async, defer, inline)
- [ ] Implement scripts() extractor
- [ ] Define ExtractedStyle struct (href, media, inline)
- [ ] Implement styles() extractor

### Schema Extraction
- [ ] Define FieldConfig enum (Selector, Config)
- [ ] Define Transform enum (Trim, ParseFloat, ParseInt, Regex, Replace, Split)
- [ ] Define ExtractedValue enum (String, Number, Array, None)
- [ ] Implement Document.extract() with schema support
- [ ] Add transform application to extracted values

## Phase 3: Integration

### HTTP Client HAR Integration
- [ ] Add har_recorder: Option<HarRecorder> to HttpClient
- [ ] Capture request details in send() method
- [ ] Capture response details and timings
- [ ] Add with_har_recording() builder method
- [ ] Add get_har() method to retrieve recorded HAR
- [ ] Add save_har(path) method to write HAR file

### Enhanced Crawler (`src/modules/web/crawler.rs`)
- [ ] Add HAR recording option to WebCrawler
- [ ] Integrate DOM parser for better link extraction
- [ ] Use selector engine for form/asset extraction
- [ ] Add callback for each page crawled
- [ ] Add HAR export after crawl

### Scraper Module (`src/modules/web/scraper.rs`)
- [ ] Define ScrapeConfig struct
- [ ] Define ScrapeRule struct
- [ ] Support YAML-like config parsing (manual parser)
- [ ] Execute extraction rules against Document
- [ ] Support nested extractions
- [ ] Add pagination support (next page selector)
- [ ] Add rate limiting

## Phase 4: Shell Commands

### Interactive Scraping Commands (TUI)
- [ ] Add current_doc: Option<Document> to TuiApp
- [ ] Add current_doc_url: String to TuiApp
- [ ] Implement `scrap <url>` command (fetch and parse)
- [ ] Implement `$ <selector>` command (count and preview)
- [ ] Implement `$text <selector>` command (extract text)
- [ ] Implement `$attr <name> <selector>` command (extract attribute)
- [ ] Implement `$html <selector>` command (get inner HTML)
- [ ] Implement `$links [selector]` command (list links)
- [ ] Implement `$images [selector]` command (list images)
- [ ] Implement `$scripts` command (list JS files)
- [ ] Implement `$css` command (list CSS files)
- [ ] Implement `$table <selector>` command (extract table)
- [ ] Implement `$forms [selector]` command (list forms)
- [ ] Implement `$meta` command (show meta tags)
- [ ] Implement `$og` command (show OpenGraph)
- [ ] Implement `$json-ld` command (show JSON-LD)
- [ ] Update help command with scraping commands

### CLI Commands (`src/cli/commands/web.rs`)
- [ ] Add `rb web crawl` command
- [ ] Add `rb web scrape` command with --select flag
- [ ] Add `rb web links` command
- [ ] Add `rb web images` command
- [ ] Add `rb web meta` command
- [ ] Add `rb web forms` command
- [ ] Add `rb web tables` command

### HAR CLI Commands
- [ ] Add `rb web har record` command
- [ ] Add `rb web har replay` command
- [ ] Add `rb web har info` command
- [ ] Add `rb web har export` command (curl/wget/python)

### URL Harvester CLI
- [ ] Expose `rb recon urls <domain>` command
- [ ] Add --source flag (wayback, urlscan, commoncrawl, otx, all)
- [ ] Add --filter and --exclude flags
- [ ] Add output format support (text, json)

## Phase 5: MCP Integration

### MCP Tool Handlers (`src/mcp/tools/scraper.rs`)
- [ ] Implement handle_web_crawl tool
- [ ] Implement handle_web_scrape tool
- [ ] Implement handle_html_select tool (no HTTP, just parse)
- [ ] Implement handle_web_links tool
- [ ] Implement handle_web_tables tool
- [ ] Implement handle_har_record tool
- [ ] Implement handle_har_analyze tool

### Register with MCP Server
- [ ] Add tool definitions to MCP server
- [ ] Wire up handlers
- [ ] Add tool documentation

## Testing

### Unit Tests
- [ ] Selector parser tests (all selector types)
- [ ] Selector matching tests
- [ ] DOM parser tests (well-formed HTML)
- [ ] DOM parser tests (malformed HTML)
- [ ] HAR serialization tests
- [ ] HAR deserialization tests
- [ ] Extractor tests (links, images, meta, etc.)
- [ ] Schema extraction tests

### Integration Tests
- [ ] Crawl real website test
- [ ] Scrape with selectors test
- [ ] HAR recording test
- [ ] HAR replay test
- [ ] HAR compatibility with Chrome DevTools export

### MCP Tests
- [ ] web_crawl tool test
- [ ] web_scrape tool test
- [ ] html_select tool test

## Documentation

- [ ] Update README with scraping examples
- [ ] Document CSS selector syntax support
- [ ] Document shell scraping commands
- [ ] Document HAR format and usage
- [ ] Document MCP tools for recker
- [ ] Add examples for common scraping scenarios

## Summary

| Phase | Items | Est. Lines |
|-------|-------|------------|
| 1. Core | HAR + DOM + Selectors | ~1400 |
| 2. Extractors | Built-ins + Schema | ~600 |
| 3. Integration | HTTP + Crawler + Scraper | ~400 |
| 4. CLI | Shell + Commands | ~500 |
| 5. MCP | Tools + Registration | ~200 |
| **Total** | | **~3100** |
