/// Web Extractors - Built-in extractors for common web data
///
/// Provides Cheerio-like extraction for:
/// - Links (internal, external, mailto, tel, anchor)
/// - Images (with srcset parsing)
/// - Meta tags (title, description, keywords, OpenGraph, Twitter Cards)
/// - Forms and form fields
/// - Tables
/// - Scripts and Styles
/// - JSON-LD structured data

use crate::modules::web::dom::{Document, Element};
use std::collections::HashMap;

// ============================================================================
// Link Extraction
// ============================================================================

/// Type of link found
#[derive(Debug, Clone, PartialEq)]
pub enum LinkType {
    /// Same domain link
    Internal,
    /// Different domain link
    External,
    /// mailto: link
    Mailto,
    /// tel: link
    Telephone,
    /// #anchor link
    Anchor,
    /// javascript: link
    JavaScript,
    /// Other protocol (ftp, magnet, etc.)
    Other(String),
}

/// Extracted link data
#[derive(Debug, Clone)]
pub struct ExtractedLink {
    /// The href attribute
    pub href: String,
    /// Resolved absolute URL (if possible)
    pub url: String,
    /// Link text content
    pub text: String,
    /// rel attribute value
    pub rel: Option<String>,
    /// target attribute value
    pub target: Option<String>,
    /// Classification of link type
    pub link_type: LinkType,
    /// Whether link is nofollow
    pub nofollow: bool,
    /// Title attribute
    pub title: Option<String>,
}

impl ExtractedLink {
    /// Check if this is an internal link
    pub fn is_internal(&self) -> bool {
        matches!(self.link_type, LinkType::Internal)
    }

    /// Check if this is an external link
    pub fn is_external(&self) -> bool {
        matches!(self.link_type, LinkType::External)
    }
}

/// Extract all links from a document
pub fn links(doc: &Document) -> Vec<ExtractedLink> {
    let mut result = Vec::new();
    let base_domain = doc
        .base_url
        .as_ref()
        .and_then(|url| extract_domain(url));

    for elem in doc.all_elements() {
        if elem.tag == "a" {
            if let Some(href) = elem.attr("href") {
                let href = href.clone();
                let resolved = doc.resolve_url(&href);
                let link_type = classify_link(&href, &resolved, base_domain.as_deref());
                let rel = elem.attr("rel").cloned();
                let nofollow = rel
                    .as_ref()
                    .map(|r| r.contains("nofollow"))
                    .unwrap_or(false);

                result.push(ExtractedLink {
                    href: href.clone(),
                    url: resolved,
                    text: doc.element_text(elem.self_index),
                    rel,
                    target: elem.attr("target").cloned(),
                    link_type,
                    nofollow,
                    title: elem.attr("title").cloned(),
                });
            }
        }
    }

    result
}

/// Extract links matching a selector
pub fn links_matching(doc: &Document, selector: &str) -> Vec<ExtractedLink> {
    use crate::protocols::selector::parse;

    let sel = match parse(selector) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let selection = sel.match_in(doc);
    let mut result = Vec::new();
    let base_domain = doc
        .base_url
        .as_ref()
        .and_then(|url| extract_domain(url));

    for elem in selection.iter() {
        // Check the element itself
        if elem.tag == "a" {
            if let Some(href) = elem.attr("href") {
                let href = href.clone();
                let resolved = doc.resolve_url(&href);
                let link_type = classify_link(&href, &resolved, base_domain.as_deref());
                let rel = elem.attr("rel").cloned();
                let nofollow = rel
                    .as_ref()
                    .map(|r| r.contains("nofollow"))
                    .unwrap_or(false);

                result.push(ExtractedLink {
                    href: href.clone(),
                    url: resolved,
                    text: doc.element_text(elem.self_index),
                    rel,
                    target: elem.attr("target").cloned(),
                    link_type,
                    nofollow,
                    title: elem.attr("title").cloned(),
                });
            }
        }

        // Also check descendants for links
        for child in doc.all_elements() {
            if is_descendant_of(doc, child.self_index, elem.self_index) && child.tag == "a" {
                if let Some(href) = child.attr("href") {
                    let href = href.clone();
                    let resolved = doc.resolve_url(&href);
                    let link_type = classify_link(&href, &resolved, base_domain.as_deref());
                    let rel = child.attr("rel").cloned();
                    let nofollow = rel
                        .as_ref()
                        .map(|r| r.contains("nofollow"))
                        .unwrap_or(false);

                    result.push(ExtractedLink {
                        href: href.clone(),
                        url: resolved,
                        text: doc.element_text(child.self_index),
                        rel,
                        target: child.attr("target").cloned(),
                        link_type,
                        nofollow,
                        title: child.attr("title").cloned(),
                    });
                }
            }
        }
    }

    result
}

fn classify_link(href: &str, resolved: &str, base_domain: Option<&str>) -> LinkType {
    let href_lower = href.to_lowercase();

    if href_lower.starts_with("mailto:") {
        return LinkType::Mailto;
    }
    if href_lower.starts_with("tel:") {
        return LinkType::Telephone;
    }
    if href.starts_with('#') {
        return LinkType::Anchor;
    }
    if href_lower.starts_with("javascript:") {
        return LinkType::JavaScript;
    }

    // Check for other protocols
    if let Some(colon_pos) = href.find(':') {
        let protocol = &href[..colon_pos].to_lowercase();
        if !["http", "https"].contains(&protocol.as_str()) {
            return LinkType::Other(protocol.clone());
        }
    }

    // Compare domains for internal/external
    if let Some(base) = base_domain {
        if let Some(link_domain) = extract_domain(resolved) {
            if domains_match(&link_domain, base) {
                return LinkType::Internal;
            } else {
                return LinkType::External;
            }
        }
    }

    // If no base URL, treat relative URLs as internal
    if !href.starts_with("http://") && !href.starts_with("https://") && !href.starts_with("//") {
        LinkType::Internal
    } else {
        LinkType::External
    }
}

fn extract_domain(url: &str) -> Option<String> {
    // Skip protocol
    let without_protocol = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else if url.starts_with("//") {
        &url[2..]
    } else {
        url
    };

    // Get host part (before first /)
    let host = without_protocol.split('/').next()?;

    // Remove port
    let domain = host.split(':').next()?;

    Some(domain.to_lowercase())
}

fn domains_match(domain1: &str, domain2: &str) -> bool {
    // Exact match
    if domain1 == domain2 {
        return true;
    }

    // Check if one is subdomain of the other
    domain1.ends_with(&format!(".{}", domain2)) || domain2.ends_with(&format!(".{}", domain1))
}

fn is_descendant_of(doc: &Document, child_idx: usize, parent_idx: usize) -> bool {
    if child_idx == parent_idx {
        return false;
    }

    let mut current = child_idx;
    while let Some(elem) = doc.get_element(current) {
        if let Some(parent) = elem.parent_index {
            if parent == parent_idx {
                return true;
            }
            current = parent;
        } else {
            break;
        }
    }

    false
}

// ============================================================================
// Image Extraction
// ============================================================================

/// Extracted image data
#[derive(Debug, Clone)]
pub struct ExtractedImage {
    /// src attribute
    pub src: String,
    /// Resolved absolute URL
    pub url: String,
    /// alt text
    pub alt: Option<String>,
    /// width attribute
    pub width: Option<u32>,
    /// height attribute
    pub height: Option<u32>,
    /// srcset attribute (parsed)
    pub srcset: Vec<SrcsetEntry>,
    /// loading attribute (lazy, eager)
    pub loading: Option<String>,
    /// title attribute
    pub title: Option<String>,
}

/// Entry in srcset attribute
#[derive(Debug, Clone)]
pub struct SrcsetEntry {
    pub url: String,
    pub descriptor: String, // e.g., "2x" or "800w"
}

/// Extract all images from a document
pub fn images(doc: &Document) -> Vec<ExtractedImage> {
    let mut result = Vec::new();

    for elem in doc.all_elements() {
        if elem.tag == "img" {
            if let Some(src) = elem.attr("src") {
                let src = src.clone();
                let resolved = doc.resolve_url(&src);

                result.push(ExtractedImage {
                    src: src.clone(),
                    url: resolved,
                    alt: elem.attr("alt").cloned(),
                    width: elem.attr("width").and_then(|w| w.parse().ok()),
                    height: elem.attr("height").and_then(|h| h.parse().ok()),
                    srcset: parse_srcset(elem.attr("srcset").map(|s| s.as_str()).unwrap_or("")),
                    loading: elem.attr("loading").cloned(),
                    title: elem.attr("title").cloned(),
                });
            }
        }
    }

    result
}

fn parse_srcset(srcset: &str) -> Vec<SrcsetEntry> {
    if srcset.is_empty() {
        return Vec::new();
    }

    srcset
        .split(',')
        .filter_map(|entry| {
            let parts: Vec<&str> = entry.trim().split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }

            let url = parts[0].to_string();
            let descriptor = parts.get(1).unwrap_or(&"1x").to_string();

            Some(SrcsetEntry { url, descriptor })
        })
        .collect()
}

// ============================================================================
// Meta Tag Extraction
// ============================================================================

/// Extracted meta information
#[derive(Debug, Clone, Default)]
pub struct ExtractedMeta {
    /// Document title from <title> tag
    pub title: Option<String>,
    /// Meta description
    pub description: Option<String>,
    /// Meta keywords
    pub keywords: Vec<String>,
    /// Author
    pub author: Option<String>,
    /// Canonical URL
    pub canonical: Option<String>,
    /// Robots directive
    pub robots: Option<String>,
    /// Viewport
    pub viewport: Option<String>,
    /// Charset
    pub charset: Option<String>,
    /// Language (from html lang attribute)
    pub language: Option<String>,
    /// All other meta tags
    pub other: HashMap<String, String>,
}

/// OpenGraph data
#[derive(Debug, Clone, Default)]
pub struct OpenGraphData {
    pub og_type: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub image: Option<String>,
    pub image_width: Option<String>,
    pub image_height: Option<String>,
    pub site_name: Option<String>,
    pub locale: Option<String>,
    pub other: HashMap<String, String>,
}

/// Twitter Card data
#[derive(Debug, Clone, Default)]
pub struct TwitterCardData {
    pub card: Option<String>,
    pub site: Option<String>,
    pub creator: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub other: HashMap<String, String>,
}

/// Extract meta information from a document
pub fn meta(doc: &Document) -> ExtractedMeta {
    let mut result = ExtractedMeta::default();

    // Get title from document
    result.title = doc.title().map(|s| s.to_string());

    // Get language from html tag
    for elem in doc.all_elements() {
        if elem.tag == "html" {
            result.language = elem.attr("lang").cloned();
            break;
        }
    }

    // Get canonical from link tag
    for elem in doc.all_elements() {
        if elem.tag == "link" {
            if let Some(rel) = elem.attr("rel") {
                if rel == "canonical" {
                    result.canonical = elem.attr("href").cloned();
                }
            }
        }
    }

    // Process meta tags
    for elem in doc.all_elements() {
        if elem.tag == "meta" {
            // Charset
            if let Some(charset) = elem.attr("charset") {
                result.charset = Some(charset.clone());
            }

            // name/content pairs
            if let (Some(name), Some(content)) = (elem.attr("name"), elem.attr("content")) {
                let name_lower = name.to_lowercase();
                match name_lower.as_str() {
                    "description" => result.description = Some(content.clone()),
                    "keywords" => {
                        result.keywords = content
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    "author" => result.author = Some(content.clone()),
                    "robots" => result.robots = Some(content.clone()),
                    "viewport" => result.viewport = Some(content.clone()),
                    _ => {
                        result.other.insert(name.clone(), content.clone());
                    }
                }
            }

            // http-equiv
            if let (Some(http_equiv), Some(content)) =
                (elem.attr("http-equiv"), elem.attr("content"))
            {
                result.other.insert(http_equiv.clone(), content.clone());
            }
        }
    }

    result
}

/// Extract OpenGraph data
pub fn open_graph(doc: &Document) -> OpenGraphData {
    let mut result = OpenGraphData::default();

    for elem in doc.all_elements() {
        if elem.tag == "meta" {
            if let (Some(property), Some(content)) = (elem.attr("property"), elem.attr("content")) {
                if property.starts_with("og:") {
                    let key = &property[3..];
                    match key {
                        "type" => result.og_type = Some(content.clone()),
                        "title" => result.title = Some(content.clone()),
                        "description" => result.description = Some(content.clone()),
                        "url" => result.url = Some(content.clone()),
                        "image" => result.image = Some(content.clone()),
                        "image:width" => result.image_width = Some(content.clone()),
                        "image:height" => result.image_height = Some(content.clone()),
                        "site_name" => result.site_name = Some(content.clone()),
                        "locale" => result.locale = Some(content.clone()),
                        _ => {
                            result.other.insert(key.to_string(), content.clone());
                        }
                    }
                }
            }
        }
    }

    result
}

/// Extract Twitter Card data
pub fn twitter_card(doc: &Document) -> TwitterCardData {
    let mut result = TwitterCardData::default();

    for elem in doc.all_elements() {
        if elem.tag == "meta" {
            if let (Some(name), Some(content)) = (elem.attr("name"), elem.attr("content")) {
                if name.starts_with("twitter:") {
                    let key = &name[8..];
                    match key {
                        "card" => result.card = Some(content.clone()),
                        "site" => result.site = Some(content.clone()),
                        "creator" => result.creator = Some(content.clone()),
                        "title" => result.title = Some(content.clone()),
                        "description" => result.description = Some(content.clone()),
                        "image" => result.image = Some(content.clone()),
                        _ => {
                            result.other.insert(key.to_string(), content.clone());
                        }
                    }
                }
            }
        }
    }

    result
}

/// Extract JSON-LD data
pub fn json_ld(doc: &Document) -> Vec<String> {
    let mut result = Vec::new();

    for elem in doc.all_elements() {
        if elem.tag == "script" {
            if let Some(script_type) = elem.attr("type") {
                if script_type == "application/ld+json" {
                    let content = doc.element_text(elem.self_index);
                    if !content.is_empty() {
                        result.push(content);
                    }
                }
            }
        }
    }

    result
}

// ============================================================================
// Form Extraction
// ============================================================================

/// Extracted form data
#[derive(Debug, Clone)]
pub struct ExtractedForm {
    /// Form action URL
    pub action: String,
    /// HTTP method (GET, POST)
    pub method: String,
    /// Form name
    pub name: Option<String>,
    /// Form id
    pub id: Option<String>,
    /// enctype attribute
    pub enctype: Option<String>,
    /// Form fields
    pub fields: Vec<FormField>,
}

/// Form field data
#[derive(Debug, Clone)]
pub struct FormField {
    /// Field name
    pub name: Option<String>,
    /// Field type (text, password, email, hidden, etc.)
    pub field_type: String,
    /// Current value
    pub value: Option<String>,
    /// Whether field is required
    pub required: bool,
    /// Placeholder text
    pub placeholder: Option<String>,
    /// Label text (if found)
    pub label: Option<String>,
    /// Options for select fields
    pub options: Vec<SelectOption>,
}

/// Select option
#[derive(Debug, Clone)]
pub struct SelectOption {
    pub value: String,
    pub text: String,
    pub selected: bool,
}

/// Extract all forms from a document
pub fn forms(doc: &Document) -> Vec<ExtractedForm> {
    let mut result = Vec::new();

    for elem in doc.all_elements() {
        if elem.tag == "form" {
            let action = elem.attr("action").cloned().unwrap_or_default();
            let method = elem
                .attr("method")
                .cloned()
                .unwrap_or_else(|| "GET".to_string())
                .to_uppercase();

            let mut form = ExtractedForm {
                action: doc.resolve_url(&action),
                method,
                name: elem.attr("name").cloned(),
                id: elem.attr("id").cloned(),
                enctype: elem.attr("enctype").cloned(),
                fields: Vec::new(),
            };

            // Find all form fields within this form
            let form_idx = elem.self_index;
            for field_elem in doc.all_elements() {
                if is_descendant_of(doc, field_elem.self_index, form_idx) {
                    if let Some(field) = extract_form_field(doc, field_elem) {
                        form.fields.push(field);
                    }
                }
            }

            result.push(form);
        }
    }

    result
}

fn extract_form_field(doc: &Document, elem: &Element) -> Option<FormField> {
    match elem.tag.as_str() {
        "input" => {
            let field_type = elem
                .attr("type")
                .cloned()
                .unwrap_or_else(|| "text".to_string());

            Some(FormField {
                name: elem.attr("name").cloned(),
                field_type,
                value: elem.attr("value").cloned(),
                required: elem.has_attr("required"),
                placeholder: elem.attr("placeholder").cloned(),
                label: find_label_for(doc, elem.attr("id")),
                options: Vec::new(),
            })
        }
        "textarea" => Some(FormField {
            name: elem.attr("name").cloned(),
            field_type: "textarea".to_string(),
            value: Some(doc.element_text(elem.self_index)),
            required: elem.has_attr("required"),
            placeholder: elem.attr("placeholder").cloned(),
            label: find_label_for(doc, elem.attr("id")),
            options: Vec::new(),
        }),
        "select" => {
            let options = extract_select_options(doc, elem.self_index);

            Some(FormField {
                name: elem.attr("name").cloned(),
                field_type: "select".to_string(),
                value: options.iter().find(|o| o.selected).map(|o| o.value.clone()),
                required: elem.has_attr("required"),
                placeholder: None,
                label: find_label_for(doc, elem.attr("id")),
                options,
            })
        }
        "button" => Some(FormField {
            name: elem.attr("name").cloned(),
            field_type: elem
                .attr("type")
                .cloned()
                .unwrap_or_else(|| "submit".to_string()),
            value: elem.attr("value").cloned(),
            required: false,
            placeholder: None,
            label: None,
            options: Vec::new(),
        }),
        _ => None,
    }
}

fn find_label_for(doc: &Document, field_id: Option<&String>) -> Option<String> {
    let field_id = field_id?;

    for elem in doc.all_elements() {
        if elem.tag == "label" {
            if let Some(for_attr) = elem.attr("for") {
                if for_attr == field_id {
                    return Some(doc.element_text(elem.self_index));
                }
            }
        }
    }

    None
}

fn extract_select_options(doc: &Document, select_idx: usize) -> Vec<SelectOption> {
    let mut options = Vec::new();

    for elem in doc.all_elements() {
        if elem.tag == "option" && is_descendant_of(doc, elem.self_index, select_idx) {
            options.push(SelectOption {
                value: elem
                    .attr("value")
                    .cloned()
                    .unwrap_or_else(|| doc.element_text(elem.self_index)),
                text: doc.element_text(elem.self_index),
                selected: elem.has_attr("selected"),
            });
        }
    }

    options
}

// ============================================================================
// Table Extraction
// ============================================================================

/// Extracted table data
#[derive(Debug, Clone)]
pub struct ExtractedTable {
    /// Table caption
    pub caption: Option<String>,
    /// Header row (from thead or first tr with th)
    pub headers: Vec<String>,
    /// Data rows
    pub rows: Vec<Vec<String>>,
    /// Table id
    pub id: Option<String>,
    /// Table class
    pub class: Option<String>,
}

/// Extract all tables from a document
pub fn tables(doc: &Document) -> Vec<ExtractedTable> {
    let mut result = Vec::new();

    for elem in doc.all_elements() {
        if elem.tag == "table" {
            let table_idx = elem.self_index;

            let mut table = ExtractedTable {
                caption: None,
                headers: Vec::new(),
                rows: Vec::new(),
                id: elem.attr("id").cloned(),
                class: elem.attr("class").cloned(),
            };

            // Find caption
            for child in doc.all_elements() {
                if child.tag == "caption" && is_descendant_of(doc, child.self_index, table_idx) {
                    table.caption = Some(doc.element_text(child.self_index));
                    break;
                }
            }

            // Find headers (from thead or th elements)
            let mut found_thead = false;
            for child in doc.all_elements() {
                if child.tag == "thead" && is_descendant_of(doc, child.self_index, table_idx) {
                    found_thead = true;
                    // Get th elements from thead
                    for th in doc.all_elements() {
                        if th.tag == "th" && is_descendant_of(doc, th.self_index, child.self_index) {
                            table.headers.push(doc.element_text(th.self_index));
                        }
                    }
                    break;
                }
            }

            // If no thead, look for th in first tr
            if !found_thead && table.headers.is_empty() {
                for tr in doc.all_elements() {
                    if tr.tag == "tr" && is_descendant_of(doc, tr.self_index, table_idx) {
                        for th in doc.all_elements() {
                            if th.tag == "th" && is_descendant_of(doc, th.self_index, tr.self_index)
                            {
                                table.headers.push(doc.element_text(th.self_index));
                            }
                        }
                        if !table.headers.is_empty() {
                            break;
                        }
                    }
                }
            }

            // Find data rows
            for tr in doc.all_elements() {
                if tr.tag == "tr" && is_descendant_of(doc, tr.self_index, table_idx) {
                    let mut row = Vec::new();
                    let mut has_td = false;

                    for td in doc.all_elements() {
                        if td.tag == "td" && is_descendant_of(doc, td.self_index, tr.self_index) {
                            has_td = true;
                            row.push(doc.element_text(td.self_index));
                        }
                    }

                    if has_td {
                        table.rows.push(row);
                    }
                }
            }

            result.push(table);
        }
    }

    result
}

// ============================================================================
// Script and Style Extraction
// ============================================================================

/// Extracted script data
#[derive(Debug, Clone)]
pub struct ExtractedScript {
    /// src attribute (external script)
    pub src: Option<String>,
    /// Resolved URL (if src present)
    pub url: Option<String>,
    /// type attribute
    pub script_type: Option<String>,
    /// async attribute present
    pub is_async: bool,
    /// defer attribute present
    pub defer: bool,
    /// Inline content (if no src)
    pub inline: Option<String>,
    /// crossorigin attribute
    pub crossorigin: Option<String>,
    /// integrity attribute (SRI)
    pub integrity: Option<String>,
}

/// Extract all scripts from a document
pub fn scripts(doc: &Document) -> Vec<ExtractedScript> {
    let mut result = Vec::new();

    for elem in doc.all_elements() {
        if elem.tag == "script" {
            let src = elem.attr("src").cloned();
            let url = src.as_ref().map(|s| doc.resolve_url(s));

            // Skip JSON-LD scripts
            if let Some(script_type) = elem.attr("type") {
                if script_type == "application/ld+json" {
                    continue;
                }
            }

            let inline = if src.is_none() {
                let content = doc.element_text(elem.self_index);
                if content.is_empty() {
                    None
                } else {
                    Some(content)
                }
            } else {
                None
            };

            result.push(ExtractedScript {
                src,
                url,
                script_type: elem.attr("type").cloned(),
                is_async: elem.has_attr("async"),
                defer: elem.has_attr("defer"),
                inline,
                crossorigin: elem.attr("crossorigin").cloned(),
                integrity: elem.attr("integrity").cloned(),
            });
        }
    }

    result
}

/// Extracted stylesheet data
#[derive(Debug, Clone)]
pub struct ExtractedStyle {
    /// href attribute (external stylesheet)
    pub href: Option<String>,
    /// Resolved URL (if href present)
    pub url: Option<String>,
    /// media attribute
    pub media: Option<String>,
    /// Inline content (if style tag)
    pub inline: Option<String>,
    /// rel attribute (usually "stylesheet")
    pub rel: Option<String>,
    /// integrity attribute (SRI)
    pub integrity: Option<String>,
}

/// Extract all stylesheets from a document
pub fn styles(doc: &Document) -> Vec<ExtractedStyle> {
    let mut result = Vec::new();

    // External stylesheets from link tags
    for elem in doc.all_elements() {
        if elem.tag == "link" {
            if let Some(rel) = elem.attr("rel") {
                if rel.contains("stylesheet") {
                    let href = elem.attr("href").cloned();
                    let url = href.as_ref().map(|h| doc.resolve_url(h));

                    result.push(ExtractedStyle {
                        href,
                        url,
                        media: elem.attr("media").cloned(),
                        inline: None,
                        rel: Some(rel.clone()),
                        integrity: elem.attr("integrity").cloned(),
                    });
                }
            }
        }
    }

    // Inline styles from style tags
    for elem in doc.all_elements() {
        if elem.tag == "style" {
            let content = doc.element_text(elem.self_index);
            if !content.is_empty() {
                result.push(ExtractedStyle {
                    href: None,
                    url: None,
                    media: elem.attr("media").cloned(),
                    inline: Some(content),
                    rel: None,
                    integrity: None,
                });
            }
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_links() {
        let html = r##"
            <html>
            <body>
                <a href="https://example.com">External</a>
                <a href="/page">Internal</a>
                <a href="mailto:test@example.com">Email</a>
                <a href="tel:+1234567890">Phone</a>
                <a href="#section">Anchor</a>
                <a href="page.html" rel="nofollow">Nofollow</a>
            </body>
            </html>
        "##;

        let doc = Document::parse_with_base(html, "https://test.com/");
        let extracted = links(&doc);

        assert_eq!(extracted.len(), 6);

        assert!(extracted.iter().any(|l| l.is_external()));
        assert!(extracted.iter().any(|l| l.is_internal()));
        assert!(extracted
            .iter()
            .any(|l| matches!(l.link_type, LinkType::Mailto)));
        assert!(extracted
            .iter()
            .any(|l| matches!(l.link_type, LinkType::Telephone)));
        assert!(extracted
            .iter()
            .any(|l| matches!(l.link_type, LinkType::Anchor)));
        assert!(extracted.iter().any(|l| l.nofollow));
    }

    #[test]
    fn test_extract_images() {
        let html = r#"
            <html>
            <body>
                <img src="image.png" alt="Test" width="100" height="50">
                <img src="photo.jpg" srcset="photo-2x.jpg 2x, photo-3x.jpg 3x" loading="lazy">
            </body>
            </html>
        "#;

        let doc = Document::parse(html);
        let extracted = images(&doc);

        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].alt, Some("Test".to_string()));
        assert_eq!(extracted[0].width, Some(100));
        assert_eq!(extracted[1].srcset.len(), 2);
        assert_eq!(extracted[1].loading, Some("lazy".to_string()));
    }

    #[test]
    fn test_extract_meta() {
        let html = r#"
            <html lang="en">
            <head>
                <title>Test Page</title>
                <meta charset="utf-8">
                <meta name="description" content="A test page">
                <meta name="keywords" content="test, page, demo">
                <meta name="author" content="Test Author">
                <link rel="canonical" href="https://example.com/page">
            </head>
            </html>
        "#;

        let doc = Document::parse(html);
        let extracted = meta(&doc);

        assert_eq!(extracted.title, Some("Test Page".to_string()));
        assert_eq!(extracted.description, Some("A test page".to_string()));
        assert_eq!(extracted.keywords, vec!["test", "page", "demo"]);
        assert_eq!(extracted.author, Some("Test Author".to_string()));
        assert_eq!(
            extracted.canonical,
            Some("https://example.com/page".to_string())
        );
        assert_eq!(extracted.charset, Some("utf-8".to_string()));
        assert_eq!(extracted.language, Some("en".to_string()));
    }

    #[test]
    fn test_extract_opengraph() {
        let html = r#"
            <html>
            <head>
                <meta property="og:type" content="website">
                <meta property="og:title" content="OG Title">
                <meta property="og:description" content="OG Description">
                <meta property="og:image" content="https://example.com/image.png">
            </head>
            </html>
        "#;

        let doc = Document::parse(html);
        let og = open_graph(&doc);

        assert_eq!(og.og_type, Some("website".to_string()));
        assert_eq!(og.title, Some("OG Title".to_string()));
        assert_eq!(og.description, Some("OG Description".to_string()));
        assert_eq!(og.image, Some("https://example.com/image.png".to_string()));
    }

    #[test]
    fn test_extract_twitter_card() {
        let html = r#"
            <html>
            <head>
                <meta name="twitter:card" content="summary_large_image">
                <meta name="twitter:site" content="@example">
                <meta name="twitter:title" content="Twitter Title">
            </head>
            </html>
        "#;

        let doc = Document::parse(html);
        let tc = twitter_card(&doc);

        assert_eq!(tc.card, Some("summary_large_image".to_string()));
        assert_eq!(tc.site, Some("@example".to_string()));
        assert_eq!(tc.title, Some("Twitter Title".to_string()));
    }

    #[test]
    fn test_extract_forms() {
        let html = r#"
            <html>
            <body>
                <form action="/submit" method="POST">
                    <input type="text" name="username" required>
                    <input type="password" name="password">
                    <input type="hidden" name="token" value="abc123">
                    <select name="country">
                        <option value="us">United States</option>
                        <option value="uk" selected>United Kingdom</option>
                    </select>
                    <button type="submit">Submit</button>
                </form>
            </body>
            </html>
        "#;

        let doc = Document::parse_with_base(html, "https://example.com/");
        let extracted = forms(&doc);

        assert_eq!(extracted.len(), 1);
        let form = &extracted[0];
        assert_eq!(form.action, "https://example.com/submit");
        assert_eq!(form.method, "POST");
        assert!(form.fields.len() >= 4);

        // Check hidden field
        let hidden = form.fields.iter().find(|f| f.field_type == "hidden");
        assert!(hidden.is_some());
        assert_eq!(hidden.unwrap().value, Some("abc123".to_string()));

        // Check select
        let select = form.fields.iter().find(|f| f.field_type == "select");
        assert!(select.is_some());
        assert_eq!(select.unwrap().options.len(), 2);
    }

    #[test]
    fn test_extract_tables() {
        let html = r#"
            <html>
            <body>
                <table>
                    <caption>Test Table</caption>
                    <thead>
                        <tr><th>Name</th><th>Age</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>Alice</td><td>30</td></tr>
                        <tr><td>Bob</td><td>25</td></tr>
                    </tbody>
                </table>
            </body>
            </html>
        "#;

        let doc = Document::parse(html);
        let extracted = tables(&doc);

        assert_eq!(extracted.len(), 1);
        let table = &extracted[0];
        assert_eq!(table.caption, Some("Test Table".to_string()));
        assert_eq!(table.headers, vec!["Name", "Age"]);
        assert_eq!(table.rows.len(), 2);
        assert_eq!(table.rows[0], vec!["Alice", "30"]);
    }

    #[test]
    fn test_extract_scripts() {
        let html = r#"
            <html>
            <head>
                <script src="app.js" async defer></script>
                <script type="application/ld+json">{"@type": "WebPage"}</script>
            </head>
            <body>
                <script>console.log('inline');</script>
            </body>
            </html>
        "#;

        let doc = Document::parse(html);
        let extracted = scripts(&doc);

        // Should skip JSON-LD script
        assert_eq!(extracted.len(), 2);

        let external = extracted.iter().find(|s| s.src.is_some());
        assert!(external.is_some());
        assert!(external.unwrap().is_async);
        assert!(external.unwrap().defer);

        let inline = extracted.iter().find(|s| s.inline.is_some());
        assert!(inline.is_some());
    }

    #[test]
    fn test_extract_styles() {
        let html = r#"
            <html>
            <head>
                <link rel="stylesheet" href="style.css" media="screen">
                <style>body { margin: 0; }</style>
            </head>
            </html>
        "#;

        let doc = Document::parse(html);
        let extracted = styles(&doc);

        assert_eq!(extracted.len(), 2);

        let external = extracted.iter().find(|s| s.href.is_some());
        assert!(external.is_some());
        assert_eq!(external.unwrap().media, Some("screen".to_string()));

        let inline = extracted.iter().find(|s| s.inline.is_some());
        assert!(inline.is_some());
    }

    #[test]
    fn test_json_ld_extraction() {
        let html = r#"
            <html>
            <head>
                <script type="application/ld+json">
                    {"@type": "Organization", "name": "Example"}
                </script>
            </head>
            </html>
        "#;

        let doc = Document::parse(html);
        let ld = json_ld(&doc);

        assert_eq!(ld.len(), 1);
        assert!(ld[0].contains("Organization"));
    }
}
