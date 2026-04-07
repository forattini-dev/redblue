/// HTML Data Extractors
///
/// Utility functions that operate on a parsed `HtmlDocument` (arena-based DOM)
/// to extract structured data: links, images, meta tags, forms, tables,
/// scripts, and styles.
///
/// All functions accept `&HtmlDocument` as their first argument and return
/// owned data structures. URL resolution is handled by the standalone
/// `resolve_url` helper.
///
/// NO external dependencies -- pure Rust std implementation.
use super::parser::{HtmlDocument, NodeType};

// ============================================================================
// Link Extraction
// ============================================================================

/// Classification of a link based on its href
#[derive(Debug, Clone, PartialEq)]
pub enum LinkType {
  /// Same-domain link (or relative path when no base given)
  Internal,
  /// Different-domain link
  External,
  /// Fragment-only anchor (`#section`)
  Anchor,
  /// `mailto:` link
  Mailto,
  /// `tel:` link
  Tel,
  /// `javascript:` link
  JavaScript,
  /// Anything else (ftp, magnet, data, etc.)
  Other,
}

/// A single link extracted from an `<a>` element
#[derive(Debug, Clone)]
pub struct ExtractedLink {
  pub href: String,
  pub text: String,
  pub rel: Option<String>,
  pub target: Option<String>,
  pub title: Option<String>,
  pub link_type: LinkType,
}

/// Extract all links from the document.
///
/// Finds every `<a>` element that has an `href` attribute, extracts its
/// text content and metadata, classifies the link type, and optionally
/// resolves relative URLs against `base_url`.
pub fn extract_links(doc: &HtmlDocument, base_url: Option<&str>) -> Vec<ExtractedLink> {
  let base_domain = base_url.and_then(extract_domain);
  let mut result = Vec::new();

  for id in doc.select("a[href]") {
    let href = match doc.get_attribute(id, "href") {
      Some(h) => h.to_string(),
      None => continue,
    };

    let resolved = match base_url {
      Some(base) => resolve_url(&href, base),
      None => href.clone(),
    };

    let link_type = classify_link(&href, &resolved, base_domain);

    result.push(ExtractedLink {
      href,
      text: doc.text_content(id),
      rel: doc.get_attribute(id, "rel").map(|s| s.to_string()),
      target: doc.get_attribute(id, "target").map(|s| s.to_string()),
      title: doc.get_attribute(id, "title").map(|s| s.to_string()),
      link_type,
    });
  }

  result
}

/// Determine the `LinkType` for a given href.
fn classify_link(href: &str, resolved: &str, base_domain: Option<&str>) -> LinkType {
  let lower = href.to_ascii_lowercase();

  if lower.starts_with("mailto:") {
    return LinkType::Mailto;
  }
  if lower.starts_with("tel:") {
    return LinkType::Tel;
  }
  if href.starts_with('#') {
    return LinkType::Anchor;
  }
  if lower.starts_with("javascript:") {
    return LinkType::JavaScript;
  }

  // Detect non-http protocols
  if let Some(colon) = href.find(':') {
    let proto = &href[..colon].to_ascii_lowercase();
    if proto != "http" && proto != "https" {
      return LinkType::Other;
    }
  }

  // Compare domains for internal vs external
  if let Some(base) = base_domain {
    if let Some(link_domain) = extract_domain(resolved) {
      if !domains_match(link_domain, base) {
        return LinkType::External;
      }
    }
  }

  LinkType::Internal
}

// ============================================================================
// Image Extraction
// ============================================================================

/// A single image extracted from an `<img>` element
#[derive(Debug, Clone)]
pub struct ExtractedImage {
  pub src: String,
  pub alt: Option<String>,
  pub title: Option<String>,
  pub width: Option<String>,
  pub height: Option<String>,
  pub loading: Option<String>,
}

/// Extract all images from the document.
///
/// Finds every `<img>` element with a `src` attribute, resolves relative
/// URLs when `base_url` is provided, and captures common attributes.
pub fn extract_images(doc: &HtmlDocument, base_url: Option<&str>) -> Vec<ExtractedImage> {
  let mut result = Vec::new();

  for id in doc.select("img[src]") {
    let raw_src = match doc.get_attribute(id, "src") {
      Some(s) => s.to_string(),
      None => continue,
    };

    let src = match base_url {
      Some(base) => resolve_url(&raw_src, base),
      None => raw_src,
    };

    result.push(ExtractedImage {
      src,
      alt: doc.get_attribute(id, "alt").map(|s| s.to_string()),
      title: doc.get_attribute(id, "title").map(|s| s.to_string()),
      width: doc.get_attribute(id, "width").map(|s| s.to_string()),
      height: doc.get_attribute(id, "height").map(|s| s.to_string()),
      loading: doc.get_attribute(id, "loading").map(|s| s.to_string()),
    });
  }

  result
}

// ============================================================================
// Meta Tag Extraction
// ============================================================================

/// Aggregated metadata extracted from `<head>` elements.
#[derive(Debug, Clone, Default)]
pub struct ExtractedMeta {
  pub title: Option<String>,
  pub description: Option<String>,
  pub keywords: Vec<String>,
  pub author: Option<String>,
  pub robots: Vec<String>,
  pub canonical: Option<String>,
  pub viewport: Option<String>,
  pub charset: Option<String>,
  /// OpenGraph `<meta property="og:*">` pairs
  pub og: Vec<(String, String)>,
  /// Twitter Card `<meta name="twitter:*">` pairs
  pub twitter: Vec<(String, String)>,
  /// All remaining `<meta name="..." content="...">` pairs
  pub other: Vec<(String, String)>,
}

/// Extract metadata from the document.
///
/// Processes `<title>`, `<meta>`, and `<link rel="canonical">` elements
/// to build a consolidated `ExtractedMeta` structure.
pub fn extract_meta(doc: &HtmlDocument) -> ExtractedMeta {
  let mut meta = ExtractedMeta::default();

  // Title
  if let Some(id) = doc.select_one("title") {
    let text = doc.text_content(id);
    if !text.is_empty() {
      meta.title = Some(text);
    }
  }

  // Canonical link
  for id in doc.select("link[rel]") {
    if let Some(rel) = doc.get_attribute(id, "rel") {
      if rel.eq_ignore_ascii_case("canonical") {
        meta.canonical = doc.get_attribute(id, "href").map(|s| s.to_string());
      }
    }
  }

  // Meta tags
  for id in doc.select("meta") {
    // charset attribute: <meta charset="utf-8">
    if let Some(cs) = doc.get_attribute(id, "charset") {
      meta.charset = Some(cs.to_string());
    }

    // http-equiv Content-Type with charset in content
    if let Some(equiv) = doc.get_attribute(id, "http-equiv") {
      if equiv.eq_ignore_ascii_case("content-type") {
        if let Some(content) = doc.get_attribute(id, "content") {
          if let Some(pos) = content.to_ascii_lowercase().find("charset=") {
            let cs = content[pos + 8..].trim().trim_end_matches(';');
            meta.charset = Some(cs.to_string());
          }
        }
      }
    }

    // OpenGraph: <meta property="og:*" content="...">
    if let Some(property) = doc.get_attribute(id, "property") {
      let prop_lower = property.to_ascii_lowercase();
      if prop_lower.starts_with("og:") {
        if let Some(content) = doc.get_attribute(id, "content") {
          meta.og.push((prop_lower, content.to_string()));
        }
        continue;
      }
    }

    // name/content pairs
    if let Some(name) = doc.get_attribute(id, "name") {
      let name_lower = name.to_ascii_lowercase();
      let content = doc
        .get_attribute(id, "content")
        .unwrap_or("")
        .to_string();

      match name_lower.as_str() {
        "description" => meta.description = Some(content),
        "keywords" => {
          meta.keywords = content
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        }
        "author" => meta.author = Some(content),
        "robots" => {
          meta.robots = content
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        }
        "viewport" => meta.viewport = Some(content),
        _ if name_lower.starts_with("twitter:") => {
          meta.twitter.push((name_lower, content));
        }
        _ => {
          if !content.is_empty() {
            meta.other.push((name_lower, content));
          }
        }
      }
    }
  }

  meta
}

// ============================================================================
// Form Extraction
// ============================================================================

/// A `<select>` option
#[derive(Debug, Clone)]
pub struct SelectOption {
  pub value: String,
  pub text: String,
  pub selected: bool,
}

/// A field inside a form (`<input>`, `<textarea>`, `<select>`, submit `<button>`)
#[derive(Debug, Clone)]
pub struct FormField {
  pub name: Option<String>,
  /// `text`, `email`, `password`, `hidden`, `textarea`, `select`, `submit`, etc.
  pub field_type: String,
  pub value: Option<String>,
  pub placeholder: Option<String>,
  pub required: bool,
  /// Populated for `<select>` elements
  pub options: Vec<SelectOption>,
}

/// A `<form>` element with its contained fields
#[derive(Debug, Clone)]
pub struct ExtractedForm {
  pub action: Option<String>,
  pub method: Option<String>,
  pub name: Option<String>,
  pub id: Option<String>,
  pub fields: Vec<FormField>,
}

/// Extract all forms and their fields from the document.
///
/// For each `<form>`, collects `action`, `method`, `name`, `id`, then walks
/// descendant elements to find `<input>`, `<textarea>`, `<select>`, and
/// `<button type="submit">`.
pub fn extract_forms(doc: &HtmlDocument) -> Vec<ExtractedForm> {
  let mut result = Vec::new();

  for id in doc.select("form") {

    let mut form = ExtractedForm {
      action: doc.get_attribute(id, "action").map(|s| s.to_string()),
      method: doc.get_attribute(id, "method").map(|s| s.to_string()),
      name: doc.get_attribute(id, "name").map(|s| s.to_string()),
      id: doc.get_attribute(id, "id").map(|s| s.to_string()),
      fields: Vec::new(),
    };

    // Walk descendants of this form
    collect_form_fields(doc, id, &mut form.fields);

    result.push(form);
  }

  result
}

/// Recursively collect form fields from all descendants of `parent`.
fn collect_form_fields(doc: &HtmlDocument, parent: usize, fields: &mut Vec<FormField>) {
  for &child in doc.children(parent) {
    if doc.node_type(child) != NodeType::Element {
      continue;
    }

    match doc.tag_name(child) {
      "input" => {
        let ft = doc
          .get_attribute(child, "type")
          .unwrap_or("text")
          .to_ascii_lowercase();
        fields.push(FormField {
          name: doc.get_attribute(child, "name").map(|s| s.to_string()),
          field_type: ft,
          value: doc.get_attribute(child, "value").map(|s| s.to_string()),
          placeholder: doc.get_attribute(child, "placeholder").map(|s| s.to_string()),
          required: doc.get_attribute(child, "required").is_some(),
          options: Vec::new(),
        });
      }

      "textarea" => {
        let text = doc.text_content(child);
        fields.push(FormField {
          name: doc.get_attribute(child, "name").map(|s| s.to_string()),
          field_type: "textarea".to_string(),
          value: if text.is_empty() { None } else { Some(text) },
          placeholder: doc.get_attribute(child, "placeholder").map(|s| s.to_string()),
          required: doc.get_attribute(child, "required").is_some(),
          options: Vec::new(),
        });
      }

      "select" => {
        let options = collect_select_options(doc, child);
        fields.push(FormField {
          name: doc.get_attribute(child, "name").map(|s| s.to_string()),
          field_type: "select".to_string(),
          value: None,
          placeholder: None,
          required: doc.get_attribute(child, "required").is_some(),
          options,
        });
      }

      "button" => {
        let bt = doc
          .get_attribute(child, "type")
          .unwrap_or("submit")
          .to_ascii_lowercase();
        if bt == "submit" {
          fields.push(FormField {
            name: doc.get_attribute(child, "name").map(|s| s.to_string()),
            field_type: "submit".to_string(),
            value: doc
              .get_attribute(child, "value")
              .map(|s| s.to_string())
              .or_else(|| {
                let t = doc.text_content(child);
                if t.is_empty() { None } else { Some(t) }
              }),
            placeholder: None,
            required: false,
            options: Vec::new(),
          });
        }
      }

      // Recurse into container elements (div, fieldset, etc.)
      _ => collect_form_fields(doc, child, fields),
    }
  }
}

/// Collect `<option>` children of a `<select>` element.
fn collect_select_options(doc: &HtmlDocument, select_id: usize) -> Vec<SelectOption> {
  let mut options = Vec::new();

  for &child in doc.children(select_id) {
    if doc.node_type(child) != NodeType::Element {
      continue;
    }

    if doc.tag_name(child) == "option" {
      let value = doc
        .get_attribute(child, "value")
        .unwrap_or("")
        .to_string();
      let text = doc.text_content(child);
      let selected = doc.get_attribute(child, "selected").is_some();
      options.push(SelectOption {
        value,
        text,
        selected,
      });
    } else if doc.tag_name(child) == "optgroup" {
      // Recurse into optgroup
      for &opt in doc.children(child) {
        if doc.tag_name(opt) == "option" {
          let value = doc.get_attribute(opt, "value").unwrap_or("").to_string();
          let text = doc.text_content(opt);
          let selected = doc.get_attribute(opt, "selected").is_some();
          options.push(SelectOption {
            value,
            text,
            selected,
          });
        }
      }
    }
  }

  options
}

// ============================================================================
// Table Extraction
// ============================================================================

/// A table extracted from the document
#[derive(Debug, Clone)]
pub struct ExtractedTable {
  pub headers: Vec<String>,
  pub rows: Vec<Vec<String>>,
  pub caption: Option<String>,
}

/// Extract all tables from the document.
///
/// For each `<table>`:
/// - Looks for `<caption>` text
/// - Collects headers from `<thead> <tr> <th>` (falls back to first `<tr>`)
/// - Collects data rows from `<tbody> <tr>` (or remaining `<tr>` elements)
pub fn extract_tables(doc: &HtmlDocument) -> Vec<ExtractedTable> {
  let mut result = Vec::new();

  for id in doc.select("table") {

    let mut table = ExtractedTable {
      headers: Vec::new(),
      rows: Vec::new(),
      caption: None,
    };

    // Gather direct structural children
    let mut thead_id: Option<usize> = None;
    let mut tbody_ids: Vec<usize> = Vec::new();
    let mut bare_trs: Vec<usize> = Vec::new();

    for &child in doc.children(id) {
      if doc.node_type(child) != NodeType::Element {
        continue;
      }
      match doc.tag_name(child) {
        "caption" => table.caption = Some(doc.text_content(child)),
        "thead" => thead_id = Some(child),
        "tbody" => tbody_ids.push(child),
        "tr" => bare_trs.push(child),
        _ => {}
      }
    }

    // Extract headers
    if let Some(thead) = thead_id {
      // Find first <tr> inside <thead>
      for &tr in doc.children(thead) {
        if doc.tag_name(tr) == "tr" {
          table.headers = extract_row_cells(doc, tr);
          break;
        }
      }
    } else if !bare_trs.is_empty() {
      // Fallback: treat first bare <tr> as header if it has <th> cells
      let first_tr = bare_trs[0];
      let has_th = doc
        .children(first_tr)
        .iter()
        .any(|&c| doc.tag_name(c) == "th");
      if has_th {
        table.headers = extract_row_cells(doc, first_tr);
        bare_trs.remove(0);
      }
    }

    // Extract data rows from <tbody> sections
    for &tbody in &tbody_ids {
      for &tr in doc.children(tbody) {
        if doc.tag_name(tr) == "tr" {
          table.rows.push(extract_row_cells(doc, tr));
        }
      }
    }

    // Also include bare <tr> elements (those outside thead/tbody)
    for &tr in &bare_trs {
      table.rows.push(extract_row_cells(doc, tr));
    }

    result.push(table);
  }

  result
}

/// Extract the text of each `<td>` or `<th>` cell in a `<tr>`.
fn extract_row_cells(doc: &HtmlDocument, tr_id: usize) -> Vec<String> {
  doc
    .children(tr_id)
    .iter()
    .filter(|&&c| {
      let tag = doc.tag_name(c);
      tag == "td" || tag == "th"
    })
    .map(|&c| doc.text_content(c))
    .collect()
}

// ============================================================================
// Script Extraction
// ============================================================================

/// A `<script>` element
#[derive(Debug, Clone)]
pub struct ExtractedScript {
  pub src: Option<String>,
  pub script_type: Option<String>,
  pub is_async: bool,
  pub is_defer: bool,
  pub inline_content: Option<String>,
}

/// Extract all scripts from the document.
///
/// Captures both external (`src`) and inline scripts, along with
/// `type`, `async`, and `defer` attributes.
pub fn extract_scripts(doc: &HtmlDocument) -> Vec<ExtractedScript> {
  let mut result = Vec::new();

  for id in doc.select("script") {

    let src = doc.get_attribute(id, "src").map(|s| s.to_string());
    let inline = if src.is_none() {
      let text = doc.text_content(id);
      if text.is_empty() { None } else { Some(text) }
    } else {
      None
    };

    result.push(ExtractedScript {
      src,
      script_type: doc.get_attribute(id, "type").map(|s| s.to_string()),
      is_async: doc.get_attribute(id, "async").is_some(),
      is_defer: doc.get_attribute(id, "defer").is_some(),
      inline_content: inline,
    });
  }

  result
}

// ============================================================================
// Style Extraction
// ============================================================================

/// A stylesheet reference (`<link rel="stylesheet">`) or inline `<style>`
#[derive(Debug, Clone)]
pub struct ExtractedStyle {
  pub href: Option<String>,
  pub media: Option<String>,
  pub inline_content: Option<String>,
}

/// Extract all styles from the document.
///
/// Finds `<link rel="stylesheet">` and `<style>` elements.
pub fn extract_styles(doc: &HtmlDocument) -> Vec<ExtractedStyle> {
  let mut result = Vec::new();

  // External stylesheets
  for id in doc.select("link[rel]") {
    let rel = doc.get_attribute(id, "rel").unwrap_or("");
    if rel.eq_ignore_ascii_case("stylesheet") {
      result.push(ExtractedStyle {
        href: doc.get_attribute(id, "href").map(|s| s.to_string()),
        media: doc.get_attribute(id, "media").map(|s| s.to_string()),
        inline_content: None,
      });
    }
  }

  // Inline styles
  for id in doc.select("style") {
    let text = doc.text_content(id);
    result.push(ExtractedStyle {
      href: None,
      media: doc.get_attribute(id, "media").map(|s| s.to_string()),
      inline_content: if text.is_empty() { None } else { Some(text) },
    });
  }

  result
}

// ============================================================================
// URL Resolution
// ============================================================================

/// Resolve `href` against `base_url` to produce an absolute URL.
///
/// Rules:
/// - Absolute URLs (http:// or https://) are returned as-is
/// - Protocol-relative (`//`) gets the scheme from base_url
/// - Root-relative (`/path`) gets scheme + host from base_url
/// - Fragment, javascript, mailto, tel are returned as-is
/// - Relative paths are appended to the base path, resolving `.` and `..`
pub fn resolve_url(href: &str, base_url: &str) -> String {
  // Already absolute
  if href.starts_with("http://") || href.starts_with("https://") {
    return href.to_string();
  }

  // Special schemes -- return unchanged
  if href.starts_with('#')
    || href.starts_with("javascript:")
    || href.starts_with("mailto:")
    || href.starts_with("tel:")
    || href.starts_with("data:")
  {
    return href.to_string();
  }

  // Extract scheme from base
  let (scheme, after_scheme) = match base_url.find("://") {
    Some(pos) => (&base_url[..pos + 3], &base_url[pos + 3..]),
    None => ("", base_url),
  };

  let host = after_scheme.split('/').next().unwrap_or("");

  // Protocol-relative
  if href.starts_with("//") {
    let scheme_prefix = if scheme.is_empty() { "https://" } else { &scheme[..scheme.len() - 3] };
    return format!("{}:{}", scheme_prefix, href);
  }

  // Root-relative
  if href.starts_with('/') {
    return format!("{}{}{}", scheme, host, href);
  }

  // Relative path: resolve against base directory
  let base_path = if after_scheme.ends_with('/') {
    after_scheme.to_string()
  } else {
    match after_scheme.rfind('/') {
      Some(pos) => after_scheme[..=pos].to_string(),
      None => format!("{}/", after_scheme),
    }
  };

  let mut parts: Vec<&str> = base_path.split('/').filter(|s| !s.is_empty()).collect();

  for segment in href.split('/') {
    match segment {
      "" | "." => {}
      ".." => {
        // Keep at least the host component
        if parts.len() > 1 {
          parts.pop();
        }
      }
      _ => parts.push(segment),
    }
  }

  if scheme.is_empty() {
    format!("/{}", parts.join("/"))
  } else {
    format!("{}{}", scheme, parts.join("/"))
  }
}

/// Extract the domain (host without port) from a URL.
fn extract_domain(url: &str) -> Option<&str> {
  let after_proto = if let Some(pos) = url.find("://") {
    &url[pos + 3..]
  } else if let Some(stripped) = url.strip_prefix("//") {
    stripped
  } else {
    url
  };

  let host = after_proto.split('/').next()?;
  let domain = host.split(':').next()?;

  if domain.is_empty() {
    None
  } else {
    Some(domain)
  }
}

/// Check whether two domains should be considered the same origin.
///
/// Returns `true` for exact match or if one is a subdomain of the other.
fn domains_match(a: &str, b: &str) -> bool {
  let a = a.to_ascii_lowercase();
  let b = b.to_ascii_lowercase();

  if a == b {
    return true;
  }

  a.ends_with(&format!(".{}", b)) || b.ends_with(&format!(".{}", a))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ---- Link tests ----

  #[test]
  fn test_extract_links_basic() {
    let html = r#"<html><body>
      <a href="/about">About</a>
      <a href="/contact">Contact</a>
    </body></html>"#;
    let doc = HtmlDocument::parse(html);
    let links = extract_links(&doc, None);

    assert_eq!(links.len(), 2);
    assert_eq!(links[0].href, "/about");
    assert_eq!(links[0].text, "About");
    assert_eq!(links[1].href, "/contact");
    assert_eq!(links[1].text, "Contact");
  }

  #[test]
  fn test_extract_links_with_base_url() {
    let html = r#"<a href="/page">Link</a>"#;
    let doc = HtmlDocument::parse(html);
    let links = extract_links(&doc, Some("https://example.com/dir/index.html"));

    assert_eq!(links.len(), 1);
    assert_eq!(links[0].href, "/page");
    assert_eq!(links[0].link_type, LinkType::Internal);
  }

  #[test]
  fn test_extract_links_classify_types() {
    let html = r#"
      <a href="https://example.com/a">Internal</a>
      <a href="https://other.com/b">External</a>
      <a href="#top">Anchor</a>
    "#;
    let doc = HtmlDocument::parse(html);
    let links = extract_links(&doc, Some("https://example.com"));

    assert_eq!(links[0].link_type, LinkType::Internal);
    assert_eq!(links[1].link_type, LinkType::External);
    assert_eq!(links[2].link_type, LinkType::Anchor);
  }

  #[test]
  fn test_extract_links_mailto_tel() {
    let html = r#"
      <a href="mailto:a@b.com">Email</a>
      <a href="tel:+1234">Call</a>
      <a href="javascript:void(0)">JS</a>
    "#;
    let doc = HtmlDocument::parse(html);
    let links = extract_links(&doc, None);

    assert_eq!(links[0].link_type, LinkType::Mailto);
    assert_eq!(links[1].link_type, LinkType::Tel);
    assert_eq!(links[2].link_type, LinkType::JavaScript);
  }

  // ---- Image tests ----

  #[test]
  fn test_extract_images_basic() {
    let html = r#"<img src="photo.jpg"><img src="logo.png">"#;
    let doc = HtmlDocument::parse(html);
    let images = extract_images(&doc, None);

    assert_eq!(images.len(), 2);
    assert_eq!(images[0].src, "photo.jpg");
    assert_eq!(images[1].src, "logo.png");
  }

  #[test]
  fn test_extract_images_with_attributes() {
    let html = r#"<img src="/img/hero.webp" alt="Hero image" title="Welcome" width="1200" height="600" loading="lazy">"#;
    let doc = HtmlDocument::parse(html);
    let images = extract_images(&doc, Some("https://cdn.example.com"));

    assert_eq!(images.len(), 1);
    let img = &images[0];
    assert_eq!(img.src, "https://cdn.example.com/img/hero.webp");
    assert_eq!(img.alt.as_deref(), Some("Hero image"));
    assert_eq!(img.title.as_deref(), Some("Welcome"));
    assert_eq!(img.width.as_deref(), Some("1200"));
    assert_eq!(img.height.as_deref(), Some("600"));
    assert_eq!(img.loading.as_deref(), Some("lazy"));
  }

  // ---- Meta tests ----

  #[test]
  fn test_extract_meta_basic() {
    let html = r#"<html><head>
      <title>My Page</title>
      <meta name="description" content="A test page">
      <meta name="keywords" content="rust, html, parser">
      <meta name="author" content="Test Author">
      <meta name="viewport" content="width=device-width">
      <link rel="canonical" href="https://example.com/page">
    </head></html>"#;
    let doc = HtmlDocument::parse(html);
    let meta = extract_meta(&doc);

    assert_eq!(meta.title.as_deref(), Some("My Page"));
    assert_eq!(meta.description.as_deref(), Some("A test page"));
    assert_eq!(meta.keywords, vec!["rust", "html", "parser"]);
    assert_eq!(meta.author.as_deref(), Some("Test Author"));
    assert_eq!(meta.viewport.as_deref(), Some("width=device-width"));
    assert_eq!(meta.canonical.as_deref(), Some("https://example.com/page"));
  }

  #[test]
  fn test_extract_meta_opengraph() {
    let html = r#"<html><head>
      <meta property="og:title" content="OG Title">
      <meta property="og:description" content="OG Desc">
      <meta property="og:image" content="https://example.com/og.png">
    </head></html>"#;
    let doc = HtmlDocument::parse(html);
    let meta = extract_meta(&doc);

    assert_eq!(meta.og.len(), 3);
    assert_eq!(meta.og[0], ("og:title".to_string(), "OG Title".to_string()));
    assert_eq!(meta.og[1], ("og:description".to_string(), "OG Desc".to_string()));
    assert_eq!(meta.og[2], ("og:image".to_string(), "https://example.com/og.png".to_string()));
  }

  #[test]
  fn test_extract_meta_twitter() {
    let html = r#"<html><head>
      <meta name="twitter:card" content="summary_large_image">
      <meta name="twitter:site" content="@example">
    </head></html>"#;
    let doc = HtmlDocument::parse(html);
    let meta = extract_meta(&doc);

    assert_eq!(meta.twitter.len(), 2);
    assert_eq!(meta.twitter[0].0, "twitter:card");
    assert_eq!(meta.twitter[0].1, "summary_large_image");
  }

  #[test]
  fn test_extract_meta_charset() {
    // Direct charset attribute
    let html1 = r#"<meta charset="utf-8">"#;
    let doc1 = HtmlDocument::parse(html1);
    let meta1 = extract_meta(&doc1);
    assert_eq!(meta1.charset.as_deref(), Some("utf-8"));

    // http-equiv Content-Type with charset
    let html2 = r#"<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">"#;
    let doc2 = HtmlDocument::parse(html2);
    let meta2 = extract_meta(&doc2);
    assert_eq!(meta2.charset.as_deref(), Some("iso-8859-1"));
  }

  // ---- Form tests ----

  #[test]
  fn test_extract_forms_basic() {
    let html = r#"<form action="/submit" method="POST" id="myform">
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <input type="submit" value="Login">
    </form>"#;
    let doc = HtmlDocument::parse(html);
    let forms = extract_forms(&doc);

    assert_eq!(forms.len(), 1);
    let form = &forms[0];
    assert_eq!(form.action.as_deref(), Some("/submit"));
    assert_eq!(form.method.as_deref(), Some("POST"));
    assert_eq!(form.id.as_deref(), Some("myform"));
    assert_eq!(form.fields.len(), 3);
    assert_eq!(form.fields[0].field_type, "text");
    assert_eq!(form.fields[0].name.as_deref(), Some("username"));
    assert!(form.fields[0].required);
    assert_eq!(form.fields[1].field_type, "password");
    assert_eq!(form.fields[2].field_type, "submit");
  }

  #[test]
  fn test_extract_forms_with_select() {
    let html = r#"<form>
      <select name="country">
        <option value="us">United States</option>
        <option value="uk" selected>United Kingdom</option>
        <option value="de">Germany</option>
      </select>
    </form>"#;
    let doc = HtmlDocument::parse(html);
    let forms = extract_forms(&doc);

    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].fields.len(), 1);
    let field = &forms[0].fields[0];
    assert_eq!(field.field_type, "select");
    assert_eq!(field.name.as_deref(), Some("country"));
    assert_eq!(field.options.len(), 3);
    assert_eq!(field.options[0].value, "us");
    assert_eq!(field.options[0].text, "United States");
    assert!(!field.options[0].selected);
    assert!(field.options[1].selected);
  }

  #[test]
  fn test_extract_forms_textarea() {
    let html = r#"<form>
      <textarea name="message" placeholder="Your message">Default text</textarea>
    </form>"#;
    let doc = HtmlDocument::parse(html);
    let forms = extract_forms(&doc);

    assert_eq!(forms[0].fields.len(), 1);
    let field = &forms[0].fields[0];
    assert_eq!(field.field_type, "textarea");
    assert_eq!(field.name.as_deref(), Some("message"));
    assert_eq!(field.value.as_deref(), Some("Default text"));
    assert_eq!(field.placeholder.as_deref(), Some("Your message"));
  }

  #[test]
  fn test_extract_forms_hidden_fields() {
    let html = r#"<form>
      <input type="hidden" name="csrf_token" value="abc123">
      <input type="hidden" name="session_id" value="xyz789">
      <input type="text" name="query">
    </form>"#;
    let doc = HtmlDocument::parse(html);
    let forms = extract_forms(&doc);

    assert_eq!(forms[0].fields.len(), 3);
    assert_eq!(forms[0].fields[0].field_type, "hidden");
    assert_eq!(forms[0].fields[0].name.as_deref(), Some("csrf_token"));
    assert_eq!(forms[0].fields[0].value.as_deref(), Some("abc123"));
    assert_eq!(forms[0].fields[1].field_type, "hidden");
    assert_eq!(forms[0].fields[2].field_type, "text");
  }

  // ---- Table tests ----

  #[test]
  fn test_extract_tables_basic() {
    let html = r#"<table>
      <caption>Users</caption>
      <tr><th>Name</th><th>Age</th></tr>
      <tr><td>Alice</td><td>30</td></tr>
      <tr><td>Bob</td><td>25</td></tr>
    </table>"#;
    let doc = HtmlDocument::parse(html);
    let tables = extract_tables(&doc);

    assert_eq!(tables.len(), 1);
    let t = &tables[0];
    assert_eq!(t.caption.as_deref(), Some("Users"));
    assert_eq!(t.headers, vec!["Name", "Age"]);
    assert_eq!(t.rows.len(), 2);
    assert_eq!(t.rows[0], vec!["Alice", "30"]);
    assert_eq!(t.rows[1], vec!["Bob", "25"]);
  }

  #[test]
  fn test_extract_tables_with_thead() {
    let html = r#"<table>
      <thead><tr><th>Product</th><th>Price</th></tr></thead>
      <tbody>
        <tr><td>Widget</td><td>$10</td></tr>
        <tr><td>Gadget</td><td>$20</td></tr>
      </tbody>
    </table>"#;
    let doc = HtmlDocument::parse(html);
    let tables = extract_tables(&doc);

    assert_eq!(tables[0].headers, vec!["Product", "Price"]);
    assert_eq!(tables[0].rows.len(), 2);
    assert_eq!(tables[0].rows[0], vec!["Widget", "$10"]);
  }

  #[test]
  fn test_extract_tables_no_header() {
    let html = r#"<table>
      <tr><td>A</td><td>B</td></tr>
      <tr><td>C</td><td>D</td></tr>
    </table>"#;
    let doc = HtmlDocument::parse(html);
    let tables = extract_tables(&doc);

    assert!(tables[0].headers.is_empty());
    assert_eq!(tables[0].rows.len(), 2);
    assert_eq!(tables[0].rows[0], vec!["A", "B"]);
  }

  // ---- Script tests ----

  #[test]
  fn test_extract_scripts() {
    let html = r#"<html><head>
      <script src="/app.js" defer></script>
      <script type="module" src="/main.mjs" async></script>
      <script>console.log("inline")</script>
    </head></html>"#;
    let doc = HtmlDocument::parse(html);
    let scripts = extract_scripts(&doc);

    assert_eq!(scripts.len(), 3);

    assert_eq!(scripts[0].src.as_deref(), Some("/app.js"));
    assert!(!scripts[0].is_async);
    assert!(scripts[0].is_defer);
    assert!(scripts[0].inline_content.is_none());

    assert_eq!(scripts[1].script_type.as_deref(), Some("module"));
    assert!(scripts[1].is_async);

    assert!(scripts[2].src.is_none());
    assert!(scripts[2].inline_content.as_deref().unwrap().contains("inline"));
  }

  // ---- Style tests ----

  #[test]
  fn test_extract_styles() {
    let html = r#"<html><head>
      <link rel="stylesheet" href="/main.css" media="screen">
      <style>body { margin: 0; }</style>
    </head></html>"#;
    let doc = HtmlDocument::parse(html);
    let styles = extract_styles(&doc);

    assert_eq!(styles.len(), 2);
    assert_eq!(styles[0].href.as_deref(), Some("/main.css"));
    assert_eq!(styles[0].media.as_deref(), Some("screen"));
    assert!(styles[0].inline_content.is_none());

    assert!(styles[1].href.is_none());
    assert!(styles[1].inline_content.as_deref().unwrap().contains("margin"));
  }

  // ---- URL resolution tests ----

  #[test]
  fn test_resolve_absolute_url() {
    assert_eq!(
      resolve_url("https://cdn.example.com/img.png", "https://example.com"),
      "https://cdn.example.com/img.png"
    );
  }

  #[test]
  fn test_resolve_protocol_relative() {
    assert_eq!(
      resolve_url("//cdn.example.com/img.png", "https://example.com"),
      "https://cdn.example.com/img.png"
    );
    assert_eq!(
      resolve_url("//cdn.example.com/img.png", "http://example.com"),
      "http://cdn.example.com/img.png"
    );
  }

  #[test]
  fn test_resolve_root_relative() {
    assert_eq!(
      resolve_url("/images/logo.png", "https://example.com/page/about"),
      "https://example.com/images/logo.png"
    );
  }

  #[test]
  fn test_resolve_relative_path() {
    assert_eq!(
      resolve_url("img/photo.jpg", "https://example.com/blog/post.html"),
      "https://example.com/blog/img/photo.jpg"
    );
    assert_eq!(
      resolve_url("../assets/style.css", "https://example.com/dir/sub/page.html"),
      "https://example.com/dir/assets/style.css"
    );
  }

  // ---- Real-world scenario ----

  #[test]
  fn test_extract_login_form() {
    let html = r#"<!DOCTYPE html>
    <html>
    <head>
      <title>Login</title>
      <meta name="description" content="Login to your account">
      <meta name="robots" content="noindex, nofollow">
    </head>
    <body>
      <form action="/auth/login" method="POST" id="login-form" name="login">
        <input type="hidden" name="csrf" value="tok3n">
        <input type="email" name="email" placeholder="Email address" required>
        <input type="password" name="password" placeholder="Password" required>
        <select name="role">
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
        <textarea name="notes" placeholder="Optional notes"></textarea>
        <button type="submit">Sign In</button>
      </form>
      <a href="/auth/register">Create account</a>
      <a href="/auth/reset">Forgot password?</a>
      <img src="/img/logo.svg" alt="Company Logo">
      <script src="/js/login.js" defer></script>
      <link rel="stylesheet" href="/css/auth.css">
    </body>
    </html>"#;
    let doc = HtmlDocument::parse(html);

    // Meta
    let meta = extract_meta(&doc);
    assert_eq!(meta.title.as_deref(), Some("Login"));
    assert_eq!(meta.description.as_deref(), Some("Login to your account"));
    assert_eq!(meta.robots, vec!["noindex", "nofollow"]);

    // Forms
    let forms = extract_forms(&doc);
    assert_eq!(forms.len(), 1);
    let form = &forms[0];
    assert_eq!(form.action.as_deref(), Some("/auth/login"));
    assert_eq!(form.method.as_deref(), Some("POST"));
    assert_eq!(form.id.as_deref(), Some("login-form"));
    assert_eq!(form.name.as_deref(), Some("login"));

    // Fields: hidden csrf, email, password, select, textarea, submit
    assert_eq!(form.fields.len(), 6);
    assert_eq!(form.fields[0].field_type, "hidden");
    assert_eq!(form.fields[0].value.as_deref(), Some("tok3n"));
    assert_eq!(form.fields[1].field_type, "email");
    assert!(form.fields[1].required);
    assert_eq!(form.fields[2].field_type, "password");
    assert_eq!(form.fields[3].field_type, "select");
    assert_eq!(form.fields[3].options.len(), 2);
    assert_eq!(form.fields[4].field_type, "textarea");
    assert_eq!(form.fields[5].field_type, "submit");

    // Links
    let links = extract_links(&doc, Some("https://example.com"));
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].href, "/auth/register");
    assert_eq!(links[0].link_type, LinkType::Internal);

    // Images
    let images = extract_images(&doc, Some("https://example.com"));
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].src, "https://example.com/img/logo.svg");
    assert_eq!(images[0].alt.as_deref(), Some("Company Logo"));

    // Scripts
    let scripts = extract_scripts(&doc);
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].src.as_deref(), Some("/js/login.js"));
    assert!(scripts[0].is_defer);

    // Styles
    let styles = extract_styles(&doc);
    assert_eq!(styles.len(), 1);
    assert_eq!(styles[0].href.as_deref(), Some("/css/auth.css"));
  }
}
