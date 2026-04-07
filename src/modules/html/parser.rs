#![allow(dead_code)]

/// HTML Parser - single-pass arena-based DOM builder
///
/// A regex-less, zero-dependency HTML parser that tokenizes character-by-character
/// and builds a DOM tree using arena allocation. Ported from the recker TypeScript
/// parser to idiomatic Rust.
///
/// Features:
/// - Arena-allocated nodes (no Rc/RefCell overhead)
/// - Single-pass tokenizer with stack-based tree construction
/// - Handles malformed/broken HTML gracefully (never panics)
/// - Void tag, auto-close, and raw-text element support
/// - HTML entity decoding (named, decimal, hex)
/// - DOM traversal, search, and serialization methods
///
/// NO external dependencies - pure Rust std implementation.

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

/// DOM node type, matching the W3C DOM spec numeric constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
  Element = 1,
  Text = 3,
  Comment = 8,
}

/// A single DOM node stored inside the [`Arena`].
#[derive(Debug, Clone)]
pub struct Node {
  pub node_type: NodeType,
  /// Lowercase tag name for Element nodes; empty for Text/Comment.
  pub tag_name: String,
  /// Attribute (name, value) pairs. Names are lowercase.
  pub attributes: Vec<(String, String)>,
  /// Indices of child nodes inside the arena.
  pub children: Vec<usize>,
  /// Index of the parent node (None for root).
  pub parent: Option<usize>,
  /// Text payload for Text and Comment nodes; raw content for
  /// block-text elements (script, style, etc.).
  pub text_content: String,
  /// True when the source tag was self-closing (e.g. `<br/>`).
  pub self_closing: bool,
}

impl Node {
  /// Create a new element node.
  fn element(tag: &str) -> Self {
    Self {
      node_type: NodeType::Element,
      tag_name: tag.to_lowercase(),
      attributes: Vec::new(),
      children: Vec::new(),
      parent: None,
      text_content: String::new(),
      self_closing: false,
    }
  }

  /// Create an element node with pre-parsed attributes.
  fn element_with_attrs(tag: String, attrs: Vec<(String, String)>, self_closing: bool) -> Self {
    Self {
      node_type: NodeType::Element,
      tag_name: tag,
      attributes: attrs,
      children: Vec::new(),
      parent: None,
      text_content: String::new(),
      self_closing,
    }
  }

  /// Create a new text node.
  fn text(content: &str) -> Self {
    Self {
      node_type: NodeType::Text,
      tag_name: String::new(),
      attributes: Vec::new(),
      children: Vec::new(),
      parent: None,
      text_content: content.to_string(),
      self_closing: false,
    }
  }

  /// Create a new comment node.
  fn comment(content: &str) -> Self {
    Self {
      node_type: NodeType::Comment,
      tag_name: String::new(),
      attributes: Vec::new(),
      children: Vec::new(),
      parent: None,
      text_content: content.to_string(),
      self_closing: false,
    }
  }
}

// ---------------------------------------------------------------------------
// Arena allocator
// ---------------------------------------------------------------------------

/// Flat arena that owns every DOM node. Nodes reference each other through
/// `usize` indices, avoiding reference-counting overhead.
#[derive(Debug)]
pub struct Arena {
  nodes: Vec<Node>,
}

impl Arena {
  pub fn new() -> Self {
    Self {
      nodes: Vec::with_capacity(256),
    }
  }

  /// Allocate a node and return its index.
  pub fn alloc(&mut self, node: Node) -> usize {
    let id = self.nodes.len();
    self.nodes.push(node);
    id
  }

  /// Get a shared reference to the node at `id`.
  pub fn get(&self, id: usize) -> Option<&Node> {
    self.nodes.get(id)
  }

  /// Get a mutable reference to the node at `id`.
  pub fn get_mut(&mut self, id: usize) -> Option<&mut Node> {
    self.nodes.get_mut(id)
  }

  /// Total number of nodes in the arena.
  pub fn len(&self) -> usize {
    self.nodes.len()
  }

  /// Returns true when the arena contains no nodes.
  pub fn is_empty(&self) -> bool {
    self.nodes.is_empty()
  }
}

impl Default for Arena {
  fn default() -> Self {
    Self::new()
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Void elements (HTML spec) that never have children.
const VOID_TAGS: &[&str] = &[
  "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
  "track", "wbr",
];

/// Elements whose content is treated as raw text -- the tokenizer scans
/// forward to the matching closing tag without interpreting nested markup.
const RAW_TEXT_TAGS: &[&str] = &["script", "style", "textarea", "pre", "noscript", "title"];

fn is_void_tag(tag: &str) -> bool {
  VOID_TAGS.contains(&tag)
}

fn is_raw_text_tag(tag: &str) -> bool {
  RAW_TEXT_TAGS.contains(&tag)
}

/// Return the set of tags that `tag` should implicitly close when found on
/// the open-element stack.
fn auto_close_peers(tag: &str) -> &'static [&'static str] {
  match tag {
    "li" => &["li"],
    "p" => &["p"],
    "td" => &["td", "th"],
    "th" => &["td", "th"],
    "tr" => &["tr"],
    "option" => &["option"],
    "dt" => &["dt", "dd"],
    "dd" => &["dt", "dd"],
    _ => &[],
  }
}

// ---------------------------------------------------------------------------
// Entity decoding
// ---------------------------------------------------------------------------

/// Decode common HTML entities in `s`.
///
/// Handles named entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`,
/// `&nbsp;`), decimal numeric references (`&#NNN;`) and hexadecimal
/// references (`&#xHH;`).
pub fn decode_entities(s: &str) -> String {
  if !s.contains('&') {
    return s.to_string();
  }

  let bytes = s.as_bytes();
  let len = bytes.len();
  let mut out = String::with_capacity(len);
  let mut i = 0;

  while i < len {
    if bytes[i] == b'&' {
      // Look for a closing ';' within a reasonable window (max entity
      // length is about 10 chars).
      let max_end = std::cmp::min(i + 12, len);
      if let Some(semi_off) = s[i + 1..max_end].find(';') {
        let semi = i + 1 + semi_off;
        let entity = &s[i + 1..semi];
        if let Some(decoded) = resolve_entity(entity) {
          out.push_str(&decoded);
          i = semi + 1;
          continue;
        }
      }
      // Not a valid entity reference -- emit the literal '&'
      out.push('&');
      i += 1;
    } else {
      // Fast path: copy non-entity bytes directly
      let start = i;
      while i < len && bytes[i] != b'&' {
        i += 1;
      }
      out.push_str(&s[start..i]);
    }
  }

  out
}

/// Resolve a single entity body (the text between '&' and ';').
fn resolve_entity(entity: &str) -> Option<String> {
  // Named entities
  match entity {
    "amp" => return Some("&".into()),
    "lt" => return Some("<".into()),
    "gt" => return Some(">".into()),
    "quot" => return Some("\"".into()),
    "apos" => return Some("'".into()),
    "nbsp" => return Some("\u{00A0}".into()),
    _ => {}
  }

  // Numeric: &#NNN; or &#xHH;
  if let Some(rest) = entity.strip_prefix('#') {
    let code = if let Some(hex) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
      u32::from_str_radix(hex, 16).ok()
    } else {
      rest.parse::<u32>().ok()
    };
    if let Some(cp) = code {
      if let Some(ch) = char::from_u32(cp) {
        return Some(ch.to_string());
      }
    }
  }

  None
}

// ---------------------------------------------------------------------------
// HTML escape helpers (for serialization)
// ---------------------------------------------------------------------------

fn escape_html_text(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  for ch in s.chars() {
    match ch {
      '&' => out.push_str("&amp;"),
      '<' => out.push_str("&lt;"),
      '>' => out.push_str("&gt;"),
      _ => out.push(ch),
    }
  }
  out
}

fn escape_html_attr(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  for ch in s.chars() {
    match ch {
      '&' => out.push_str("&amp;"),
      '"' => out.push_str("&quot;"),
      '<' => out.push_str("&lt;"),
      '>' => out.push_str("&gt;"),
      _ => out.push(ch),
    }
  }
  out
}

// ===========================================================================
// HtmlDocument
// ===========================================================================

/// A parsed HTML document backed by an arena allocator.
pub struct HtmlDocument {
  pub arena: Arena,
  /// Index of the synthetic root (document) node.
  pub root: usize,
}

impl std::fmt::Debug for HtmlDocument {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("HtmlDocument")
      .field("root", &self.root)
      .field("node_count", &self.arena.len())
      .finish()
  }
}

impl HtmlDocument {
  // -----------------------------------------------------------------------
  // Parsing
  // -----------------------------------------------------------------------

  /// Parse an HTML string into an `HtmlDocument`.
  ///
  /// The parser is intentionally lenient: malformed HTML is handled
  /// gracefully and will never cause a panic.
  pub fn parse(html: &str) -> Self {
    let mut arena = Arena::new();
    let root = arena.alloc(Node::element("[root]"));

    let mut parser = InternalParser {
      src: html.as_bytes(),
      pos: 0,
      arena: &mut arena,
      stack: vec![root],
    };
    parser.run();

    HtmlDocument { arena, root }
  }

  // -----------------------------------------------------------------------
  // Traversal
  // -----------------------------------------------------------------------

  /// Children of `node_id`.
  pub fn children(&self, node_id: usize) -> &[usize] {
    self
      .arena
      .get(node_id)
      .map(|n| n.children.as_slice())
      .unwrap_or(&[])
  }

  /// Parent of `node_id` (None for the root).
  pub fn parent(&self, node_id: usize) -> Option<usize> {
    self.arena.get(node_id).and_then(|n| n.parent)
  }

  /// Lowercase tag name (empty for text/comment nodes).
  pub fn tag_name(&self, node_id: usize) -> &str {
    self
      .arena
      .get(node_id)
      .map(|n| n.tag_name.as_str())
      .unwrap_or("")
  }

  /// Node type.
  pub fn node_type(&self, node_id: usize) -> NodeType {
    self
      .arena
      .get(node_id)
      .map(|n| n.node_type)
      .unwrap_or(NodeType::Text)
  }

  /// Check whether a node is an Element.
  pub fn is_element(&self, node_id: usize) -> bool {
    self
      .arena
      .get(node_id)
      .map(|n| n.node_type == NodeType::Element)
      .unwrap_or(false)
  }

  /// Return only the Element-type children of `node_id`.
  pub fn element_children(&self, node_id: usize) -> Vec<usize> {
    self
      .children(node_id)
      .iter()
      .copied()
      .filter(|&id| self.is_element(id))
      .collect()
  }

  /// Iterate over all node IDs in document order (depth-first).
  pub fn node_ids(&self) -> Vec<usize> {
    let mut result = Vec::new();
    self.collect_ids_dfs(self.root, &mut result);
    result
  }

  fn collect_ids_dfs(&self, node_id: usize, result: &mut Vec<usize>) {
    if node_id != self.root {
      result.push(node_id);
    }
    for &child in self.children(node_id) {
      self.collect_ids_dfs(child, result);
    }
  }

  // -----------------------------------------------------------------------
  // Attributes
  // -----------------------------------------------------------------------

  /// Get the value of an attribute (case-insensitive lookup).
  pub fn get_attribute(&self, node_id: usize, name: &str) -> Option<&str> {
    let node = self.arena.get(node_id)?;
    let name_lower = name.to_ascii_lowercase();
    node
      .attributes
      .iter()
      .find(|(k, _)| *k == name_lower)
      .map(|(_, v)| v.as_str())
  }

  /// Check whether an attribute is present.
  pub fn has_attribute(&self, node_id: usize, name: &str) -> bool {
    self.get_attribute(node_id, name).is_some()
  }

  /// Shortcut for `get_attribute(node_id, "id")`.
  pub fn id(&self, node_id: usize) -> Option<&str> {
    self.get_attribute(node_id, "id")
  }

  /// Split the `class` attribute into individual class names.
  pub fn class_list(&self, node_id: usize) -> Vec<&str> {
    self
      .get_attribute(node_id, "class")
      .map(|c| c.split_whitespace().collect())
      .unwrap_or_default()
  }

  // -----------------------------------------------------------------------
  // Text content
  // -----------------------------------------------------------------------

  /// Recursively collect all descendant text content (depth-first).
  /// Alias kept for backward compatibility with selector/extractor modules.
  pub fn text_content(&self, node_id: usize) -> String {
    self.text(node_id)
  }

  /// Recursively collect all descendant text content (depth-first).
  pub fn text(&self, node_id: usize) -> String {
    let mut buf = String::new();
    self.collect_text(node_id, &mut buf);
    buf
  }

  fn collect_text(&self, id: usize, buf: &mut String) {
    if let Some(node) = self.arena.get(id) {
      match node.node_type {
        NodeType::Text => {
          let trimmed = node.text_content.trim();
          if !trimmed.is_empty() {
            if !buf.is_empty() && !buf.ends_with(' ') {
              buf.push(' ');
            }
            buf.push_str(trimmed);
          }
        }
        NodeType::Element => {
          // For raw-text elements, emit the stored text_content directly
          if !node.text_content.is_empty() {
            if !buf.is_empty() && !buf.ends_with(' ') {
              buf.push(' ');
            }
            buf.push_str(&node.text_content);
          }
          let kids = node.children.clone();
          for child in kids {
            self.collect_text(child, buf);
          }
        }
        NodeType::Comment => {} // comments produce no text
      }
    }
  }

  // -----------------------------------------------------------------------
  // HTML serialization
  // -----------------------------------------------------------------------

  /// Serialize the entire document back to an HTML string.
  pub fn to_html(&self) -> String {
    self.outer_html(self.root)
  }

  /// Remove nodes from the tree.  Each node in `ids` is detached from its
  /// parent's children list so it (and its subtree) no longer appears in
  /// serialization or traversal.
  pub fn remove_nodes(&mut self, ids: &[usize]) {
    let id_set: std::collections::HashSet<usize> = ids.iter().copied().collect();
    // For each node, remove it from its parent's children list
    for &id in ids {
      let parent_id = match self.arena.get(id) {
        Some(n) => n.parent,
        None => continue,
      };
      if let Some(pid) = parent_id {
        if let Some(parent) = self.arena.get_mut(pid) {
          parent.children.retain(|c| !id_set.contains(c));
        }
      }
    }
  }

  /// Remove all elements matching a CSS selector.
  /// Returns the number of elements removed.
  pub fn remove_by_selector(&mut self, selector_str: &str) -> usize {
    use crate::modules::html::selector;
    let Ok(sel) = selector::parse_selector(selector_str) else {
      return 0;
    };
    let ids = selector::select_all(self, &sel);
    let count = ids.len();
    self.remove_nodes(&ids);
    count
  }

  /// Serialize the children of `node_id` to an HTML string.
  pub fn inner_html(&self, node_id: usize) -> String {
    let mut buf = String::new();
    let kids = match self.arena.get(node_id) {
      Some(n) => n.children.clone(),
      None => return buf,
    };
    for child in kids {
      self.serialize_node(child, &mut buf);
    }
    buf
  }

  /// Serialize `node_id` itself (including its tag) to an HTML string.
  pub fn outer_html(&self, node_id: usize) -> String {
    let mut buf = String::new();
    self.serialize_node(node_id, &mut buf);
    buf
  }

  fn serialize_node(&self, id: usize, buf: &mut String) {
    let node = match self.arena.get(id) {
      Some(n) => n,
      None => return,
    };
    match node.node_type {
      NodeType::Text => {
        buf.push_str(&escape_html_text(&node.text_content));
      }
      NodeType::Comment => {
        buf.push_str("<!--");
        buf.push_str(&node.text_content);
        buf.push_str("-->");
      }
      NodeType::Element => {
        // Synthetic root -- just serialize children
        if node.tag_name == "[root]" {
          let kids = node.children.clone();
          for kid in kids {
            self.serialize_node(kid, buf);
          }
          return;
        }

        buf.push('<');
        buf.push_str(&node.tag_name);

        for (name, value) in &node.attributes {
          buf.push(' ');
          buf.push_str(name);
          buf.push_str("=\"");
          buf.push_str(&escape_html_attr(value));
          buf.push('"');
        }

        if is_void_tag(&node.tag_name) {
          buf.push_str(" />");
          return;
        }

        buf.push('>');

        // Raw-text content (script, style, etc.)
        if !node.text_content.is_empty() {
          buf.push_str(&node.text_content);
        }

        let kids = node.children.clone();
        for kid in kids {
          self.serialize_node(kid, buf);
        }

        buf.push_str("</");
        buf.push_str(&node.tag_name);
        buf.push('>');
      }
    }
  }

  // -----------------------------------------------------------------------
  // Search
  // -----------------------------------------------------------------------

  /// Find all elements whose tag name matches `tag` (case-insensitive).
  pub fn get_elements_by_tag_name(&self, tag: &str) -> Vec<usize> {
    let lower = tag.to_ascii_lowercase();
    let mut results = Vec::new();
    self.walk(self.root, &mut |id| {
      if let Some(node) = self.arena.get(id) {
        if node.node_type == NodeType::Element && node.tag_name == lower {
          results.push(id);
        }
      }
    });
    results
  }

  /// Find the first element whose `id` attribute equals `target_id`.
  pub fn get_element_by_id(&self, target_id: &str) -> Option<usize> {
    let mut found = None;
    self.walk(self.root, &mut |node_id| {
      if found.is_some() {
        return;
      }
      if let Some(node) = self.arena.get(node_id) {
        if node.node_type == NodeType::Element {
          if let Some(val) = self.get_attribute(node_id, "id") {
            if val == target_id {
              found = Some(node_id);
            }
          }
        }
      }
    });
    found
  }

  /// Find all elements that include `class` in their `class` attribute.
  pub fn get_elements_by_class_name(&self, class: &str) -> Vec<usize> {
    let mut results = Vec::new();
    self.walk(self.root, &mut |id| {
      if let Some(node) = self.arena.get(id) {
        if node.node_type == NodeType::Element {
          if let Some(cls_attr) = self.get_attribute(id, "class") {
            if cls_attr.split_whitespace().any(|c| c == class) {
              results.push(id);
            }
          }
        }
      }
    });
    results
  }

  /// Depth-first walk over every node reachable from `start`.
  fn walk(&self, start: usize, visitor: &mut dyn FnMut(usize)) {
    visitor(start);
    let kids = match self.arena.get(start) {
      Some(n) => n.children.clone(),
      None => return,
    };
    for kid in kids {
      self.walk(kid, visitor);
    }
  }
}

// ===========================================================================
// Internal single-pass parser
// ===========================================================================

struct InternalParser<'a> {
  src: &'a [u8],
  pos: usize,
  arena: &'a mut Arena,
  /// Stack of open element indices; the last entry is the current parent.
  stack: Vec<usize>,
}

impl<'a> InternalParser<'a> {
  /// Main parse loop -- scan through the source byte-by-byte.
  fn run(&mut self) {
    while self.pos < self.src.len() {
      if self.starts_with(b"<!--") {
        self.parse_comment();
      } else if self.at_doctype() {
        self.skip_doctype();
      } else if self.starts_with(b"</") {
        self.parse_closing_tag();
      } else if self.src[self.pos] == b'<' && self.next_is_alpha() {
        self.parse_opening_tag();
      } else if self.src[self.pos] == b'<' {
        // Stray '<' that does not start a valid tag -- skip bogus markup
        // like <!, <?, or bare < followed by non-alpha.
        self.skip_bogus();
      } else {
        self.parse_text();
      }
    }
  }

  // -- Utility helpers ---------------------------------------------------

  fn starts_with(&self, needle: &[u8]) -> bool {
    self.src[self.pos..].starts_with(needle)
  }

  /// Check if current position starts with `<!doctype` (case-insensitive).
  fn at_doctype(&self) -> bool {
    let rem = &self.src[self.pos..];
    if rem.len() < 9 {
      return false;
    }
    rem[0] == b'<' && rem[1] == b'!' && rem[2..9].eq_ignore_ascii_case(b"doctype")
  }

  /// Is the character after '<' alphabetic?
  fn next_is_alpha(&self) -> bool {
    let next = self.pos + 1;
    next < self.src.len() && self.src[next].is_ascii_alphabetic()
  }

  fn current_parent(&self) -> usize {
    *self.stack.last().unwrap_or(&0)
  }

  /// Append `child_id` to the current parent's children list and set the
  /// child's parent pointer.
  fn append_child(&mut self, child_id: usize) {
    let parent_id = self.current_parent();
    if let Some(parent) = self.arena.get_mut(parent_id) {
      parent.children.push(child_id);
    }
    if let Some(child) = self.arena.get_mut(child_id) {
      child.parent = Some(parent_id);
    }
  }

  fn skip_whitespace(&mut self) {
    while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
      self.pos += 1;
    }
  }

  // -- Comment -----------------------------------------------------------

  fn parse_comment(&mut self) {
    self.pos += 4; // skip `<!--`
    let start = self.pos;
    while self.pos < self.src.len() {
      if self.starts_with(b"-->") {
        let text = self.slice_str(start, self.pos);
        let id = self.arena.alloc(Node::comment(&text));
        self.append_child(id);
        self.pos += 3;
        return;
      }
      self.pos += 1;
    }
    // Unterminated comment -- consume everything remaining
    let text = self.slice_str(start, self.src.len());
    let id = self.arena.alloc(Node::comment(&text));
    self.append_child(id);
  }

  // -- Doctype (skipped) -------------------------------------------------

  fn skip_doctype(&mut self) {
    while self.pos < self.src.len() && self.src[self.pos] != b'>' {
      self.pos += 1;
    }
    if self.pos < self.src.len() {
      self.pos += 1; // skip '>'
    }
  }

  // -- Bogus markup (e.g. <!, <?) ----------------------------------------

  fn skip_bogus(&mut self) {
    // Advance past the '<'
    self.pos += 1;
    // Skip to '>' if present
    while self.pos < self.src.len() && self.src[self.pos] != b'>' {
      self.pos += 1;
    }
    if self.pos < self.src.len() {
      self.pos += 1; // skip '>'
    }
  }

  // -- Closing tag -------------------------------------------------------

  fn parse_closing_tag(&mut self) {
    self.pos += 2; // skip '</'
    let tag = self.scan_tag_name();
    // Skip to '>'
    while self.pos < self.src.len() && self.src[self.pos] != b'>' {
      self.pos += 1;
    }
    if self.pos < self.src.len() {
      self.pos += 1; // skip '>'
    }

    if tag.is_empty() {
      return;
    }

    // Walk the stack upward looking for a matching open tag
    self.close_tag(&tag);
  }

  /// Pop the stack up to and including the element whose tag matches `tag`.
  /// If the tag is not on the stack, the close is silently ignored (lenient
  /// behaviour for malformed HTML).
  fn close_tag(&mut self, tag: &str) {
    for i in (0..self.stack.len()).rev() {
      if let Some(node) = self.arena.get(self.stack[i]) {
        if node.tag_name == tag {
          self.stack.truncate(i);
          return;
        }
      }
    }
    // Not found -- silently ignore the close tag
  }

  // -- Opening tag -------------------------------------------------------

  fn parse_opening_tag(&mut self) {
    self.pos += 1; // skip '<'
    let tag = self.scan_tag_name();
    if tag.is_empty() {
      return;
    }

    // Auto-close peer elements (e.g. <li> closes open <li>)
    let peers = auto_close_peers(&tag);
    if !peers.is_empty() {
      // Search from the top of the stack for a peer to close.
      // Only look at the immediate top (do not cross block boundaries).
      for i in (1..self.stack.len()).rev() {
        if let Some(node) = self.arena.get(self.stack[i]) {
          if peers.contains(&node.tag_name.as_str()) {
            self.stack.truncate(i);
            break;
          }
        }
        // Stop at the first non-peer so we do not accidentally close
        // further up the tree.
        break;
      }
    }

    // Parse attributes
    let attrs = self.parse_attributes();

    // Detect explicit self-closing `<br />`
    self.skip_whitespace();
    let explicit_self_close = self.pos < self.src.len() && self.src[self.pos] == b'/';
    if explicit_self_close {
      self.pos += 1; // skip '/'
    }

    // Skip '>'
    if self.pos < self.src.len() && self.src[self.pos] == b'>' {
      self.pos += 1;
    }

    let self_closing = explicit_self_close || is_void_tag(&tag);

    let node_id = self
      .arena
      .alloc(Node::element_with_attrs(tag.clone(), attrs, self_closing));
    self.append_child(node_id);

    if self_closing {
      return; // void / self-closing -- never pushed
    }

    // Raw-text elements: scan forward to the closing tag
    if is_raw_text_tag(&tag) {
      self.stack.push(node_id);
      self.parse_raw_content(&tag);
      self.close_tag(&tag);
      return;
    }

    // Regular element -- push onto the stack
    self.stack.push(node_id);
  }

  // -- Raw-text content (script, style, etc.) ----------------------------

  fn parse_raw_content(&mut self, tag: &str) {
    let start = self.pos;
    let close_pattern = format!("</{}", tag);

    while self.pos < self.src.len() {
      if self.src[self.pos] == b'<'
        && self.pos + close_pattern.len() <= self.src.len()
        && self.src[self.pos..self.pos + close_pattern.len()]
          .eq_ignore_ascii_case(close_pattern.as_bytes())
      {
        // Verify it is followed by optional whitespace + '>'
        let after = self.pos + close_pattern.len();
        let mut probe = after;
        while probe < self.src.len() && self.src[probe].is_ascii_whitespace() {
          probe += 1;
        }
        if probe < self.src.len() && self.src[probe] == b'>' {
          let raw = self.slice_str(start, self.pos);
          if let Some(&nid) = self.stack.last() {
            if let Some(node) = self.arena.get_mut(nid) {
              node.text_content = raw;
            }
          }
          self.pos = probe + 1; // advance past </tag>
          return;
        }
      }
      self.pos += 1;
    }

    // Unterminated raw-text element -- store everything as content
    let raw = self.slice_str(start, self.src.len());
    if let Some(&nid) = self.stack.last() {
      if let Some(node) = self.arena.get_mut(nid) {
        node.text_content = raw;
      }
    }
  }

  // -- Text node ---------------------------------------------------------

  fn parse_text(&mut self) {
    let start = self.pos;
    while self.pos < self.src.len() && self.src[self.pos] != b'<' {
      self.pos += 1;
    }
    if self.pos == start {
      // Edge case: lone '<' that didn't start a valid tag -- advance to
      // prevent an infinite loop.
      if self.pos < self.src.len() {
        self.pos += 1;
      }
      return;
    }
    let raw = self.slice_str(start, self.pos);
    let text = decode_entities(&raw);
    // Keep whitespace-only text nodes only when they contain a newline
    // (likely significant formatting), otherwise skip them to match
    // typical DOM parsing behaviour.
    if !text.trim().is_empty() || text.contains('\n') {
      let id = self.arena.alloc(Node::text(&text));
      self.append_child(id);
    }
  }

  // -- Tag name scanning -------------------------------------------------

  /// Scan a tag name at the current position. Returns lowercase.
  fn scan_tag_name(&mut self) -> String {
    let start = self.pos;
    while self.pos < self.src.len() {
      let b = self.src[self.pos];
      if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':' {
        self.pos += 1;
      } else {
        break;
      }
    }
    let name = self.slice_str(start, self.pos);
    name.to_ascii_lowercase()
  }

  // -- Attribute parsing -------------------------------------------------

  fn parse_attributes(&mut self) -> Vec<(String, String)> {
    let mut attrs = Vec::new();

    loop {
      self.skip_whitespace();

      if self.pos >= self.src.len() {
        break;
      }

      let b = self.src[self.pos];
      if b == b'>' || b == b'/' {
        break;
      }

      // Scan attribute name
      let name_start = self.pos;
      while self.pos < self.src.len() {
        let c = self.src[self.pos];
        if c == b'=' || c == b'>' || c == b'/' || c.is_ascii_whitespace() {
          break;
        }
        self.pos += 1;
      }
      let attr_name = self.slice_str(name_start, self.pos).to_ascii_lowercase();
      if attr_name.is_empty() {
        // Junk character -- skip it to avoid infinite loop
        self.pos += 1;
        continue;
      }

      self.skip_whitespace();

      // Check for '='
      if self.pos < self.src.len() && self.src[self.pos] == b'=' {
        self.pos += 1; // skip '='
        self.skip_whitespace();
        let value = self.parse_attr_value();
        attrs.push((attr_name, value));
      } else {
        // Boolean attribute (no value)
        attrs.push((attr_name, String::new()));
      }
    }

    attrs
  }

  fn parse_attr_value(&mut self) -> String {
    if self.pos >= self.src.len() {
      return String::new();
    }

    let quote = self.src[self.pos];
    if quote == b'"' || quote == b'\'' {
      self.pos += 1; // skip opening quote
      let start = self.pos;
      while self.pos < self.src.len() && self.src[self.pos] != quote {
        self.pos += 1;
      }
      let val = self.slice_str(start, self.pos);
      if self.pos < self.src.len() {
        self.pos += 1; // skip closing quote
      }
      decode_entities(&val)
    } else {
      // Unquoted value -- ends at whitespace, '>', or '/'
      let start = self.pos;
      while self.pos < self.src.len() {
        let c = self.src[self.pos];
        if c.is_ascii_whitespace() || c == b'>' || c == b'/' {
          break;
        }
        self.pos += 1;
      }
      let val = self.slice_str(start, self.pos);
      decode_entities(&val)
    }
  }

  // -- Byte-to-string helper ---------------------------------------------

  /// Convert a byte range to a `String`. Uses lossy UTF-8 conversion so
  /// that invalid byte sequences are replaced rather than causing a panic.
  fn slice_str(&self, start: usize, end: usize) -> String {
    String::from_utf8_lossy(&self.src[start..end]).into_owned()
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // -- helpers -----------------------------------------------------------

  fn doc(html: &str) -> HtmlDocument {
    HtmlDocument::parse(html)
  }

  /// Collect all element tag names under root, depth-first.
  fn all_tags(d: &HtmlDocument) -> Vec<String> {
    let mut tags = Vec::new();
    collect_tags(d, d.root, &mut tags);
    tags
  }

  fn collect_tags(d: &HtmlDocument, id: usize, out: &mut Vec<String>) {
    if let Some(node) = d.arena.get(id) {
      if node.node_type == NodeType::Element && node.tag_name != "[root]" {
        out.push(node.tag_name.clone());
      }
      for &kid in &node.children.clone() {
        collect_tags(d, kid, out);
      }
    }
  }

  // ======================================================================
  // Basic parsing
  // ======================================================================

  #[test]
  fn test_parse_simple_div() {
    let d = doc("<div>Hello</div>");
    let divs = d.get_elements_by_tag_name("div");
    assert_eq!(divs.len(), 1);
    assert_eq!(d.text(divs[0]), "Hello");
  }

  #[test]
  fn test_parse_nested_elements() {
    let d = doc("<div><span><em>deep</em></span></div>");
    let tags = all_tags(&d);
    assert!(tags.contains(&"div".into()));
    assert!(tags.contains(&"span".into()));
    assert!(tags.contains(&"em".into()));

    let div = d.get_elements_by_tag_name("div")[0];
    assert_eq!(d.text(div), "deep");
  }

  #[test]
  fn test_parse_attributes() {
    let d = doc(r#"<a href="https://example.com" class="link active">Go</a>"#);
    let a = d.get_elements_by_tag_name("a")[0];
    assert_eq!(d.get_attribute(a, "href"), Some("https://example.com"));
    assert_eq!(d.get_attribute(a, "class"), Some("link active"));
  }

  #[test]
  fn test_parse_void_tags() {
    let d = doc("<div><br><hr><img src=\"x.png\"><input type=\"text\"></div>");
    let tags = all_tags(&d);
    assert!(tags.contains(&"br".into()));
    assert!(tags.contains(&"hr".into()));
    assert!(tags.contains(&"img".into()));
    assert!(tags.contains(&"input".into()));

    // Void tags must not eat following siblings
    let div = d.get_elements_by_tag_name("div")[0];
    assert_eq!(d.children(div).len(), 4);
  }

  #[test]
  fn test_parse_self_closing() {
    let d = doc("<br/><br />");
    let brs = d.get_elements_by_tag_name("br");
    assert_eq!(brs.len(), 2);
    for &br in &brs {
      assert!(d.arena.get(br).unwrap().self_closing);
    }
  }

  #[test]
  fn test_parse_comments() {
    let d = doc("<div><!-- this is a comment -->text</div>");
    let div = d.get_elements_by_tag_name("div")[0];
    let kids = d.children(div);
    let comments: Vec<usize> = kids
      .iter()
      .copied()
      .filter(|&k| d.node_type(k) == NodeType::Comment)
      .collect();
    assert_eq!(comments.len(), 1);
    assert_eq!(
      d.arena.get(comments[0]).unwrap().text_content,
      " this is a comment "
    );
  }

  #[test]
  fn test_parse_text_nodes() {
    let d = doc("<p>Hello <b>world</b> !</p>");
    let p = d.get_elements_by_tag_name("p")[0];
    let text = d.text(p);
    assert!(text.contains("Hello"));
    assert!(text.contains("world"));
  }

  #[test]
  fn test_parse_script_raw_content() {
    let d = doc(r#"<script>if (a < b && c > d) { alert("hi"); }</script>"#);
    let scripts = d.get_elements_by_tag_name("script");
    assert_eq!(scripts.len(), 1);
    let content = &d.arena.get(scripts[0]).unwrap().text_content;
    assert!(content.contains("a < b"));
    assert!(content.contains("c > d"));
  }

  #[test]
  fn test_parse_style_raw_content() {
    let d = doc("<style>body { color: red; } .a > .b { margin: 0; }</style>");
    let styles = d.get_elements_by_tag_name("style");
    assert_eq!(styles.len(), 1);
    let content = &d.arena.get(styles[0]).unwrap().text_content;
    assert!(content.contains("color: red"));
    assert!(content.contains(".a > .b"));
  }

  // ======================================================================
  // Auto-closing
  // ======================================================================

  #[test]
  fn test_auto_close_li() {
    let d = doc("<ul><li>One<li>Two<li>Three</ul>");
    let lis = d.get_elements_by_tag_name("li");
    assert_eq!(lis.len(), 3);
    let ul = d.get_elements_by_tag_name("ul")[0];
    let ul_kids: Vec<usize> = d
      .children(ul)
      .iter()
      .copied()
      .filter(|&id| d.node_type(id) == NodeType::Element)
      .collect();
    assert_eq!(ul_kids.len(), 3);
  }

  #[test]
  fn test_auto_close_p() {
    let d = doc("<div><p>First<p>Second</div>");
    let ps = d.get_elements_by_tag_name("p");
    assert_eq!(ps.len(), 2);
    let div = d.get_elements_by_tag_name("div")[0];
    let div_kids: Vec<usize> = d
      .children(div)
      .iter()
      .copied()
      .filter(|&id| d.node_type(id) == NodeType::Element)
      .collect();
    assert_eq!(div_kids.len(), 2);
  }

  #[test]
  fn test_auto_close_td() {
    let d = doc("<table><tr><td>A<td>B<th>C</tr></table>");
    let tds = d.get_elements_by_tag_name("td");
    assert_eq!(tds.len(), 2);
    let ths = d.get_elements_by_tag_name("th");
    assert_eq!(ths.len(), 1);
  }

  // ======================================================================
  // Malformed HTML
  // ======================================================================

  #[test]
  fn test_unclosed_tags() {
    let d = doc("<div><span>text");
    let divs = d.get_elements_by_tag_name("div");
    assert_eq!(divs.len(), 1);
    let spans = d.get_elements_by_tag_name("span");
    assert_eq!(spans.len(), 1);
  }

  #[test]
  fn test_extra_closing_tags() {
    let d = doc("<div>text</span></div>");
    let divs = d.get_elements_by_tag_name("div");
    assert_eq!(divs.len(), 1);
    assert_eq!(d.text(divs[0]), "text");
  }

  #[test]
  fn test_nested_same_tags() {
    let d = doc("<div><div>inner</div></div>");
    let divs = d.get_elements_by_tag_name("div");
    assert_eq!(divs.len(), 2);
  }

  // ======================================================================
  // Attributes
  // ======================================================================

  #[test]
  fn test_double_quoted_attr() {
    let d = doc(r#"<input type="text" value="hello world">"#);
    let input = d.get_elements_by_tag_name("input")[0];
    assert_eq!(d.get_attribute(input, "type"), Some("text"));
    assert_eq!(d.get_attribute(input, "value"), Some("hello world"));
  }

  #[test]
  fn test_single_quoted_attr() {
    let d = doc("<input type='text' value='hello'>");
    let input = d.get_elements_by_tag_name("input")[0];
    assert_eq!(d.get_attribute(input, "type"), Some("text"));
    assert_eq!(d.get_attribute(input, "value"), Some("hello"));
  }

  #[test]
  fn test_unquoted_attr() {
    let d = doc("<input type=text value=hello>");
    let input = d.get_elements_by_tag_name("input")[0];
    assert_eq!(d.get_attribute(input, "type"), Some("text"));
    assert_eq!(d.get_attribute(input, "value"), Some("hello"));
  }

  #[test]
  fn test_boolean_attr() {
    let d = doc("<input disabled readonly>");
    let input = d.get_elements_by_tag_name("input")[0];
    assert!(d.has_attribute(input, "disabled"));
    assert!(d.has_attribute(input, "readonly"));
    assert_eq!(d.get_attribute(input, "disabled"), Some(""));
  }

  #[test]
  fn test_multiple_attributes() {
    let d = doc(r#"<div id="main" class="container fluid" data-role="page" hidden></div>"#);
    let div = d.get_elements_by_tag_name("div")[0];
    assert_eq!(d.get_attribute(div, "id"), Some("main"));
    assert_eq!(d.get_attribute(div, "class"), Some("container fluid"));
    assert_eq!(d.get_attribute(div, "data-role"), Some("page"));
    assert!(d.has_attribute(div, "hidden"));
  }

  // ======================================================================
  // Text content
  // ======================================================================

  #[test]
  fn test_text_content_recursive() {
    let d = doc("<div>Hello <span>beautiful <b>world</b></span>!</div>");
    let div = d.get_elements_by_tag_name("div")[0];
    let text = d.text(div);
    assert!(text.contains("Hello"));
    assert!(text.contains("beautiful"));
    assert!(text.contains("world"));
  }

  #[test]
  fn test_inner_html_serialization() {
    let d = doc("<div><span>hi</span></div>");
    let div = d.get_elements_by_tag_name("div")[0];
    let html = d.inner_html(div);
    assert!(html.contains("<span>"));
    assert!(html.contains("hi"));
    assert!(html.contains("</span>"));
  }

  #[test]
  fn test_outer_html_serialization() {
    let d = doc("<div><span>hi</span></div>");
    let div = d.get_elements_by_tag_name("div")[0];
    let html = d.outer_html(div);
    assert!(html.starts_with("<div>"));
    assert!(html.ends_with("</div>"));
    assert!(html.contains("<span>hi</span>"));
  }

  // ======================================================================
  // Search methods
  // ======================================================================

  #[test]
  fn test_get_elements_by_tag_name() {
    let d = doc("<div><p>1</p><p>2</p><span><p>3</p></span></div>");
    let ps = d.get_elements_by_tag_name("p");
    assert_eq!(ps.len(), 3);
  }

  #[test]
  fn test_get_element_by_id() {
    let d = doc(r#"<div id="a"></div><div id="b"><span id="c"></span></div>"#);
    assert!(d.get_element_by_id("a").is_some());
    assert!(d.get_element_by_id("b").is_some());
    assert!(d.get_element_by_id("c").is_some());
    assert!(d.get_element_by_id("z").is_none());

    let c = d.get_element_by_id("c").unwrap();
    assert_eq!(d.tag_name(c), "span");
  }

  #[test]
  fn test_get_elements_by_class_name() {
    let d = doc(r#"<div class="a b"><span class="b c"></span><p class="a"></p></div>"#);
    assert_eq!(d.get_elements_by_class_name("a").len(), 2);
    assert_eq!(d.get_elements_by_class_name("b").len(), 2);
    assert_eq!(d.get_elements_by_class_name("c").len(), 1);
    assert_eq!(d.get_elements_by_class_name("z").len(), 0);
  }

  // ======================================================================
  // Entity decoding
  // ======================================================================

  #[test]
  fn test_decode_named_entities() {
    assert_eq!(decode_entities("&amp;"), "&");
    assert_eq!(decode_entities("&lt;"), "<");
    assert_eq!(decode_entities("&gt;"), ">");
    assert_eq!(decode_entities("&quot;"), "\"");
    assert_eq!(decode_entities("&apos;"), "'");
    assert_eq!(decode_entities("&nbsp;"), "\u{00A0}");
    assert_eq!(decode_entities("a &amp; b &lt; c"), "a & b < c");
  }

  #[test]
  fn test_decode_numeric_entities() {
    assert_eq!(decode_entities("&#65;"), "A");
    assert_eq!(decode_entities("&#97;"), "a");
    assert_eq!(decode_entities("&#169;"), "\u{00A9}"); // copyright
  }

  #[test]
  fn test_decode_hex_entities() {
    assert_eq!(decode_entities("&#x41;"), "A");
    assert_eq!(decode_entities("&#x61;"), "a");
    assert_eq!(decode_entities("&#xA9;"), "\u{00A9}");
    assert_eq!(decode_entities("&#X42;"), "B"); // uppercase X
  }

  #[test]
  fn test_entities_in_text() {
    let d = doc("<p>5 &gt; 3 &amp;&amp; 2 &lt; 4</p>");
    let p = d.get_elements_by_tag_name("p")[0];
    assert_eq!(d.text(p), "5 > 3 && 2 < 4");
  }

  #[test]
  fn test_entities_in_attributes() {
    let d = doc(r#"<a href="a&amp;b=1" title="&lt;tag&gt;">x</a>"#);
    let a = d.get_elements_by_tag_name("a")[0];
    assert_eq!(d.get_attribute(a, "href"), Some("a&b=1"));
    assert_eq!(d.get_attribute(a, "title"), Some("<tag>"));
  }

  // ======================================================================
  // class_list and id helpers
  // ======================================================================

  #[test]
  fn test_class_list() {
    let d = doc(r#"<div class="foo bar baz"></div>"#);
    let div = d.get_elements_by_tag_name("div")[0];
    assert_eq!(d.class_list(div), vec!["foo", "bar", "baz"]);
  }

  #[test]
  fn test_id_helper() {
    let d = doc(r#"<div id="main"></div>"#);
    let div = d.get_elements_by_tag_name("div")[0];
    assert_eq!(d.id(div), Some("main"));
  }

  // ======================================================================
  // Real-world HTML: login page
  // ======================================================================

  #[test]
  fn test_parse_login_page() {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login - My App</title>
  <link rel="stylesheet" href="/css/app.css">
  <script src="/js/app.js"></script>
  <style>
    body { font-family: sans-serif; }
    .login-form { max-width: 400px; margin: 0 auto; }
  </style>
</head>
<body>
  <nav id="main-nav" class="navbar fixed-top">
    <a href="/" class="brand">My App</a>
    <ul>
      <li><a href="/about">About</a>
      <li><a href="/contact">Contact</a>
    </ul>
  </nav>

  <main class="container">
    <div class="login-form" id="login-section">
      <h1>Sign In</h1>
      <form action="/auth/login" method="post">
        <input type="hidden" name="_token" value="abc123">
        <div class="form-group">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" required placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
        </div>
        <div class="form-check">
          <input type="checkbox" id="remember" name="remember">
          <label for="remember">Remember me</label>
        </div>
        <button type="submit" class="btn btn-primary">Log In</button>
      </form>
      <p>Don&apos;t have an account? <a href="/register">Sign up</a></p>
    </div>
  </main>

  <!-- footer -->
  <footer>
    <p>&copy; 2025 My App. All rights reserved.</p>
  </footer>
</body>
</html>"#;

    let d = doc(html);

    // Title element
    let titles = d.get_elements_by_tag_name("title");
    assert_eq!(titles.len(), 1);
    assert_eq!(d.text(titles[0]), "Login - My App");

    // Navigation
    let nav = d.get_element_by_id("main-nav").unwrap();
    assert_eq!(d.tag_name(nav), "nav");
    assert!(d.class_list(nav).contains(&"navbar"));

    // Form
    let forms = d.get_elements_by_tag_name("form");
    assert_eq!(forms.len(), 1);
    assert_eq!(d.get_attribute(forms[0], "action"), Some("/auth/login"));
    assert_eq!(d.get_attribute(forms[0], "method"), Some("post"));

    // Inputs (hidden + email + password + checkbox = 4 minimum)
    let inputs = d.get_elements_by_tag_name("input");
    assert!(inputs.len() >= 4);

    // Email input by id
    let email = d.get_element_by_id("email").unwrap();
    assert_eq!(d.get_attribute(email, "type"), Some("email"));
    assert!(d.has_attribute(email, "required"));
    assert_eq!(d.get_attribute(email, "placeholder"), Some("you@example.com"));

    // Auto-closed <li> tags
    let lis = d.get_elements_by_tag_name("li");
    assert_eq!(lis.len(), 2);

    // Class search
    let form_groups = d.get_elements_by_class_name("form-group");
    assert_eq!(form_groups.len(), 2);

    // Entity in text: "Don't"
    let login_section = d.get_element_by_id("login-section").unwrap();
    let section_text = d.text(login_section);
    assert!(section_text.contains("Don't"));

    // Footer exists
    let footer = d.get_elements_by_tag_name("footer");
    assert_eq!(footer.len(), 1);

    // Style raw content
    let styles = d.get_elements_by_tag_name("style");
    assert_eq!(styles.len(), 1);
    let style_content = &d.arena.get(styles[0]).unwrap().text_content;
    assert!(style_content.contains("font-family"));
    assert!(style_content.contains(".login-form"));

    // Links
    let links = d.get_elements_by_tag_name("a");
    assert!(links.len() >= 3);
  }

  // ======================================================================
  // Edge cases
  // ======================================================================

  #[test]
  fn test_empty_input() {
    let d = doc("");
    assert_eq!(d.children(d.root).len(), 0);
  }

  #[test]
  fn test_text_only() {
    let d = doc("just some text");
    let text = d.text(d.root);
    assert_eq!(text, "just some text");
  }

  #[test]
  fn test_case_insensitive_tags() {
    let d = doc("<DIV><SPAN>hi</SPAN></DIV>");
    assert_eq!(d.get_elements_by_tag_name("div").len(), 1);
    assert_eq!(d.get_elements_by_tag_name("span").len(), 1);
  }

  #[test]
  fn test_doctype_skipped() {
    let d = doc("<!DOCTYPE html><html><body>ok</body></html>");
    let bodies = d.get_elements_by_tag_name("body");
    assert_eq!(bodies.len(), 1);
    assert_eq!(d.text(bodies[0]), "ok");
  }

  #[test]
  fn test_case_insensitive_tag_search() {
    let d = doc("<div>x</div>");
    assert_eq!(d.get_elements_by_tag_name("DIV").len(), 1);
    assert_eq!(d.get_elements_by_tag_name("Div").len(), 1);
  }

  #[test]
  fn test_raw_text_script_with_nested_tags() {
    let d = doc("<script>var x = '<div>not a tag</div>';</script><p>after</p>");
    let scripts = d.get_elements_by_tag_name("script");
    assert_eq!(scripts.len(), 1);
    let content = &d.arena.get(scripts[0]).unwrap().text_content;
    assert!(content.contains("<div>not a tag</div>"));
    // <p> after the script should still parse
    assert_eq!(d.get_elements_by_tag_name("p").len(), 1);
  }

  #[test]
  fn test_void_tags_no_children() {
    let d = doc("<br><hr><img src=\"x\"><p>after</p>");
    let brs = d.get_elements_by_tag_name("br");
    let hrs = d.get_elements_by_tag_name("hr");
    assert_eq!(d.children(brs[0]).len(), 0);
    assert_eq!(d.children(hrs[0]).len(), 0);
    // <p> must NOT be a child of <img>
    let ps = d.get_elements_by_tag_name("p");
    assert_eq!(ps.len(), 1);
    let p_parent = d.parent(ps[0]).unwrap();
    assert_ne!(d.tag_name(p_parent), "img");
  }

  #[test]
  fn test_outer_html_void_tag() {
    let d = doc(r#"<img src="photo.jpg" alt="pic">"#);
    let imgs = d.get_elements_by_tag_name("img");
    let html = d.outer_html(imgs[0]);
    assert!(html.contains("<img"));
    assert!(html.contains("src=\"photo.jpg\""));
    assert!(html.contains("/>"));
  }

  #[test]
  fn test_deeply_nested() {
    let mut html = String::new();
    for _ in 0..50 {
      html.push_str("<div>");
    }
    html.push_str("deep");
    for _ in 0..50 {
      html.push_str("</div>");
    }
    let d = doc(&html);
    let divs = d.get_elements_by_tag_name("div");
    assert_eq!(divs.len(), 50);
    let deepest = divs.last().unwrap();
    assert_eq!(d.text(*deepest), "deep");
  }

  #[test]
  fn test_text_content_alias() {
    // text_content() is an alias for text() kept for backward compat
    let d = doc("<p>hello <b>world</b></p>");
    let p = d.get_elements_by_tag_name("p")[0];
    assert_eq!(d.text_content(p), d.text(p));
  }

  #[test]
  fn test_node_ids_depth_first() {
    let d = doc("<div><span>a</span><em>b</em></div>");
    let ids = d.node_ids();
    // Should include: div, span, text(a), em, text(b)
    assert!(ids.len() >= 4);
    // The root itself should NOT be in the list
    assert!(!ids.contains(&d.root));
  }

  #[test]
  fn test_element_children() {
    let d = doc("<div>text<span>a</span>more text<em>b</em></div>");
    let div = d.get_elements_by_tag_name("div")[0];
    let elem_kids = d.element_children(div);
    // Only span and em, not text nodes
    assert_eq!(elem_kids.len(), 2);
    assert_eq!(d.tag_name(elem_kids[0]), "span");
    assert_eq!(d.tag_name(elem_kids[1]), "em");
  }

  #[test]
  fn test_has_attribute() {
    let d = doc(r#"<input type="text" disabled>"#);
    let input = d.get_elements_by_tag_name("input")[0];
    assert!(d.has_attribute(input, "type"));
    assert!(d.has_attribute(input, "disabled"));
    assert!(!d.has_attribute(input, "readonly"));
  }

  #[test]
  fn test_parent_tracking() {
    let d = doc("<div><p>text</p></div>");
    let div = d.children(d.root)[0];
    let p = d.children(div)[0];
    assert_eq!(d.parent(p), Some(div));
    assert_eq!(d.parent(div), Some(d.root));
  }

  #[test]
  fn test_comment_nodes() {
    let d = doc("<div><!-- a comment --><p>text</p></div>");
    let div = d.children(d.root)[0];
    let children = d.children(div);
    assert!(children.len() >= 2);
    assert_eq!(d.node_type(children[0]), NodeType::Comment);
  }

  #[test]
  fn test_entity_decoding_basic() {
    let d = doc("<p>&amp; &lt; &gt; &quot;</p>");
    let p = d.children(d.root)[0];
    let text = d.text_content(p);
    assert!(text.contains('&'));
    assert!(text.contains('<'));
    assert!(text.contains('>'));
    assert!(text.contains('"'));
  }

  #[test]
  fn test_parse_self_closing_void() {
    let d = doc("<div><br/><img src='x.png'/><p>text</p></div>");
    let div = d.children(d.root)[0];
    let children = d.children(div);
    assert_eq!(children.len(), 3);
    assert_eq!(d.tag_name(children[0]), "br");
    assert_eq!(d.tag_name(children[1]), "img");
    assert_eq!(d.tag_name(children[2]), "p");
  }

  #[test]
  fn test_void_elements_not_pushed() {
    let d = doc("<div><input type='text'><span>hi</span></div>");
    let div = d.children(d.root)[0];
    let children = d.children(div);
    assert_eq!(children.len(), 2);
    assert_eq!(d.tag_name(children[0]), "input");
    assert_eq!(d.tag_name(children[1]), "span");
  }
}
