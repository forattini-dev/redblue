#![allow(dead_code)]

/// HTML Parser with Arena-based DOM
///
/// Provides a fast, zero-dependency HTML parser that builds an arena-allocated
/// DOM tree. The arena approach gives O(1) node access and cache-friendly
/// traversal for the CSS selector engine.
///
/// NO external dependencies - pure Rust std implementation.

/// Node type constants matching the DOM spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
  Element = 1,
  Text = 3,
  Comment = 8,
}

/// A single DOM node stored in the arena
#[derive(Debug, Clone)]
pub struct Node {
  pub node_type: NodeType,
  pub tag_name: String,
  pub attributes: Vec<(String, String)>,
  pub children: Vec<usize>,
  pub parent: Option<usize>,
  pub text_content: String,
  pub self_closing: bool,
}

impl Node {
  /// Create a new element node
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

  /// Create a new text node
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

  /// Create a new comment node
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

/// Arena allocator for DOM nodes -- flat Vec for O(1) access
#[derive(Debug)]
pub struct Arena {
  nodes: Vec<Node>,
}

impl Arena {
  fn new() -> Self {
    Self { nodes: Vec::new() }
  }

  fn alloc(&mut self, node: Node) -> usize {
    let id = self.nodes.len();
    self.nodes.push(node);
    id
  }

  pub fn get(&self, id: usize) -> Option<&Node> {
    self.nodes.get(id)
  }

  pub fn get_mut(&mut self, id: usize) -> Option<&mut Node> {
    self.nodes.get_mut(id)
  }

  pub fn len(&self) -> usize {
    self.nodes.len()
  }

  pub fn is_empty(&self) -> bool {
    self.nodes.is_empty()
  }
}

/// A parsed HTML document backed by an arena
#[derive(Debug)]
pub struct HtmlDocument {
  pub arena: Arena,
  /// Index of the synthetic root node (contains all top-level nodes)
  pub root: usize,
}

impl HtmlDocument {
  /// Parse an HTML string into an HtmlDocument
  pub fn parse(html: &str) -> Self {
    let mut arena = Arena::new();

    // Create a synthetic root element to hold top-level nodes
    let root_node = Node::element("[root]");
    let root = arena.alloc(root_node);

    let mut parser = HtmlTokenizer::new(html);
    let mut stack: Vec<usize> = vec![root];

    while let Some(token) = parser.next_token() {
      match token {
        Token::OpenTag {
          name,
          attributes,
          self_closing,
        } => {
          let mut node = Node::element(&name);
          node.attributes = attributes;
          node.self_closing = self_closing;
          let id = arena.alloc(node);

          // Link to parent
          if let Some(&parent_id) = stack.last() {
            arena.get_mut(id).unwrap().parent = Some(parent_id);
            arena.get_mut(parent_id).unwrap().children.push(id);
          }

          // Push onto stack unless self-closing or void
          if !self_closing && !is_void_element(&name) {
            stack.push(id);
          }
        }
        Token::CloseTag { name } => {
          // Pop the stack back to the matching open tag
          let name_lower = name.to_lowercase();
          let mut found = false;
          for i in (1..stack.len()).rev() {
            let tag = arena.get(stack[i]).map(|n| n.tag_name.as_str());
            if tag == Some(&name_lower) {
              stack.truncate(i);
              found = true;
              break;
            }
          }
          // If not found, ignore the close tag (malformed HTML tolerance)
          let _ = found;
        }
        Token::Text { content } => {
          if content.trim().is_empty() && content.len() < 2 {
            // Skip trivial whitespace-only text nodes
            continue;
          }
          let node = Node::text(&content);
          let id = arena.alloc(node);

          if let Some(&parent_id) = stack.last() {
            arena.get_mut(id).unwrap().parent = Some(parent_id);
            arena.get_mut(parent_id).unwrap().children.push(id);
          }
        }
        Token::Comment { content } => {
          let node = Node::comment(&content);
          let id = arena.alloc(node);

          if let Some(&parent_id) = stack.last() {
            arena.get_mut(id).unwrap().parent = Some(parent_id);
            arena.get_mut(parent_id).unwrap().children.push(id);
          }
        }
      }
    }

    HtmlDocument { arena, root }
  }

  /// Get an attribute value for a node
  pub fn get_attribute(&self, node_id: usize, name: &str) -> Option<&str> {
    let node = self.arena.get(node_id)?;
    let name_lower = name.to_lowercase();
    node
      .attributes
      .iter()
      .find(|(k, _)| k.to_lowercase() == name_lower)
      .map(|(_, v)| v.as_str())
  }

  /// Get the tag name of a node (lowercase)
  pub fn tag_name(&self, node_id: usize) -> &str {
    self
      .arena
      .get(node_id)
      .map(|n| n.tag_name.as_str())
      .unwrap_or("")
  }

  /// Get the children of a node
  pub fn children(&self, node_id: usize) -> &[usize] {
    self
      .arena
      .get(node_id)
      .map(|n| n.children.as_slice())
      .unwrap_or(&[])
  }

  /// Get the parent of a node
  pub fn parent(&self, node_id: usize) -> Option<usize> {
    self.arena.get(node_id).and_then(|n| n.parent)
  }

  /// Get the node type
  pub fn node_type(&self, node_id: usize) -> NodeType {
    self
      .arena
      .get(node_id)
      .map(|n| n.node_type)
      .unwrap_or(NodeType::Text)
  }

  /// Get the id attribute of a node
  pub fn id(&self, node_id: usize) -> Option<&str> {
    self.get_attribute(node_id, "id")
  }

  /// Get the class list of a node as whitespace-separated tokens
  pub fn class_list(&self, node_id: usize) -> Vec<&str> {
    self
      .get_attribute(node_id, "class")
      .map(|c| c.split_whitespace().collect())
      .unwrap_or_default()
  }

  /// Get the text content of a node (recursive)
  pub fn text_content(&self, node_id: usize) -> String {
    let mut buf = String::new();
    self.collect_text(node_id, &mut buf);
    buf
  }

  fn collect_text(&self, node_id: usize, buf: &mut String) {
    if let Some(node) = self.arena.get(node_id) {
      match node.node_type {
        NodeType::Text => {
          let text = node.text_content.trim();
          if !text.is_empty() {
            if !buf.is_empty() && !buf.ends_with(' ') {
              buf.push(' ');
            }
            buf.push_str(text);
          }
        }
        NodeType::Element => {
          for &child in &node.children {
            self.collect_text(child, buf);
          }
        }
        NodeType::Comment => {}
      }
    }
  }

  /// Iterate over all node IDs in document order (depth-first)
  pub fn node_ids(&self) -> Vec<usize> {
    let mut result = Vec::new();
    self.collect_ids_dfs(self.root, &mut result);
    result
  }

  fn collect_ids_dfs(&self, node_id: usize, result: &mut Vec<usize>) {
    // Don't include the synthetic root itself
    if node_id != self.root {
      result.push(node_id);
    }
    for &child in self.children(node_id) {
      self.collect_ids_dfs(child, result);
    }
  }

  /// Check whether a node_id is a valid element
  pub fn is_element(&self, node_id: usize) -> bool {
    self
      .arena
      .get(node_id)
      .map(|n| n.node_type == NodeType::Element)
      .unwrap_or(false)
  }

  /// Get element child indices (only Element-type children)
  pub fn element_children(&self, node_id: usize) -> Vec<usize> {
    self
      .children(node_id)
      .iter()
      .copied()
      .filter(|&id| self.is_element(id))
      .collect()
  }
}

// ============================================================================
// HTML Tokenizer
// ============================================================================

#[derive(Debug)]
enum Token {
  OpenTag {
    name: String,
    attributes: Vec<(String, String)>,
    self_closing: bool,
  },
  CloseTag {
    name: String,
  },
  Text {
    content: String,
  },
  Comment {
    content: String,
  },
}

struct HtmlTokenizer<'a> {
  input: &'a str,
  pos: usize,
}

impl<'a> HtmlTokenizer<'a> {
  fn new(input: &'a str) -> Self {
    Self { input, pos: 0 }
  }

  fn next_token(&mut self) -> Option<Token> {
    if self.pos >= self.input.len() {
      return None;
    }

    if self.starts_with("<!--") {
      return Some(self.read_comment());
    }

    if self.starts_with("</") {
      return Some(self.read_close_tag());
    }

    if self.starts_with("<") && self.pos + 1 < self.input.len() {
      let next = self.input.as_bytes()[self.pos + 1];
      if next.is_ascii_alphabetic() {
        return Some(self.read_open_tag());
      }
      // Skip things like <!, <? etc
      if next == b'!' || next == b'?' {
        return Some(self.read_bogus());
      }
    }

    Some(self.read_text())
  }

  fn read_comment(&mut self) -> Token {
    self.pos += 4; // skip <!--
    let start = self.pos;
    while self.pos < self.input.len() {
      if self.starts_with("-->") {
        let content = &self.input[start..self.pos];
        self.pos += 3;
        return Token::Comment {
          content: content.to_string(),
        };
      }
      self.pos += 1;
    }
    // Unterminated comment
    Token::Comment {
      content: self.input[start..].to_string(),
    }
  }

  fn read_close_tag(&mut self) -> Token {
    self.pos += 2; // skip </
    self.skip_ws();
    let name = self.read_tag_name();
    // Skip to >
    while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'>' {
      self.pos += 1;
    }
    if self.pos < self.input.len() {
      self.pos += 1; // skip >
    }
    Token::CloseTag { name }
  }

  fn read_open_tag(&mut self) -> Token {
    self.pos += 1; // skip <
    let name = self.read_tag_name();
    let mut attributes = Vec::new();
    let mut self_closing = false;

    loop {
      self.skip_ws();
      if self.pos >= self.input.len() {
        break;
      }

      let ch = self.input.as_bytes()[self.pos];
      if ch == b'>' {
        self.pos += 1;
        break;
      }
      if ch == b'/' {
        self.pos += 1;
        self_closing = true;
        self.skip_ws();
        if self.pos < self.input.len() && self.input.as_bytes()[self.pos] == b'>' {
          self.pos += 1;
        }
        break;
      }

      // Read attribute
      if let Some((key, val)) = self.read_attribute() {
        attributes.push((key, val));
      } else {
        // Skip unrecognized character
        self.pos += 1;
      }
    }

    Token::OpenTag {
      name,
      attributes,
      self_closing,
    }
  }

  fn read_bogus(&mut self) -> Token {
    // Skip <!DOCTYPE ...> and <?xml ...> etc
    let start = self.pos;
    while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'>' {
      self.pos += 1;
    }
    if self.pos < self.input.len() {
      self.pos += 1;
    }
    Token::Comment {
      content: self.input[start..self.pos].to_string(),
    }
  }

  fn read_text(&mut self) -> Token {
    let start = self.pos;
    while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'<' {
      self.pos += 1;
    }
    let raw = &self.input[start..self.pos];
    Token::Text {
      content: decode_entities(raw),
    }
  }

  fn read_tag_name(&mut self) -> String {
    let start = self.pos;
    while self.pos < self.input.len() {
      let ch = self.input.as_bytes()[self.pos];
      if ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_' || ch == b':' {
        self.pos += 1;
      } else {
        break;
      }
    }
    self.input[start..self.pos].to_lowercase()
  }

  fn read_attribute(&mut self) -> Option<(String, String)> {
    let start = self.pos;
    // Attribute name
    while self.pos < self.input.len() {
      let ch = self.input.as_bytes()[self.pos];
      if ch == b'=' || ch == b'>' || ch == b'/' || ch.is_ascii_whitespace() {
        break;
      }
      self.pos += 1;
    }
    if self.pos == start {
      return None;
    }
    let key = self.input[start..self.pos].to_lowercase();

    self.skip_ws();
    if self.pos >= self.input.len() || self.input.as_bytes()[self.pos] != b'=' {
      // Boolean attribute (no value)
      return Some((key, String::new()));
    }
    self.pos += 1; // skip =
    self.skip_ws();

    let value = if self.pos < self.input.len() {
      let ch = self.input.as_bytes()[self.pos];
      if ch == b'"' || ch == b'\'' {
        self.read_quoted_value(ch)
      } else {
        self.read_unquoted_value()
      }
    } else {
      String::new()
    };

    Some((key, value))
  }

  fn read_quoted_value(&mut self, quote: u8) -> String {
    self.pos += 1; // skip opening quote
    let start = self.pos;
    while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != quote {
      self.pos += 1;
    }
    let val = &self.input[start..self.pos];
    if self.pos < self.input.len() {
      self.pos += 1; // skip closing quote
    }
    decode_entities(val)
  }

  fn read_unquoted_value(&mut self) -> String {
    let start = self.pos;
    while self.pos < self.input.len() {
      let ch = self.input.as_bytes()[self.pos];
      if ch.is_ascii_whitespace() || ch == b'>' || ch == b'/' {
        break;
      }
      self.pos += 1;
    }
    decode_entities(&self.input[start..self.pos])
  }

  fn skip_ws(&mut self) {
    while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
      self.pos += 1;
    }
  }

  fn starts_with(&self, prefix: &str) -> bool {
    self.input[self.pos..].starts_with(prefix)
  }
}

// ============================================================================
// Helpers
// ============================================================================

fn is_void_element(tag: &str) -> bool {
  matches!(
    tag.to_lowercase().as_str(),
    "area"
      | "base"
      | "br"
      | "col"
      | "embed"
      | "hr"
      | "img"
      | "input"
      | "link"
      | "meta"
      | "param"
      | "source"
      | "track"
      | "wbr"
  )
}

/// Decode the most common HTML entities
fn decode_entities(s: &str) -> String {
  if !s.contains('&') {
    return s.to_string();
  }
  let mut result = String::with_capacity(s.len());
  let mut chars = s.chars().peekable();
  while let Some(c) = chars.next() {
    if c == '&' {
      let mut entity = String::new();
      while let Some(&ec) = chars.peek() {
        if ec == ';' {
          chars.next();
          break;
        }
        if ec.is_ascii_whitespace() || ec == '<' || ec == '&' {
          break;
        }
        entity.push(ec);
        chars.next();
      }
      match entity.as_str() {
        "amp" => result.push('&'),
        "lt" => result.push('<'),
        "gt" => result.push('>'),
        "quot" => result.push('"'),
        "apos" => result.push('\''),
        "nbsp" => result.push('\u{00a0}'),
        s if s.starts_with('#') => {
          let code = if s.starts_with("#x") || s.starts_with("#X") {
            u32::from_str_radix(&s[2..], 16).ok()
          } else {
            s[1..].parse::<u32>().ok()
          };
          if let Some(cp) = code.and_then(char::from_u32) {
            result.push(cp);
          } else {
            result.push('&');
            result.push_str(&entity);
            result.push(';');
          }
        }
        _ => {
          result.push('&');
          result.push_str(&entity);
          result.push(';');
        }
      }
    } else {
      result.push(c);
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
  fn test_parse_simple_html() {
    let doc = HtmlDocument::parse("<div><p>Hello</p></div>");
    // root -> div -> p -> "Hello"
    let root_children = doc.children(doc.root);
    assert_eq!(root_children.len(), 1);
    assert_eq!(doc.tag_name(root_children[0]), "div");

    let div_children = doc.children(root_children[0]);
    assert_eq!(div_children.len(), 1);
    assert_eq!(doc.tag_name(div_children[0]), "p");
  }

  #[test]
  fn test_parse_attributes() {
    let doc = HtmlDocument::parse(r#"<a href="/test" class="link active" id="main">Go</a>"#);
    let root_children = doc.children(doc.root);
    let a = root_children[0];
    assert_eq!(doc.get_attribute(a, "href"), Some("/test"));
    assert_eq!(doc.id(a), Some("main"));
    let classes = doc.class_list(a);
    assert_eq!(classes, vec!["link", "active"]);
  }

  #[test]
  fn test_parse_self_closing() {
    let doc = HtmlDocument::parse("<div><br/><img src='x.png'/><p>text</p></div>");
    let div = doc.children(doc.root)[0];
    let children = doc.children(div);
    // br, img, p
    assert_eq!(children.len(), 3);
    assert_eq!(doc.tag_name(children[0]), "br");
    assert_eq!(doc.tag_name(children[1]), "img");
    assert_eq!(doc.tag_name(children[2]), "p");
  }

  #[test]
  fn test_parse_void_elements() {
    let doc = HtmlDocument::parse("<div><input type='text'><span>hi</span></div>");
    let div = doc.children(doc.root)[0];
    let children = doc.children(div);
    assert_eq!(children.len(), 2);
    assert_eq!(doc.tag_name(children[0]), "input");
    assert_eq!(doc.tag_name(children[1]), "span");
  }

  #[test]
  fn test_text_content() {
    let doc = HtmlDocument::parse("<div><p>Hello</p> <p>World</p></div>");
    let div = doc.children(doc.root)[0];
    let text = doc.text_content(div);
    assert!(text.contains("Hello"));
    assert!(text.contains("World"));
  }

  #[test]
  fn test_parent_tracking() {
    let doc = HtmlDocument::parse("<div><p>text</p></div>");
    let div = doc.children(doc.root)[0];
    let p = doc.children(div)[0];
    assert_eq!(doc.parent(p), Some(div));
    assert_eq!(doc.parent(div), Some(doc.root));
  }

  #[test]
  fn test_comment_nodes() {
    let doc = HtmlDocument::parse("<div><!-- a comment --><p>text</p></div>");
    let div = doc.children(doc.root)[0];
    let children = doc.children(div);
    // comment + p
    assert!(children.len() >= 2);
    assert_eq!(
      doc.node_type(children[0]),
      NodeType::Comment
    );
  }

  #[test]
  fn test_entity_decoding() {
    let doc = HtmlDocument::parse("<p>&amp; &lt; &gt; &quot;</p>");
    let p = doc.children(doc.root)[0];
    let text = doc.text_content(p);
    assert!(text.contains('&'));
    assert!(text.contains('<'));
    assert!(text.contains('>'));
    assert!(text.contains('"'));
  }
}
