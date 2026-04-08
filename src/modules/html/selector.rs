#![allow(dead_code)]

/// CSS Selector Engine for HtmlDocument (arena-based DOM)
///
/// A hand-written CSS selector parser and matcher operating on the arena-based
/// HtmlDocument. Supports tag, class, id, attribute, combinator, compound,
/// group, and pseudo-class selectors -- everything needed for real-world
/// HTML scraping and security analysis.
///
/// NO external dependencies, no regex crate - pure Rust std implementation.
use super::parser::{HtmlDocument, NodeType};

// ============================================================================
// Selector AST
// ============================================================================

/// A parsed CSS selector
#[derive(Debug, Clone)]
pub enum Selector {
  /// Universal: *
  Universal,
  /// Tag name: div, p, a
  Tag(String),
  /// ID: #main
  Id(String),
  /// Class: .active
  Class(String),
  /// Attribute: [href], [type="text"], [class~="foo"], [href^="https"]
  Attribute(AttrSelector),
  /// Combinator: combines two selectors with a relationship
  Combinator(Box<Selector>, CombinatorOp, Box<Selector>),
  /// Compound: multiple simple selectors on same element (div.active#main)
  Compound(Vec<Selector>),
  /// Group: comma-separated (div, p, .class)
  Group(Vec<Selector>),
  /// Pseudo-class: :first-child, :last-child, :nth-child(n), :not(selector)
  Pseudo(PseudoSelector),
}

/// Relationship between two selectors joined by a combinator
#[derive(Debug, Clone, PartialEq)]
pub enum CombinatorOp {
  /// " " (space) -- any descendant
  Descendant,
  /// ">" -- direct child only
  Child,
  /// "+" -- immediately following sibling element
  AdjacentSibling,
  /// "~" -- any following sibling element
  GeneralSibling,
}

/// Attribute selector with optional operator and value
#[derive(Debug, Clone)]
pub struct AttrSelector {
  pub name: String,
  pub op: Option<AttrOp>,
  pub value: Option<String>,
}

/// Attribute comparison operators
#[derive(Debug, Clone, PartialEq)]
pub enum AttrOp {
  /// = exact match
  Equals,
  /// ~= word in space-separated list
  Contains,
  /// ^= starts with
  StartsWith,
  /// $= ends with
  EndsWith,
  /// *= substring
  Substring,
  /// |= exact value or value followed by -
  DashMatch,
}

/// Pseudo-class selectors
#[derive(Debug, Clone)]
pub enum PseudoSelector {
  FirstChild,
  LastChild,
  NthChild(NthExpr),
  NthLastChild(NthExpr),
  Not(Box<Selector>),
  Empty,
}

/// An+B expression for :nth-child() etc.
#[derive(Debug, Clone)]
pub struct NthExpr {
  pub a: i32,
  pub b: i32,
}

// ============================================================================
// Selector Parser
// ============================================================================

/// Parse a CSS selector string into a Selector AST.
///
/// Returns `Err` with a description for invalid selectors. Never panics.
pub fn parse_selector(input: &str) -> Result<Selector, String> {
  let input = input.trim();
  if input.is_empty() {
    return Err("empty selector".to_string());
  }

  let mut parser = Parser::new(input);
  parser.parse_top_level()
}

struct Parser<'a> {
  input: &'a [u8],
  pos: usize,
}

impl<'a> Parser<'a> {
  fn new(input: &'a str) -> Self {
    Self {
      input: input.as_bytes(),
      pos: 0,
    }
  }

  // ---- top-level: handle comma-separated groups ----------------------------

  fn parse_top_level(&mut self) -> Result<Selector, String> {
    let first = self.parse_combinator_chain()?;

    self.skip_ws();
    if self.pos >= self.input.len() {
      return Ok(first);
    }

    if self.peek() != Some(b',') {
      return Ok(first);
    }

    // We have a group (comma-separated list)
    let mut groups = vec![first];
    while self.peek() == Some(b',') {
      self.advance(); // skip comma
      self.skip_ws();
      if self.pos >= self.input.len() {
        return Err("trailing comma in selector".to_string());
      }
      groups.push(self.parse_combinator_chain()?);
      self.skip_ws();
    }

    Ok(Selector::Group(groups))
  }

  // ---- combinator chain: A > B + C ----------------------------------------

  fn parse_combinator_chain(&mut self) -> Result<Selector, String> {
    self.skip_ws();
    let mut left = self.parse_compound()?;

    loop {
      let before = self.pos;
      let had_ws = self.skip_ws_count() > 0;

      if self.pos >= self.input.len() {
        break;
      }

      let ch = self.peek().unwrap();
      if ch == b',' || ch == b')' {
        // End of this chain (group separator or end of :not())
        self.pos = if had_ws {
          before + self.leading_ws_from(before)
        } else {
          before
        };
        // Restore position to before whitespace we consumed
        self.pos = before;
        self.skip_ws();
        break;
      }

      let combinator = match ch {
        b'>' => {
          self.advance();
          self.skip_ws();
          CombinatorOp::Child
        }
        b'+' => {
          self.advance();
          self.skip_ws();
          CombinatorOp::AdjacentSibling
        }
        b'~' => {
          self.advance();
          self.skip_ws();
          CombinatorOp::GeneralSibling
        }
        _ if had_ws => CombinatorOp::Descendant,
        _ => break,
      };

      let right = self.parse_compound()?;
      left = Selector::Combinator(Box::new(left), combinator, Box::new(right));
    }

    Ok(left)
  }

  // ---- compound: div.class#id[attr]:pseudo ---------------------------------

  fn parse_compound(&mut self) -> Result<Selector, String> {
    let mut parts: Vec<Selector> = Vec::new();

    loop {
      if self.pos >= self.input.len() {
        break;
      }

      let ch = self.peek().unwrap();
      match ch {
        b'*' => {
          self.advance();
          parts.push(Selector::Universal);
        }
        b'#' => {
          self.advance();
          let name = self.read_ident()?;
          parts.push(Selector::Id(name));
        }
        b'.' => {
          self.advance();
          let name = self.read_ident()?;
          parts.push(Selector::Class(name));
        }
        b'[' => {
          parts.push(self.parse_attribute_selector()?);
        }
        b':' => {
          parts.push(self.parse_pseudo_selector()?);
        }
        c if is_ident_start(c) => {
          let name = self.read_ident()?;
          parts.push(Selector::Tag(name.to_lowercase()));
        }
        _ => break,
      }
    }

    if parts.is_empty() {
      return Err(format!(
        "expected selector at position {}, got {:?}",
        self.pos,
        self.peek().map(|b| b as char)
      ));
    }

    if parts.len() == 1 {
      Ok(parts.remove(0))
    } else {
      Ok(Selector::Compound(parts))
    }
  }

  // ---- attribute selector: [name], [name="val"], [name^="val"] etc. --------

  fn parse_attribute_selector(&mut self) -> Result<Selector, String> {
    self.expect(b'[')?;
    self.skip_ws();
    let name = self.read_ident()?.to_lowercase();
    self.skip_ws();

    if self.peek() == Some(b']') {
      self.advance();
      return Ok(Selector::Attribute(AttrSelector {
        name,
        op: None,
        value: None,
      }));
    }

    let op = self.parse_attr_op()?;
    self.skip_ws();
    let value = self.parse_attr_value()?;
    self.skip_ws();

    self.expect(b']')?;

    Ok(Selector::Attribute(AttrSelector {
      name,
      op: Some(op),
      value: Some(value),
    }))
  }

  fn parse_attr_op(&mut self) -> Result<AttrOp, String> {
    let ch = self.peek().ok_or("unexpected end in attribute selector")?;
    match ch {
      b'=' => {
        self.advance();
        Ok(AttrOp::Equals)
      }
      b'~' => {
        self.advance();
        self.expect(b'=')?;
        Ok(AttrOp::Contains)
      }
      b'^' => {
        self.advance();
        self.expect(b'=')?;
        Ok(AttrOp::StartsWith)
      }
      b'$' => {
        self.advance();
        self.expect(b'=')?;
        Ok(AttrOp::EndsWith)
      }
      b'*' => {
        self.advance();
        self.expect(b'=')?;
        Ok(AttrOp::Substring)
      }
      b'|' => {
        self.advance();
        self.expect(b'=')?;
        Ok(AttrOp::DashMatch)
      }
      _ => Err(format!(
        "invalid attribute operator '{}' at position {}",
        ch as char, self.pos
      )),
    }
  }

  fn parse_attr_value(&mut self) -> Result<String, String> {
    let ch = self.peek().ok_or("unexpected end in attribute value")?;
    if ch == b'"' || ch == b'\'' {
      self.parse_quoted_string(ch)
    } else {
      self.read_ident()
    }
  }

  fn parse_quoted_string(&mut self, quote: u8) -> Result<String, String> {
    self.advance(); // skip opening quote
    let start = self.pos;
    while self.pos < self.input.len() {
      if self.input[self.pos] == b'\\' && self.pos + 1 < self.input.len() {
        self.pos += 2; // skip escaped char
        continue;
      }
      if self.input[self.pos] == quote {
        let val = std::str::from_utf8(&self.input[start..self.pos])
          .map_err(|_| "invalid UTF-8 in attribute value")?;
        self.advance(); // skip closing quote
        return Ok(val.to_string());
      }
      self.pos += 1;
    }
    Err("unterminated string in attribute selector".to_string())
  }

  // ---- pseudo-class: :first-child, :nth-child(2n+1), :not(.foo) -----------

  fn parse_pseudo_selector(&mut self) -> Result<Selector, String> {
    self.expect(b':')?;
    // Handle :: (pseudo-elements treated like pseudo-classes for tolerance)
    if self.peek() == Some(b':') {
      self.advance();
    }

    let name = self.read_ident()?.to_lowercase();

    match name.as_str() {
      "first-child" => Ok(Selector::Pseudo(PseudoSelector::FirstChild)),
      "last-child" => Ok(Selector::Pseudo(PseudoSelector::LastChild)),
      "empty" => Ok(Selector::Pseudo(PseudoSelector::Empty)),
      "nth-child" => {
        let expr = self.parse_nth_expr()?;
        Ok(Selector::Pseudo(PseudoSelector::NthChild(expr)))
      }
      "nth-last-child" => {
        let expr = self.parse_nth_expr()?;
        Ok(Selector::Pseudo(PseudoSelector::NthLastChild(expr)))
      }
      "not" => {
        self.expect(b'(')?;
        self.skip_ws();
        let inner = self.parse_compound()?;
        self.skip_ws();
        self.expect(b')')?;
        Ok(Selector::Pseudo(PseudoSelector::Not(Box::new(inner))))
      }
      _ => Err(format!("unsupported pseudo-class :{}", name)),
    }
  }

  fn parse_nth_expr(&mut self) -> Result<NthExpr, String> {
    self.expect(b'(')?;
    self.skip_ws();

    // Collect everything up to ')'
    let start = self.pos;
    let mut depth = 1u32;
    while self.pos < self.input.len() {
      match self.input[self.pos] {
        b'(' => depth += 1,
        b')' => {
          depth -= 1;
          if depth == 0 {
            break;
          }
        }
        _ => {}
      }
      self.pos += 1;
    }

    let expr_str = std::str::from_utf8(&self.input[start..self.pos])
      .map_err(|_| "invalid UTF-8 in nth expression")?
      .trim()
      .to_lowercase();

    self.expect(b')')?;

    parse_nth_formula(&expr_str)
  }

  // ---- low-level helpers ---------------------------------------------------

  fn peek(&self) -> Option<u8> {
    self.input.get(self.pos).copied()
  }

  fn advance(&mut self) {
    if self.pos < self.input.len() {
      self.pos += 1;
    }
  }

  fn expect(&mut self, expected: u8) -> Result<(), String> {
    if self.peek() == Some(expected) {
      self.advance();
      Ok(())
    } else {
      Err(format!(
        "expected '{}' at position {}, got {:?}",
        expected as char,
        self.pos,
        self.peek().map(|b| b as char)
      ))
    }
  }

  fn skip_ws(&mut self) {
    while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
      self.pos += 1;
    }
  }

  fn skip_ws_count(&mut self) -> usize {
    let start = self.pos;
    self.skip_ws();
    self.pos - start
  }

  fn leading_ws_from(&self, from: usize) -> usize {
    let mut n = 0;
    while from + n < self.input.len() && self.input[from + n].is_ascii_whitespace() {
      n += 1;
    }
    n
  }

  fn read_ident(&mut self) -> Result<String, String> {
    let start = self.pos;
    while self.pos < self.input.len() && is_ident_char(self.input[self.pos]) {
      self.pos += 1;
    }
    if self.pos == start {
      return Err(format!(
        "expected identifier at position {}, got {:?}",
        self.pos,
        self.peek().map(|b| b as char)
      ));
    }
    std::str::from_utf8(&self.input[start..self.pos])
      .map(|s| s.to_string())
      .map_err(|_| "invalid UTF-8 in identifier".to_string())
  }
}

// ============================================================================
// Nth-child formula parser (An+B)
// ============================================================================

fn parse_nth_formula(s: &str) -> Result<NthExpr, String> {
  let s = s.replace(' ', "");

  if s == "even" {
    return Ok(NthExpr { a: 2, b: 0 });
  }
  if s == "odd" {
    return Ok(NthExpr { a: 2, b: 1 });
  }

  // Check if it contains 'n'
  if let Some(n_pos) = s.find('n') {
    let a_part = &s[..n_pos];
    let b_part = &s[n_pos + 1..];

    let a: i32 = match a_part {
      "" | "+" => 1,
      "-" => -1,
      _ => a_part
        .parse()
        .map_err(|_| format!("invalid coefficient in nth expression: '{}'", s))?,
    };

    let b: i32 = if b_part.is_empty() {
      0
    } else {
      b_part
        .parse()
        .map_err(|_| format!("invalid offset in nth expression: '{}'", s))?
    };

    Ok(NthExpr { a, b })
  } else {
    // Just a number -- :nth-child(3) means a=0, b=3
    let n: i32 = s
      .parse()
      .map_err(|_| format!("invalid nth expression: '{}'", s))?;
    Ok(NthExpr { a: 0, b: n })
  }
}

// ============================================================================
// Character classification
// ============================================================================

fn is_ident_start(c: u8) -> bool {
  c.is_ascii_alphabetic() || c == b'_' || c == b'-'
}

fn is_ident_char(c: u8) -> bool {
  c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

// ============================================================================
// Selector Matcher
// ============================================================================

/// Check if a single node matches a selector
pub fn matches(doc: &HtmlDocument, node_id: usize, selector: &Selector) -> bool {
  // Only element nodes can be matched (text/comment never match)
  if doc.node_type(node_id) != NodeType::Element {
    return false;
  }

  match selector {
    Selector::Universal => true,

    Selector::Tag(tag) => doc.tag_name(node_id).eq_ignore_ascii_case(tag),

    Selector::Id(id) => doc.id(node_id).map(|v| v == id).unwrap_or(false),

    Selector::Class(cls) => doc
      .class_list(node_id)
      .iter()
      .any(|c| c.eq_ignore_ascii_case(cls)),

    Selector::Attribute(attr) => match_attribute(doc, node_id, attr),

    Selector::Compound(parts) => parts.iter().all(|p| matches(doc, node_id, p)),

    Selector::Group(groups) => groups.iter().any(|g| matches(doc, node_id, g)),

    Selector::Combinator(left, op, right) => {
      // The right side must match the current node
      if !matches(doc, node_id, right) {
        return false;
      }
      // Then check the relationship for the left side
      match op {
        CombinatorOp::Descendant => {
          // Walk ancestors until one matches `left`
          let mut current = doc.parent(node_id);
          while let Some(ancestor_id) = current {
            if matches(doc, ancestor_id, left) {
              return true;
            }
            current = doc.parent(ancestor_id);
          }
          false
        }
        CombinatorOp::Child => {
          // Direct parent must match `left`
          doc
            .parent(node_id)
            .map(|pid| matches(doc, pid, left))
            .unwrap_or(false)
        }
        CombinatorOp::AdjacentSibling => {
          // The immediately preceding element sibling must match `left`
          if let Some(prev) = preceding_element_sibling(doc, node_id) {
            matches(doc, prev, left)
          } else {
            false
          }
        }
        CombinatorOp::GeneralSibling => {
          // Any preceding element sibling must match `left`
          for sib in all_preceding_element_siblings(doc, node_id) {
            if matches(doc, sib, left) {
              return true;
            }
          }
          false
        }
      }
    }

    Selector::Pseudo(pseudo) => match_pseudo(doc, node_id, pseudo),
  }
}

/// Find all nodes in document order matching the selector (depth-first)
pub fn select_all(doc: &HtmlDocument, selector: &Selector) -> Vec<usize> {
  let mut result = Vec::new();
  collect_matches(doc, doc.root, selector, &mut result);
  result
}

/// Find first matching node in document order
pub fn select_first(doc: &HtmlDocument, selector: &Selector) -> Option<usize> {
  find_first_match(doc, doc.root, selector)
}

// ---- recursive helpers for traversal ---------------------------------------

fn collect_matches(
  doc: &HtmlDocument,
  node_id: usize,
  selector: &Selector,
  result: &mut Vec<usize>,
) {
  // Check current node (skip the synthetic root)
  if node_id != doc.root && matches(doc, node_id, selector) {
    result.push(node_id);
  }
  // Recurse into children
  let children: Vec<usize> = doc.children(node_id).to_vec();
  for child in children {
    collect_matches(doc, child, selector, result);
  }
}

fn find_first_match(doc: &HtmlDocument, node_id: usize, selector: &Selector) -> Option<usize> {
  if node_id != doc.root && matches(doc, node_id, selector) {
    return Some(node_id);
  }
  let children: Vec<usize> = doc.children(node_id).to_vec();
  for child in children {
    if let Some(found) = find_first_match(doc, child, selector) {
      return Some(found);
    }
  }
  None
}

// ============================================================================
// Attribute matching
// ============================================================================

fn match_attribute(doc: &HtmlDocument, node_id: usize, attr: &AttrSelector) -> bool {
  let val = doc.get_attribute(node_id, &attr.name);

  match (&attr.op, &attr.value) {
    (None, _) => {
      // [attr] -- just check existence
      val.is_some()
    }
    (Some(op), Some(expected)) => {
      let actual = match val {
        Some(v) => v,
        None => return false,
      };
      match op {
        AttrOp::Equals => actual == expected,
        AttrOp::Contains => actual.split_whitespace().any(|w| w == expected),
        AttrOp::StartsWith => actual.starts_with(expected.as_str()),
        AttrOp::EndsWith => actual.ends_with(expected.as_str()),
        AttrOp::Substring => actual.contains(expected.as_str()),
        AttrOp::DashMatch => actual == expected || actual.starts_with(&format!("{}-", expected)),
      }
    }
    _ => false,
  }
}

// ============================================================================
// Pseudo-class matching
// ============================================================================

fn match_pseudo(doc: &HtmlDocument, node_id: usize, pseudo: &PseudoSelector) -> bool {
  match pseudo {
    PseudoSelector::FirstChild => {
      if let Some(parent_id) = doc.parent(node_id) {
        let siblings = doc.element_children(parent_id);
        siblings.first() == Some(&node_id)
      } else {
        false
      }
    }
    PseudoSelector::LastChild => {
      if let Some(parent_id) = doc.parent(node_id) {
        let siblings = doc.element_children(parent_id);
        siblings.last() == Some(&node_id)
      } else {
        false
      }
    }
    PseudoSelector::NthChild(expr) => {
      if let Some(parent_id) = doc.parent(node_id) {
        let siblings = doc.element_children(parent_id);
        if let Some(pos) = siblings.iter().position(|&id| id == node_id) {
          nth_matches(expr, (pos + 1) as i32) // 1-indexed
        } else {
          false
        }
      } else {
        false
      }
    }
    PseudoSelector::NthLastChild(expr) => {
      if let Some(parent_id) = doc.parent(node_id) {
        let siblings = doc.element_children(parent_id);
        if let Some(pos) = siblings.iter().position(|&id| id == node_id) {
          let from_end = (siblings.len() - pos) as i32; // 1-indexed from end
          nth_matches(expr, from_end)
        } else {
          false
        }
      } else {
        false
      }
    }
    PseudoSelector::Not(inner) => !matches(doc, node_id, inner),
    PseudoSelector::Empty => {
      // Element is empty if it has no element children and no non-empty text
      doc.children(node_id).iter().all(|&child_id| {
        match doc.node_type(child_id) {
          NodeType::Element => false,
          NodeType::Text => doc
            .arena
            .get(child_id)
            .map(|n| n.text_content.trim().is_empty())
            .unwrap_or(true),
          NodeType::Comment => true, // comments are ignored for :empty
        }
      })
    }
  }
}

/// Check whether a 1-indexed position matches an An+B expression
fn nth_matches(expr: &NthExpr, position: i32) -> bool {
  let a = expr.a;
  let b = expr.b;

  if a == 0 {
    return position == b;
  }

  // position = a*n + b, solve for n: n = (position - b) / a
  let diff = position - b;
  if diff % a != 0 {
    return false;
  }
  let n = diff / a;
  n >= 0
}

// ============================================================================
// Sibling helpers
// ============================================================================

/// Get the immediately preceding element sibling of a node
fn preceding_element_sibling(doc: &HtmlDocument, node_id: usize) -> Option<usize> {
  let parent_id = doc.parent(node_id)?;
  let siblings = doc.element_children(parent_id);
  let pos = siblings.iter().position(|&id| id == node_id)?;
  if pos == 0 {
    None
  } else {
    Some(siblings[pos - 1])
  }
}

/// Get all preceding element siblings of a node (in document order)
fn all_preceding_element_siblings(doc: &HtmlDocument, node_id: usize) -> Vec<usize> {
  let parent_id = match doc.parent(node_id) {
    Some(id) => id,
    None => return Vec::new(),
  };
  let siblings = doc.element_children(parent_id);
  let pos = match siblings.iter().position(|&id| id == node_id) {
    Some(p) => p,
    None => return Vec::new(),
  };
  siblings[..pos].to_vec()
}

// ============================================================================
// Convenience methods on HtmlDocument
// ============================================================================

impl HtmlDocument {
  /// Select all elements matching a CSS selector string.
  /// Returns node IDs in document order. Returns an empty Vec for invalid selectors.
  pub fn select(&self, selector_str: &str) -> Vec<usize> {
    match parse_selector(selector_str) {
      Ok(sel) => select_all(self, &sel),
      Err(_) => Vec::new(),
    }
  }

  /// Select the first element matching a CSS selector string.
  /// Returns None for invalid selectors or no match.
  pub fn select_one(&self, selector_str: &str) -> Option<usize> {
    match parse_selector(selector_str) {
      Ok(sel) => select_first(self, &sel),
      Err(_) => None,
    }
  }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::modules::html::parser::HtmlDocument;

  // --------------------------------------------------------------------------
  // Helper: build a standard test document for matching tests
  // --------------------------------------------------------------------------

  fn test_doc() -> HtmlDocument {
    HtmlDocument::parse(
      r#"<html>
<head><title>Test Page</title></head>
<body>
  <nav id="main-nav" class="nav primary">
    <a href="/" class="link active">Home</a>
    <a href="/about" class="link">About</a>
    <a href="/contact" class="link">Contact</a>
  </nav>
  <div id="content" class="container">
    <h1 class="title">Welcome</h1>
    <p class="intro">Hello <strong>World</strong></p>
    <p class="body hidden">Body text</p>
    <ul>
      <li class="item first">One</li>
      <li class="item">Two</li>
      <li class="item">Three</li>
      <li class="item last">Four</li>
    </ul>
    <form action="/submit" method="post">
      <input type="text" name="user" class="input" />
      <input type="password" name="pass" class="input" />
      <input type="email" name="email" />
      <button type="submit">Go</button>
    </form>
    <div class="empty-div"></div>
    <a href="https://example.com" data-lang="en-US">External</a>
  </div>
</body>
</html>"#,
    )
  }

  // ==========================================================================
  // Selector parsing tests
  // ==========================================================================

  #[test]
  fn test_parse_tag_selector() {
    let sel = parse_selector("div").unwrap();
    assert!(core::matches!(sel, Selector::Tag(ref t) if t == "div"));
  }

  #[test]
  fn test_parse_id_selector() {
    let sel = parse_selector("#main").unwrap();
    assert!(core::matches!(sel, Selector::Id(ref id) if id == "main"));
  }

  #[test]
  fn test_parse_class_selector() {
    let sel = parse_selector(".active").unwrap();
    assert!(core::matches!(sel, Selector::Class(ref c) if c == "active"));
  }

  #[test]
  fn test_parse_universal_selector() {
    let sel = parse_selector("*").unwrap();
    assert!(core::matches!(sel, Selector::Universal));
  }

  #[test]
  fn test_parse_compound_selector() {
    let sel = parse_selector("div.active#main").unwrap();
    if let Selector::Compound(parts) = sel {
      assert_eq!(parts.len(), 3);
      assert!(core::matches!(&parts[0], Selector::Tag(t) if t == "div"));
      assert!(core::matches!(&parts[1], Selector::Class(c) if c == "active"));
      assert!(core::matches!(&parts[2], Selector::Id(id) if id == "main"));
    } else {
      panic!("expected Compound, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_descendant_combinator() {
    let sel = parse_selector("div p").unwrap();
    if let Selector::Combinator(left, op, right) = sel {
      assert_eq!(op, CombinatorOp::Descendant);
      assert!(core::matches!(*left, Selector::Tag(ref t) if t == "div"));
      assert!(core::matches!(*right, Selector::Tag(ref t) if t == "p"));
    } else {
      panic!("expected Combinator, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_child_combinator() {
    let sel = parse_selector("div > p").unwrap();
    if let Selector::Combinator(left, op, right) = sel {
      assert_eq!(op, CombinatorOp::Child);
      assert!(core::matches!(*left, Selector::Tag(ref t) if t == "div"));
      assert!(core::matches!(*right, Selector::Tag(ref t) if t == "p"));
    } else {
      panic!("expected Combinator, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_adjacent_sibling() {
    let sel = parse_selector("div + p").unwrap();
    if let Selector::Combinator(_, op, _) = sel {
      assert_eq!(op, CombinatorOp::AdjacentSibling);
    } else {
      panic!("expected Combinator, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_general_sibling() {
    let sel = parse_selector("div ~ p").unwrap();
    if let Selector::Combinator(_, op, _) = sel {
      assert_eq!(op, CombinatorOp::GeneralSibling);
    } else {
      panic!("expected Combinator, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_exists() {
    let sel = parse_selector("[href]").unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.name, "href");
      assert!(attr.op.is_none());
      assert!(attr.value.is_none());
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_equals() {
    let sel = parse_selector(r#"[type="text"]"#).unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.name, "type");
      assert_eq!(attr.op, Some(AttrOp::Equals));
      assert_eq!(attr.value.as_deref(), Some("text"));
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_contains() {
    let sel = parse_selector(r#"[class~="active"]"#).unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.op, Some(AttrOp::Contains));
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_starts_with() {
    let sel = parse_selector(r#"[href^="https"]"#).unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.op, Some(AttrOp::StartsWith));
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_ends_with() {
    let sel = parse_selector(r#"[href$=".com"]"#).unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.op, Some(AttrOp::EndsWith));
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_substring() {
    let sel = parse_selector(r#"[href*="example"]"#).unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.op, Some(AttrOp::Substring));
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_attribute_dash_match() {
    let sel = parse_selector(r#"[data-lang|="en"]"#).unwrap();
    if let Selector::Attribute(attr) = sel {
      assert_eq!(attr.op, Some(AttrOp::DashMatch));
      assert_eq!(attr.value.as_deref(), Some("en"));
    } else {
      panic!("expected Attribute, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_group_selector() {
    let sel = parse_selector("div, p, .class").unwrap();
    if let Selector::Group(groups) = sel {
      assert_eq!(groups.len(), 3);
    } else {
      panic!("expected Group, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_pseudo_first_child() {
    let sel = parse_selector(":first-child").unwrap();
    assert!(core::matches!(
      sel,
      Selector::Pseudo(PseudoSelector::FirstChild)
    ));
  }

  #[test]
  fn test_parse_pseudo_last_child() {
    let sel = parse_selector(":last-child").unwrap();
    assert!(core::matches!(
      sel,
      Selector::Pseudo(PseudoSelector::LastChild)
    ));
  }

  #[test]
  fn test_parse_pseudo_nth_child_number() {
    let sel = parse_selector(":nth-child(3)").unwrap();
    if let Selector::Pseudo(PseudoSelector::NthChild(expr)) = sel {
      assert_eq!(expr.a, 0);
      assert_eq!(expr.b, 3);
    } else {
      panic!("expected NthChild, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_pseudo_nth_child_formula() {
    let sel = parse_selector(":nth-child(2n+1)").unwrap();
    if let Selector::Pseudo(PseudoSelector::NthChild(expr)) = sel {
      assert_eq!(expr.a, 2);
      assert_eq!(expr.b, 1);
    } else {
      panic!("expected NthChild, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_pseudo_nth_child_even() {
    let sel = parse_selector(":nth-child(even)").unwrap();
    if let Selector::Pseudo(PseudoSelector::NthChild(expr)) = sel {
      assert_eq!(expr.a, 2);
      assert_eq!(expr.b, 0);
    } else {
      panic!("expected NthChild(even), got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_pseudo_nth_child_odd() {
    let sel = parse_selector(":nth-child(odd)").unwrap();
    if let Selector::Pseudo(PseudoSelector::NthChild(expr)) = sel {
      assert_eq!(expr.a, 2);
      assert_eq!(expr.b, 1);
    } else {
      panic!("expected NthChild(odd), got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_pseudo_not() {
    let sel = parse_selector(":not(.hidden)").unwrap();
    if let Selector::Pseudo(PseudoSelector::Not(inner)) = sel {
      assert!(core::matches!(*inner, Selector::Class(ref c) if c == "hidden"));
    } else {
      panic!("expected Not, got {:?}", sel);
    }
  }

  #[test]
  fn test_parse_pseudo_empty() {
    let sel = parse_selector(":empty").unwrap();
    assert!(core::matches!(sel, Selector::Pseudo(PseudoSelector::Empty)));
  }

  #[test]
  fn test_parse_error_empty_input() {
    assert!(parse_selector("").is_err());
  }

  #[test]
  fn test_parse_error_trailing_comma() {
    assert!(parse_selector("div,").is_err());
  }

  #[test]
  fn test_parse_chained_combinator() {
    // div > ul li  =>  Combinator(Combinator(div, Child, ul), Descendant, li)
    let sel = parse_selector("div > ul li").unwrap();
    if let Selector::Combinator(left, op, right) = sel {
      assert_eq!(op, CombinatorOp::Descendant);
      assert!(core::matches!(*right, Selector::Tag(ref t) if t == "li"));
      if let Selector::Combinator(ll, lop, lr) = *left {
        assert_eq!(lop, CombinatorOp::Child);
        assert!(core::matches!(*ll, Selector::Tag(ref t) if t == "div"));
        assert!(core::matches!(*lr, Selector::Tag(ref t) if t == "ul"));
      } else {
        panic!("expected nested Combinator, got {:?}", left);
      }
    } else {
      panic!("expected Combinator, got {:?}", sel);
    }
  }

  // ==========================================================================
  // Matching tests
  // ==========================================================================

  #[test]
  fn test_match_tag() {
    let doc = test_doc();
    let ids = doc.select("h1");
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.tag_name(ids[0]), "h1");
  }

  #[test]
  fn test_match_id() {
    let doc = test_doc();
    let ids = doc.select("#content");
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.id(ids[0]), Some("content"));
  }

  #[test]
  fn test_match_class() {
    let doc = test_doc();
    let ids = doc.select(".link");
    assert_eq!(ids.len(), 3); // three nav links
    for &id in &ids {
      assert!(doc.class_list(id).contains(&"link"));
    }
  }

  #[test]
  fn test_match_attribute_exists() {
    let doc = test_doc();
    let ids = doc.select("[href]");
    // nav has 3 <a> links + 1 external <a>
    assert_eq!(ids.len(), 4);
  }

  #[test]
  fn test_match_attribute_equals() {
    let doc = test_doc();
    let ids = doc.select(r#"[type="text"]"#);
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.tag_name(ids[0]), "input");
    assert_eq!(doc.get_attribute(ids[0], "name"), Some("user"));
  }

  #[test]
  fn test_match_attribute_starts_with() {
    let doc = test_doc();
    let ids = doc.select(r#"[href^="https"]"#);
    assert_eq!(ids.len(), 1);
    assert_eq!(
      doc.get_attribute(ids[0], "href"),
      Some("https://example.com")
    );
  }

  #[test]
  fn test_match_attribute_ends_with() {
    let doc = test_doc();
    let ids = doc.select(r#"[href$=".com"]"#);
    assert_eq!(ids.len(), 1);
  }

  #[test]
  fn test_match_attribute_substring() {
    let doc = test_doc();
    let ids = doc.select(r#"[href*="example"]"#);
    assert_eq!(ids.len(), 1);
  }

  #[test]
  fn test_match_attribute_contains_word() {
    let doc = test_doc();
    let ids = doc.select(r#"[class~="active"]"#);
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"active"));
  }

  #[test]
  fn test_match_attribute_dash_match() {
    let doc = test_doc();
    let ids = doc.select(r#"[data-lang|="en"]"#);
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.get_attribute(ids[0], "data-lang"), Some("en-US"));
  }

  #[test]
  fn test_match_compound() {
    let doc = test_doc();
    let ids = doc.select("a.link.active");
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.text_content(ids[0]), "Home");
  }

  #[test]
  fn test_match_descendant() {
    let doc = test_doc();
    let ids = doc.select("nav a");
    assert_eq!(ids.len(), 3);
  }

  #[test]
  fn test_match_child() {
    let doc = test_doc();
    let ids = doc.select("ul > li");
    assert_eq!(ids.len(), 4);
  }

  #[test]
  fn test_match_adjacent_sibling() {
    let doc = test_doc();
    // h1 + p => the <p> immediately after <h1>
    let ids = doc.select("h1 + p");
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"intro"));
  }

  #[test]
  fn test_match_general_sibling() {
    let doc = test_doc();
    // h1 ~ p => all <p> siblings after <h1>
    let ids = doc.select("h1 ~ p");
    assert_eq!(ids.len(), 2);
  }

  #[test]
  fn test_match_not_pseudo() {
    let doc = test_doc();
    let ids = doc.select("p:not(.hidden)");
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"intro"));
  }

  #[test]
  fn test_match_first_child() {
    let doc = test_doc();
    let ids = doc.select("li:first-child");
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"first"));
  }

  #[test]
  fn test_match_last_child() {
    let doc = test_doc();
    let ids = doc.select("li:last-child");
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"last"));
  }

  #[test]
  fn test_match_nth_child() {
    let doc = test_doc();
    // :nth-child(2) -- the second li
    let ids = doc.select("li:nth-child(2)");
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.text_content(ids[0]), "Two");
  }

  #[test]
  fn test_match_nth_child_odd() {
    let doc = test_doc();
    let ids = doc.select("li:nth-child(odd)");
    // 1st and 3rd li
    assert_eq!(ids.len(), 2);
    assert_eq!(doc.text_content(ids[0]), "One");
    assert_eq!(doc.text_content(ids[1]), "Three");
  }

  #[test]
  fn test_match_nth_child_even() {
    let doc = test_doc();
    let ids = doc.select("li:nth-child(even)");
    assert_eq!(ids.len(), 2);
    assert_eq!(doc.text_content(ids[0]), "Two");
    assert_eq!(doc.text_content(ids[1]), "Four");
  }

  #[test]
  fn test_match_nth_child_formula() {
    let doc = test_doc();
    // 2n+1 = odd positions (1, 3)
    let ids = doc.select("li:nth-child(2n+1)");
    assert_eq!(ids.len(), 2);
    assert_eq!(doc.text_content(ids[0]), "One");
    assert_eq!(doc.text_content(ids[1]), "Three");
  }

  #[test]
  fn test_match_empty() {
    let doc = test_doc();
    let ids = doc.select(".empty-div:empty");
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"empty-div"));
  }

  // ==========================================================================
  // select_all / select_first tests
  // ==========================================================================

  #[test]
  fn test_select_all_by_tag() {
    let doc = test_doc();
    let sel = parse_selector("li").unwrap();
    let ids = select_all(&doc, &sel);
    assert_eq!(ids.len(), 4);
  }

  #[test]
  fn test_select_all_by_class() {
    let doc = test_doc();
    let sel = parse_selector(".item").unwrap();
    let ids = select_all(&doc, &sel);
    assert_eq!(ids.len(), 4);
  }

  #[test]
  fn test_select_complex_chain() {
    let doc = test_doc();
    // #content > ul > li.item
    let ids = doc.select("#content > ul > li.item");
    assert_eq!(ids.len(), 4);
  }

  #[test]
  fn test_select_first_returns_first() {
    let doc = test_doc();
    let sel = parse_selector("li").unwrap();
    let first = select_first(&doc, &sel);
    assert!(first.is_some());
    assert!(doc.class_list(first.unwrap()).contains(&"first"));
  }

  #[test]
  fn test_select_with_group() {
    let doc = test_doc();
    let ids = doc.select("h1, h2, h3");
    // only h1 exists
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.tag_name(ids[0]), "h1");
  }

  #[test]
  fn test_select_group_multiple() {
    let doc = test_doc();
    let ids = doc.select("h1, p");
    // 1 h1 + 2 p = 3
    assert_eq!(ids.len(), 3);
  }

  #[test]
  fn test_select_universal() {
    let doc = HtmlDocument::parse("<div><p>a</p><span>b</span></div>");
    let ids = doc.select("div > *");
    assert_eq!(ids.len(), 2);
  }

  // ==========================================================================
  // Real-world scenario tests
  // ==========================================================================

  #[test]
  fn test_select_links_from_page() {
    let doc = test_doc();
    let ids = doc.select("a[href]");
    assert_eq!(ids.len(), 4);

    // Check all have href
    for &id in &ids {
      assert!(doc.get_attribute(id, "href").is_some());
    }

    // Specifically check external links
    let external = doc.select(r#"a[href^="https"]"#);
    assert_eq!(external.len(), 1);
    assert_eq!(doc.text_content(external[0]), "External");
  }

  #[test]
  fn test_select_form_inputs() {
    let doc = test_doc();

    // All inputs
    let inputs = doc.select("form input");
    assert_eq!(inputs.len(), 3);

    // Text inputs only
    let text_inputs = doc.select(r#"input[type="text"]"#);
    assert_eq!(text_inputs.len(), 1);

    // Password inputs
    let pass_inputs = doc.select(r#"input[type="password"]"#);
    assert_eq!(pass_inputs.len(), 1);

    // Submit button
    let buttons = doc.select(r#"button[type="submit"]"#);
    assert_eq!(buttons.len(), 1);
    assert_eq!(doc.text_content(buttons[0]), "Go");
  }

  #[test]
  fn test_select_navigation_items() {
    let doc = test_doc();

    // Get nav links
    let nav_links = doc.select("nav > a.link");
    assert_eq!(nav_links.len(), 3);

    // Get active nav link
    let active = doc.select("nav a.active");
    assert_eq!(active.len(), 1);
    assert_eq!(doc.text_content(active[0]), "Home");

    // Get inactive nav links (using :not)
    let inactive = doc.select("nav a:not(.active)");
    assert_eq!(inactive.len(), 2);
  }

  #[test]
  fn test_select_nested_content() {
    let doc = test_doc();

    // Select strong inside p
    let strong = doc.select("p strong");
    assert_eq!(strong.len(), 1);
    assert_eq!(doc.text_content(strong[0]), "World");

    // Select p with specific class inside #content
    let intro = doc.select("#content p.intro");
    assert_eq!(intro.len(), 1);
  }

  #[test]
  fn test_select_one_returns_first() {
    let doc = test_doc();
    let id = doc.select_one("li");
    assert!(id.is_some());
    assert!(doc.class_list(id.unwrap()).contains(&"first"));
  }

  #[test]
  fn test_select_one_no_match() {
    let doc = test_doc();
    assert!(doc.select_one("table").is_none());
  }

  #[test]
  fn test_match_nth_last_child() {
    let doc = test_doc();
    // :nth-last-child(1) = last child
    let ids = doc.select("li:nth-last-child(1)");
    assert_eq!(ids.len(), 1);
    assert!(doc.class_list(ids[0]).contains(&"last"));
  }

  #[test]
  fn test_case_insensitive_tag() {
    // Tags are stored lowercase, but the selector should be case-insensitive
    let doc = HtmlDocument::parse("<DIV><P>hello</P></DIV>");
    let ids = doc.select("div");
    assert_eq!(ids.len(), 1);
    let ids2 = doc.select("DIV");
    assert_eq!(ids2.len(), 1);
  }

  #[test]
  fn test_deeply_nested_descendant() {
    let doc = HtmlDocument::parse("<div><section><article><p>deep</p></article></section></div>");
    let ids = doc.select("div p");
    assert_eq!(ids.len(), 1);
    assert_eq!(doc.text_content(ids[0]), "deep");
  }

  #[test]
  fn test_child_does_not_match_grandchild() {
    let doc = HtmlDocument::parse("<div><section><p>deep</p></section></div>");
    let ids = doc.select("div > p");
    assert_eq!(ids.len(), 0); // p is grandchild, not child
  }

  #[test]
  fn test_compound_with_attribute() {
    let doc = test_doc();
    let ids = doc.select(r#"input.input[type="text"]"#);
    assert_eq!(ids.len(), 1);
  }

  #[test]
  fn test_invalid_selector_returns_empty() {
    let doc = test_doc();
    let ids = doc.select("!!!invalid!!!");
    assert!(ids.is_empty());
  }
}
