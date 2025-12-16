/// CSS Selector Engine
///
/// A Cheerio-compatible CSS selector parser and matcher.
/// Supports common CSS selectors for HTML element querying.
///
/// Supported selectors:
/// - Tag: `div`, `a`, `span`
/// - Class: `.class-name`
/// - ID: `#element-id`
/// - Universal: `*`
/// - Attribute: `[href]`, `[href="value"]`, `[href^="prefix"]`, etc.
/// - Descendant: `div span`
/// - Child: `div > span`
/// - Adjacent sibling: `div + span`
/// - General sibling: `div ~ span`
/// - Compound: `div.class#id[attr]`
/// - Multiple: `div, span`
/// - Pseudo-classes: `:first-child`, `:last-child`, `:nth-child(n)`, `:not()`
use crate::modules::web::dom::{Document, Element, Selection};
use std::fmt;

/// A parsed CSS selector
#[derive(Debug, Clone)]
pub struct Selector {
    pub groups: Vec<SelectorGroup>,
}

/// A selector group (comma-separated selectors)
#[derive(Debug, Clone)]
pub struct SelectorGroup {
    pub parts: Vec<SelectorPart>,
}

/// A single part of a selector (with combinator)
#[derive(Debug, Clone)]
pub struct SelectorPart {
    pub combinator: Combinator,
    pub simple: SimpleSelector,
}

/// Combinator between selector parts
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Combinator {
    /// No combinator (first element)
    None,
    /// Descendant (space)
    Descendant,
    /// Child (>)
    Child,
    /// Adjacent sibling (+)
    AdjacentSibling,
    /// General sibling (~)
    GeneralSibling,
}

/// A simple selector (tag, class, id, attribute, pseudo)
#[derive(Debug, Clone, Default)]
pub struct SimpleSelector {
    pub tag: Option<String>,
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub attributes: Vec<AttributeSelector>,
    pub pseudo_classes: Vec<PseudoClass>,
    pub is_universal: bool,
}

/// Attribute selector with operator
#[derive(Debug, Clone)]
pub struct AttributeSelector {
    pub name: String,
    pub op: AttributeOp,
    pub value: Option<String>,
    pub case_insensitive: bool,
}

/// Attribute comparison operator
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttributeOp {
    /// [attr] - Has attribute
    Exists,
    /// [attr=value] - Exact match
    Equals,
    /// [attr~=value] - Space-separated word
    Contains,
    /// [attr|=value] - Starts with value or value-
    DashMatch,
    /// [attr^=value] - Starts with
    StartsWith,
    /// [attr$=value] - Ends with
    EndsWith,
    /// [attr*=value] - Contains substring
    Substring,
}

/// Pseudo-class selector
#[derive(Debug, Clone)]
pub enum PseudoClass {
    FirstChild,
    LastChild,
    OnlyChild,
    FirstOfType,
    LastOfType,
    OnlyOfType,
    NthChild(NthExpr),
    NthLastChild(NthExpr),
    NthOfType(NthExpr),
    NthLastOfType(NthExpr),
    Empty,
    Not(Box<SimpleSelector>),
    // Root is handled specially
    Root,
}

/// Expression for :nth-child() and similar
#[derive(Debug, Clone)]
pub enum NthExpr {
    /// Specific index (1-based)
    Index(i32),
    /// Even elements
    Even,
    /// Odd elements
    Odd,
    /// An+B formula
    Formula { a: i32, b: i32 },
}

// ============================================================================
// Parser
// ============================================================================

/// Parse a CSS selector string
pub fn parse(selector: &str) -> Result<Selector, String> {
    let mut parser = SelectorParser::new(selector);
    parser.parse()
}

struct SelectorParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> SelectorParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse(&mut self) -> Result<Selector, String> {
        let mut groups = Vec::new();

        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                break;
            }

            let group = self.parse_group()?;
            groups.push(group);

            self.skip_whitespace();
            if self.peek() == Some(',') {
                self.advance();
            } else {
                break;
            }
        }

        if groups.is_empty() {
            return Err("Empty selector".to_string());
        }

        Ok(Selector { groups })
    }

    fn parse_group(&mut self) -> Result<SelectorGroup, String> {
        let mut parts = Vec::new();

        // Parse first simple selector (no combinator)
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.peek() == Some(',') {
            return Err("Empty selector group".to_string());
        }

        let first = self.parse_simple_selector()?;
        parts.push(SelectorPart {
            combinator: Combinator::None,
            simple: first,
        });

        // Parse remaining selectors with combinators
        loop {
            // Check for whitespace (potential descendant combinator)
            let had_whitespace = {
                let pos_before = self.pos;
                self.skip_whitespace();
                self.pos > pos_before
            };

            if self.pos >= self.input.len() {
                break;
            }

            let c = self.peek();
            if c == Some(',') || c.is_none() {
                break;
            }

            // Determine combinator
            let combinator = match c {
                Some('>') => {
                    self.advance();
                    self.skip_whitespace();
                    Combinator::Child
                }
                Some('+') => {
                    self.advance();
                    self.skip_whitespace();
                    Combinator::AdjacentSibling
                }
                Some('~') => {
                    self.advance();
                    self.skip_whitespace();
                    Combinator::GeneralSibling
                }
                _ if had_whitespace => Combinator::Descendant,
                _ => break, // No combinator, part of same simple selector
            };

            // Parse next simple selector
            let simple = self.parse_simple_selector()?;
            parts.push(SelectorPart { combinator, simple });
        }

        Ok(SelectorGroup { parts })
    }

    fn parse_simple_selector(&mut self) -> Result<SimpleSelector, String> {
        let mut selector = SimpleSelector::default();

        loop {
            match self.peek() {
                Some('*') => {
                    self.advance();
                    selector.is_universal = true;
                }
                Some('.') => {
                    self.advance();
                    let class = self.parse_identifier()?;
                    selector.classes.push(class);
                }
                Some('#') => {
                    self.advance();
                    selector.id = Some(self.parse_identifier()?);
                }
                Some('[') => {
                    let attr = self.parse_attribute()?;
                    selector.attributes.push(attr);
                }
                Some(':') => {
                    let pseudo = self.parse_pseudo_class()?;
                    selector.pseudo_classes.push(pseudo);
                }
                Some(c) if c.is_alphabetic() || c == '-' || c == '_' => {
                    if selector.tag.is_none() {
                        selector.tag = Some(self.parse_identifier()?);
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        // Validate: must have at least one selector component
        if !selector.is_universal
            && selector.tag.is_none()
            && selector.id.is_none()
            && selector.classes.is_empty()
            && selector.attributes.is_empty()
            && selector.pseudo_classes.is_empty()
        {
            return Err("Invalid selector: no components".to_string());
        }

        Ok(selector)
    }

    fn parse_identifier(&mut self) -> Result<String, String> {
        let start = self.pos;

        while self.pos < self.input.len() {
            let c = self.peek().unwrap();
            if c.is_alphanumeric() || c == '-' || c == '_' {
                self.advance();
            } else {
                break;
            }
        }

        if self.pos == start {
            return Err("Expected identifier".to_string());
        }

        Ok(self.input[start..self.pos].to_string())
    }

    fn parse_attribute(&mut self) -> Result<AttributeSelector, String> {
        self.advance(); // Skip '['

        self.skip_whitespace();
        let name = self.parse_identifier()?;
        self.skip_whitespace();

        let c = self.peek();
        if c == Some(']') {
            self.advance();
            return Ok(AttributeSelector {
                name,
                op: AttributeOp::Exists,
                value: None,
                case_insensitive: false,
            });
        }

        // Parse operator
        let op = match c {
            Some('=') => {
                self.advance();
                AttributeOp::Equals
            }
            Some('~') => {
                self.advance();
                self.expect('=')?;
                AttributeOp::Contains
            }
            Some('|') => {
                self.advance();
                self.expect('=')?;
                AttributeOp::DashMatch
            }
            Some('^') => {
                self.advance();
                self.expect('=')?;
                AttributeOp::StartsWith
            }
            Some('$') => {
                self.advance();
                self.expect('=')?;
                AttributeOp::EndsWith
            }
            Some('*') => {
                self.advance();
                self.expect('=')?;
                AttributeOp::Substring
            }
            _ => return Err(format!("Invalid attribute operator: {:?}", c)),
        };

        self.skip_whitespace();
        let value = self.parse_string_or_identifier()?;

        self.skip_whitespace();

        // Check for case-insensitivity flag
        let case_insensitive = if self.peek() == Some('i') || self.peek() == Some('I') {
            self.advance();
            self.skip_whitespace();
            true
        } else {
            false
        };

        self.expect(']')?;

        Ok(AttributeSelector {
            name,
            op,
            value: Some(value),
            case_insensitive,
        })
    }

    fn parse_string_or_identifier(&mut self) -> Result<String, String> {
        match self.peek() {
            Some('"') | Some('\'') => self.parse_string(),
            _ => self.parse_identifier(),
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        let quote = self.peek().ok_or("Expected quote")?;
        self.advance();

        let start = self.pos;
        while self.pos < self.input.len() && self.peek() != Some(quote) {
            // Handle escape sequences
            if self.peek() == Some('\\') {
                self.advance();
            }
            self.advance();
        }

        let value = self.input[start..self.pos].to_string();
        self.expect(quote)?;

        Ok(value)
    }

    fn parse_pseudo_class(&mut self) -> Result<PseudoClass, String> {
        self.advance(); // Skip ':'

        // Handle double-colon for pseudo-elements (treat as single colon)
        if self.peek() == Some(':') {
            self.advance();
        }

        let name = self.parse_identifier()?.to_lowercase();

        match name.as_str() {
            "first-child" => Ok(PseudoClass::FirstChild),
            "last-child" => Ok(PseudoClass::LastChild),
            "only-child" => Ok(PseudoClass::OnlyChild),
            "first-of-type" => Ok(PseudoClass::FirstOfType),
            "last-of-type" => Ok(PseudoClass::LastOfType),
            "only-of-type" => Ok(PseudoClass::OnlyOfType),
            "empty" => Ok(PseudoClass::Empty),
            "root" => Ok(PseudoClass::Root),
            "nth-child" => {
                let expr = self.parse_nth_expression()?;
                Ok(PseudoClass::NthChild(expr))
            }
            "nth-last-child" => {
                let expr = self.parse_nth_expression()?;
                Ok(PseudoClass::NthLastChild(expr))
            }
            "nth-of-type" => {
                let expr = self.parse_nth_expression()?;
                Ok(PseudoClass::NthOfType(expr))
            }
            "nth-last-of-type" => {
                let expr = self.parse_nth_expression()?;
                Ok(PseudoClass::NthLastOfType(expr))
            }
            "not" => {
                self.expect('(')?;
                self.skip_whitespace();
                let inner = self.parse_simple_selector()?;
                self.skip_whitespace();
                self.expect(')')?;
                Ok(PseudoClass::Not(Box::new(inner)))
            }
            _ => Err(format!("Unknown pseudo-class: {}", name)),
        }
    }

    fn parse_nth_expression(&mut self) -> Result<NthExpr, String> {
        self.expect('(')?;
        self.skip_whitespace();

        let start = self.pos;
        while self.pos < self.input.len() && self.peek() != Some(')') {
            self.advance();
        }
        let expr = self.input[start..self.pos].trim().to_lowercase();
        self.expect(')')?;

        match expr.as_str() {
            "even" => Ok(NthExpr::Even),
            "odd" => Ok(NthExpr::Odd),
            _ => {
                // Try to parse as number
                if let Ok(n) = expr.parse::<i32>() {
                    return Ok(NthExpr::Index(n));
                }

                // Try to parse as An+B formula
                parse_an_plus_b(&expr)
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.peek() {
            self.pos += c.len_utf8();
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        if self.peek() == Some(expected) {
            self.advance();
            Ok(())
        } else {
            Err(format!(
                "Expected '{}' at position {}, got {:?}",
                expected,
                self.pos,
                self.peek()
            ))
        }
    }
}

fn parse_an_plus_b(s: &str) -> Result<NthExpr, String> {
    let s = s.replace(" ", "");

    // Handle cases like "n", "-n", "+n"
    if s == "n" {
        return Ok(NthExpr::Formula { a: 1, b: 0 });
    }
    if s == "-n" {
        return Ok(NthExpr::Formula { a: -1, b: 0 });
    }
    if s == "+n" {
        return Ok(NthExpr::Formula { a: 1, b: 0 });
    }

    // Find 'n'
    if let Some(n_pos) = s.find('n') {
        let a_part = &s[..n_pos];
        let b_part = &s[n_pos + 1..];

        let a = match a_part {
            "" | "+" => 1,
            "-" => -1,
            _ => a_part
                .parse()
                .map_err(|_| format!("Invalid A in An+B: {}", s))?,
        };

        let b = if b_part.is_empty() {
            0
        } else {
            b_part
                .parse()
                .map_err(|_| format!("Invalid B in An+B: {}", s))?
        };

        Ok(NthExpr::Formula { a, b })
    } else {
        // Just a number
        let n: i32 = s
            .parse()
            .map_err(|_| format!("Invalid nth expression: {}", s))?;
        Ok(NthExpr::Index(n))
    }
}

// ============================================================================
// Matcher
// ============================================================================

impl Selector {
    /// Match elements in a document
    pub fn match_in<'a>(&self, doc: &'a Document) -> Selection<'a> {
        let mut results: Vec<&'a Element> = Vec::new();

        for group in &self.groups {
            let group_results = self.match_group(group, doc);
            for elem in group_results {
                if !results.iter().any(|e| e.self_index == elem.self_index) {
                    results.push(elem);
                }
            }
        }

        Selection::new(results)
    }

    fn match_group<'a>(&self, group: &SelectorGroup, doc: &'a Document) -> Vec<&'a Element> {
        if group.parts.is_empty() {
            return Vec::new();
        }

        // Start with all elements matching the first part
        let first = &group.parts[0];
        let mut candidates: Vec<&Element> = doc
            .all_elements()
            .filter(|e| first.simple.matches(e, doc, None))
            .collect();

        // Apply combinators for remaining parts
        for part in group.parts.iter().skip(1) {
            candidates = self.apply_combinator(&candidates, &part.combinator, &part.simple, doc);
        }

        candidates
    }

    fn apply_combinator<'a>(
        &self,
        parents: &[&'a Element],
        combinator: &Combinator,
        selector: &SimpleSelector,
        doc: &'a Document,
    ) -> Vec<&'a Element> {
        let mut results = Vec::new();

        match combinator {
            Combinator::None => {
                // This shouldn't happen for non-first parts
                results.extend(parents.iter().cloned());
            }
            Combinator::Descendant => {
                // Match any descendant
                for parent in parents {
                    self.find_descendants(parent, selector, doc, &mut results);
                }
            }
            Combinator::Child => {
                // Match direct children only
                for parent in parents {
                    for child in &parent.children {
                        if let crate::modules::web::dom::Node::ElementRef(idx) = child {
                            if let Some(doc_elem) = doc.get_element(*idx) {
                                if selector.matches(doc_elem, doc, Some(parent.self_index)) {
                                    results.push(doc_elem);
                                }
                            }
                        }
                    }
                }
            }
            Combinator::AdjacentSibling => {
                // Match immediately following sibling
                for parent in parents {
                    if let Some(parent_idx) = parent.parent_index {
                        if let Some(parent_elem) = doc.get_element(parent_idx) {
                            let mut found_parent = false;
                            for child in &parent_elem.children {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = child {
                                    if found_parent {
                                        if let Some(doc_elem) = doc.get_element(*idx) {
                                            if selector.matches(doc_elem, doc, Some(parent_idx)) {
                                                results.push(doc_elem);
                                            }
                                        }
                                        break;
                                    }
                                    if *idx == parent.self_index {
                                        found_parent = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Combinator::GeneralSibling => {
                // Match any following sibling
                for parent in parents {
                    if let Some(parent_idx) = parent.parent_index {
                        if let Some(parent_elem) = doc.get_element(parent_idx) {
                            let mut found_parent = false;
                            for child in &parent_elem.children {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = child {
                                    if found_parent {
                                        if let Some(doc_elem) = doc.get_element(*idx) {
                                            if selector.matches(doc_elem, doc, Some(parent_idx)) {
                                                results.push(doc_elem);
                                            }
                                        }
                                    }
                                    if *idx == parent.self_index {
                                        found_parent = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }

    fn find_descendants<'a>(
        &self,
        parent: &Element,
        selector: &SimpleSelector,
        doc: &'a Document,
        results: &mut Vec<&'a Element>,
    ) {
        for child in &parent.children {
            if let crate::modules::web::dom::Node::ElementRef(idx) = child {
                if let Some(doc_elem) = doc.get_element(*idx) {
                    if selector.matches(doc_elem, doc, parent.parent_index)
                        && !results.iter().any(|e| e.self_index == doc_elem.self_index)
                    {
                        results.push(doc_elem);
                    }
                    // Recurse into children
                    self.find_descendants(doc_elem, selector, doc, results);
                }
            }
        }
    }
}

impl SimpleSelector {
    /// Check if this selector matches an element
    pub fn matches(&self, elem: &Element, doc: &Document, parent_idx: Option<usize>) -> bool {
        // Universal selector matches everything (unless other conditions fail)
        if !self.is_universal {
            // Check tag
            if let Some(ref tag) = self.tag {
                if elem.tag != tag.to_lowercase() {
                    return false;
                }
            }
        }

        // Check ID
        if let Some(ref id) = self.id {
            match elem.attr("id") {
                Some(elem_id) if elem_id == id => {}
                _ => return false,
            }
        }

        // Check classes
        for class in &self.classes {
            if !elem.has_class(class) {
                return false;
            }
        }

        // Check attributes
        for attr in &self.attributes {
            if !attr.matches(elem) {
                return false;
            }
        }

        // Check pseudo-classes
        for pseudo in &self.pseudo_classes {
            if !pseudo.matches(elem, doc, parent_idx) {
                return false;
            }
        }

        true
    }
}

impl AttributeSelector {
    fn matches(&self, elem: &Element) -> bool {
        let attr_value = elem.attr(&self.name);

        match self.op {
            AttributeOp::Exists => attr_value.is_some(),
            AttributeOp::Equals => {
                if let (Some(attr), Some(ref value)) = (attr_value, &self.value) {
                    if self.case_insensitive {
                        attr.eq_ignore_ascii_case(value)
                    } else {
                        attr == value
                    }
                } else {
                    false
                }
            }
            AttributeOp::Contains => {
                if let (Some(attr), Some(ref value)) = (attr_value, &self.value) {
                    let check = |s: &str, v: &str| {
                        if self.case_insensitive {
                            s.split_whitespace().any(|w| w.eq_ignore_ascii_case(v))
                        } else {
                            s.split_whitespace().any(|w| w == v)
                        }
                    };
                    check(attr, value)
                } else {
                    false
                }
            }
            AttributeOp::DashMatch => {
                if let (Some(attr), Some(ref value)) = (attr_value, &self.value) {
                    if self.case_insensitive {
                        attr.eq_ignore_ascii_case(value)
                            || attr
                                .to_lowercase()
                                .starts_with(&format!("{}-", value.to_lowercase()))
                    } else {
                        attr == value || attr.starts_with(&format!("{}-", value))
                    }
                } else {
                    false
                }
            }
            AttributeOp::StartsWith => {
                if let (Some(attr), Some(ref value)) = (attr_value, &self.value) {
                    if self.case_insensitive {
                        attr.to_lowercase().starts_with(&value.to_lowercase())
                    } else {
                        attr.starts_with(value.as_str())
                    }
                } else {
                    false
                }
            }
            AttributeOp::EndsWith => {
                if let (Some(attr), Some(ref value)) = (attr_value, &self.value) {
                    if self.case_insensitive {
                        attr.to_lowercase().ends_with(&value.to_lowercase())
                    } else {
                        attr.ends_with(value.as_str())
                    }
                } else {
                    false
                }
            }
            AttributeOp::Substring => {
                if let (Some(attr), Some(ref value)) = (attr_value, &self.value) {
                    if self.case_insensitive {
                        attr.to_lowercase().contains(&value.to_lowercase())
                    } else {
                        attr.contains(value.as_str())
                    }
                } else {
                    false
                }
            }
        }
    }
}

impl PseudoClass {
    fn matches(&self, elem: &Element, doc: &Document, _parent_idx: Option<usize>) -> bool {
        match self {
            PseudoClass::FirstChild => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        return parent.children.iter().find_map(|c| {
                            if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                Some(*idx)
                            } else {
                                None
                            }
                        }) == Some(elem.self_index);
                    }
                }
                false
            }
            PseudoClass::LastChild => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        return parent.children.iter().rev().find_map(|c| {
                            if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                Some(*idx)
                            } else {
                                None
                            }
                        }) == Some(elem.self_index);
                    }
                }
                false
            }
            PseudoClass::OnlyChild => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        let element_children: Vec<_> = parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    Some(*idx)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        return element_children.len() == 1
                            && element_children[0] == elem.self_index;
                    }
                }
                false
            }
            PseudoClass::FirstOfType => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        return parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    doc.get_element(*idx).and_then(|e| {
                                        if e.tag == elem.tag {
                                            Some(e.self_index)
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            })
                            .next()
                            == Some(elem.self_index);
                    }
                }
                false
            }
            PseudoClass::LastOfType => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        return parent
                            .children
                            .iter()
                            .rev()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    doc.get_element(*idx).and_then(|e| {
                                        if e.tag == elem.tag {
                                            Some(e.self_index)
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            })
                            .next()
                            == Some(elem.self_index);
                    }
                }
                false
            }
            PseudoClass::OnlyOfType => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        let same_type: Vec<_> = parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    doc.get_element(*idx).and_then(|e| {
                                        if e.tag == elem.tag {
                                            Some(e.self_index)
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect();
                        return same_type.len() == 1 && same_type[0] == elem.self_index;
                    }
                }
                false
            }
            PseudoClass::NthChild(expr) => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        let position = parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    Some(*idx)
                                } else {
                                    None
                                }
                            })
                            .position(|idx| idx == elem.self_index);

                        if let Some(pos) = position {
                            return expr.matches(pos as i32 + 1); // 1-indexed
                        }
                    }
                }
                false
            }
            PseudoClass::NthLastChild(expr) => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        let children: Vec<_> = parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    Some(*idx)
                                } else {
                                    None
                                }
                            })
                            .collect();

                        if let Some(pos) = children.iter().position(|&idx| idx == elem.self_index) {
                            let from_end = children.len() - pos;
                            return expr.matches(from_end as i32);
                        }
                    }
                }
                false
            }
            PseudoClass::NthOfType(expr) => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        let position = parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    doc.get_element(*idx).and_then(|e| {
                                        if e.tag == elem.tag {
                                            Some(e.self_index)
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            })
                            .position(|idx| idx == elem.self_index);

                        if let Some(pos) = position {
                            return expr.matches(pos as i32 + 1);
                        }
                    }
                }
                false
            }
            PseudoClass::NthLastOfType(expr) => {
                if let Some(parent_idx) = elem.parent_index {
                    if let Some(parent) = doc.get_element(parent_idx) {
                        let same_type: Vec<_> = parent
                            .children
                            .iter()
                            .filter_map(|c| {
                                if let crate::modules::web::dom::Node::ElementRef(idx) = c {
                                    doc.get_element(*idx).and_then(|e| {
                                        if e.tag == elem.tag {
                                            Some(e.self_index)
                                        } else {
                                            None
                                        }
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect();

                        if let Some(pos) = same_type.iter().position(|&idx| idx == elem.self_index)
                        {
                            let from_end = same_type.len() - pos;
                            return expr.matches(from_end as i32);
                        }
                    }
                }
                false
            }
            PseudoClass::Empty => elem.children.iter().all(|c| match c {
                crate::modules::web::dom::Node::Text(t) => t.trim().is_empty(),
                crate::modules::web::dom::Node::Comment(_) => true,
                crate::modules::web::dom::Node::ElementRef(_) => false,
            }),
            PseudoClass::Not(inner) => !inner.matches(elem, doc, None),
            PseudoClass::Root => elem.parent_index.is_none(),
        }
    }
}

impl NthExpr {
    fn matches(&self, position: i32) -> bool {
        match self {
            NthExpr::Index(n) => position == *n,
            NthExpr::Even => position % 2 == 0,
            NthExpr::Odd => position % 2 == 1,
            NthExpr::Formula { a, b } => {
                if *a == 0 {
                    position == *b
                } else {
                    let n = position - b;
                    n % a == 0 && n / a >= 0
                }
            }
        }
    }
}

// ============================================================================
// Document extension methods
// ============================================================================

impl Document {
    /// Select elements using a CSS selector
    pub fn select(&self, selector: &str) -> Selection<'_> {
        match parse(selector) {
            Ok(sel) => sel.match_in(self),
            Err(_) => Selection::empty(),
        }
    }

    /// Select first element matching selector
    /// Note: Use select().first() for a direct reference
    pub fn select_first(&self, selector: &str) -> Option<usize> {
        match parse(selector) {
            Ok(sel) => sel.match_in(self).first().map(|e| e.self_index),
            Err(_) => None,
        }
    }

    /// Select all elements matching selector (returns indices)
    /// Note: Use select().iter() for direct element references
    pub fn select_all_indices(&self, selector: &str) -> Vec<usize> {
        match parse(selector) {
            Ok(sel) => sel.match_in(self).iter().map(|e| e.self_index).collect(),
            Err(_) => Vec::new(),
        }
    }
}

// ============================================================================
// Display implementations
// ============================================================================

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let groups: Vec<String> = self.groups.iter().map(|g| format!("{}", g)).collect();
        write!(f, "{}", groups.join(", "))
    }
}

impl fmt::Display for SelectorGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.parts.iter().map(|p| format!("{}", p)).collect();
        write!(f, "{}", parts.join(""))
    }
}

impl fmt::Display for SelectorPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let comb = match self.combinator {
            Combinator::None => "",
            Combinator::Descendant => " ",
            Combinator::Child => " > ",
            Combinator::AdjacentSibling => " + ",
            Combinator::GeneralSibling => " ~ ",
        };
        write!(f, "{}{}", comb, self.simple)
    }
}

impl fmt::Display for SimpleSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_universal {
            write!(f, "*")?;
        }
        if let Some(ref tag) = self.tag {
            write!(f, "{}", tag)?;
        }
        if let Some(ref id) = self.id {
            write!(f, "#{}", id)?;
        }
        for class in &self.classes {
            write!(f, ".{}", class)?;
        }
        for attr in &self.attributes {
            write!(f, "{}", attr)?;
        }
        for pseudo in &self.pseudo_classes {
            write!(f, ":{}", pseudo)?;
        }
        Ok(())
    }
}

impl fmt::Display for AttributeSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}", self.name)?;
        match self.op {
            AttributeOp::Exists => {}
            AttributeOp::Equals => {
                write!(f, "=\"{}\"", self.value.as_ref().unwrap_or(&String::new()))?
            }
            AttributeOp::Contains => {
                write!(f, "~=\"{}\"", self.value.as_ref().unwrap_or(&String::new()))?
            }
            AttributeOp::DashMatch => {
                write!(f, "|=\"{}\"", self.value.as_ref().unwrap_or(&String::new()))?
            }
            AttributeOp::StartsWith => {
                write!(f, "^=\"{}\"", self.value.as_ref().unwrap_or(&String::new()))?
            }
            AttributeOp::EndsWith => {
                write!(f, "$=\"{}\"", self.value.as_ref().unwrap_or(&String::new()))?
            }
            AttributeOp::Substring => {
                write!(f, "*=\"{}\"", self.value.as_ref().unwrap_or(&String::new()))?
            }
        }
        if self.case_insensitive {
            write!(f, " i")?;
        }
        write!(f, "]")
    }
}

impl fmt::Display for PseudoClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PseudoClass::FirstChild => write!(f, "first-child"),
            PseudoClass::LastChild => write!(f, "last-child"),
            PseudoClass::OnlyChild => write!(f, "only-child"),
            PseudoClass::FirstOfType => write!(f, "first-of-type"),
            PseudoClass::LastOfType => write!(f, "last-of-type"),
            PseudoClass::OnlyOfType => write!(f, "only-of-type"),
            PseudoClass::Empty => write!(f, "empty"),
            PseudoClass::Root => write!(f, "root"),
            PseudoClass::NthChild(expr) => write!(f, "nth-child({})", expr),
            PseudoClass::NthLastChild(expr) => write!(f, "nth-last-child({})", expr),
            PseudoClass::NthOfType(expr) => write!(f, "nth-of-type({})", expr),
            PseudoClass::NthLastOfType(expr) => write!(f, "nth-last-of-type({})", expr),
            PseudoClass::Not(inner) => write!(f, "not({})", inner),
        }
    }
}

impl fmt::Display for NthExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NthExpr::Index(n) => write!(f, "{}", n),
            NthExpr::Even => write!(f, "even"),
            NthExpr::Odd => write!(f, "odd"),
            NthExpr::Formula { a, b } => {
                if *a == 0 {
                    write!(f, "{}", b)
                } else if *b == 0 {
                    write!(f, "{}n", a)
                } else if *b > 0 {
                    write!(f, "{}n+{}", a, b)
                } else {
                    write!(f, "{}n{}", a, b)
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tag() {
        let sel = parse("div").unwrap();
        assert_eq!(sel.groups.len(), 1);
        assert_eq!(sel.groups[0].parts.len(), 1);
        assert_eq!(sel.groups[0].parts[0].simple.tag, Some("div".to_string()));
    }

    #[test]
    fn test_parse_class() {
        let sel = parse(".my-class").unwrap();
        assert_eq!(sel.groups[0].parts[0].simple.classes, vec!["my-class"]);
    }

    #[test]
    fn test_parse_id() {
        let sel = parse("#main-content").unwrap();
        assert_eq!(
            sel.groups[0].parts[0].simple.id,
            Some("main-content".to_string())
        );
    }

    #[test]
    fn test_parse_compound() {
        let sel = parse("div.container#main").unwrap();
        let simple = &sel.groups[0].parts[0].simple;
        assert_eq!(simple.tag, Some("div".to_string()));
        assert_eq!(simple.classes, vec!["container"]);
        assert_eq!(simple.id, Some("main".to_string()));
    }

    #[test]
    fn test_parse_attribute_exists() {
        let sel = parse("[data-id]").unwrap();
        assert_eq!(sel.groups[0].parts[0].simple.attributes.len(), 1);
        assert_eq!(
            sel.groups[0].parts[0].simple.attributes[0].op,
            AttributeOp::Exists
        );
    }

    #[test]
    fn test_parse_attribute_equals() {
        let sel = parse("[href=\"https://example.com\"]").unwrap();
        let attr = &sel.groups[0].parts[0].simple.attributes[0];
        assert_eq!(attr.op, AttributeOp::Equals);
        assert_eq!(attr.value, Some("https://example.com".to_string()));
    }

    #[test]
    fn test_parse_attribute_starts_with() {
        let sel = parse("[href^=\"https\"]").unwrap();
        assert_eq!(
            sel.groups[0].parts[0].simple.attributes[0].op,
            AttributeOp::StartsWith
        );
    }

    #[test]
    fn test_parse_descendant() {
        let sel = parse("div span").unwrap();
        assert_eq!(sel.groups[0].parts.len(), 2);
        assert_eq!(sel.groups[0].parts[1].combinator, Combinator::Descendant);
    }

    #[test]
    fn test_parse_child() {
        let sel = parse("div > span").unwrap();
        assert_eq!(sel.groups[0].parts[1].combinator, Combinator::Child);
    }

    #[test]
    fn test_parse_adjacent_sibling() {
        let sel = parse("div + span").unwrap();
        assert_eq!(
            sel.groups[0].parts[1].combinator,
            Combinator::AdjacentSibling
        );
    }

    #[test]
    fn test_parse_general_sibling() {
        let sel = parse("div ~ span").unwrap();
        assert_eq!(
            sel.groups[0].parts[1].combinator,
            Combinator::GeneralSibling
        );
    }

    #[test]
    fn test_parse_multiple() {
        let sel = parse("div, span, p").unwrap();
        assert_eq!(sel.groups.len(), 3);
    }

    #[test]
    fn test_parse_pseudo_first_child() {
        let sel = parse("li:first-child").unwrap();
        assert_eq!(sel.groups[0].parts[0].simple.pseudo_classes.len(), 1);
        matches!(
            &sel.groups[0].parts[0].simple.pseudo_classes[0],
            PseudoClass::FirstChild
        );
    }

    #[test]
    fn test_parse_nth_child() {
        let sel = parse("li:nth-child(2n+1)").unwrap();
        if let PseudoClass::NthChild(expr) = &sel.groups[0].parts[0].simple.pseudo_classes[0] {
            assert!(matches!(expr, NthExpr::Formula { a: 2, b: 1 }));
        } else {
            panic!("Expected NthChild");
        }
    }

    #[test]
    fn test_parse_not() {
        let sel = parse("div:not(.hidden)").unwrap();
        if let PseudoClass::Not(inner) = &sel.groups[0].parts[0].simple.pseudo_classes[0] {
            assert_eq!(inner.classes, vec!["hidden"]);
        } else {
            panic!("Expected Not");
        }
    }

    #[test]
    fn test_match_tag() {
        let html = "<div><span>Hello</span><p>World</p></div>";
        let doc = Document::parse(html);

        let selection = doc.select("span");
        assert_eq!(selection.len(), 1);
        assert_eq!(selection.first().unwrap().text(), "Hello");
    }

    #[test]
    fn test_match_class() {
        let html = r#"<div class="item active">One</div><div class="item">Two</div>"#;
        let doc = Document::parse(html);

        let items = doc.select(".item");
        assert_eq!(items.len(), 2);

        let active = doc.select(".active");
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_match_id() {
        let html = r#"<div id="header">Header</div><div id="content">Content</div>"#;
        let doc = Document::parse(html);

        let header = doc.select("#header");
        assert_eq!(header.len(), 1);
        assert_eq!(header.first().unwrap().text(), "Header");
    }

    #[test]
    fn test_match_compound() {
        let html = r#"<div class="box" id="main">Main Box</div><div class="box">Other Box</div>"#;
        let doc = Document::parse(html);

        let main = doc.select("div.box#main");
        assert_eq!(main.len(), 1);
        assert_eq!(main.first().unwrap().text(), "Main Box");
    }

    #[test]
    fn test_match_descendant() {
        let html = r#"<div class="container"><p><span>Nested</span></p></div><span>Outside</span>"#;
        let doc = Document::parse(html);

        let nested = doc.select(".container span");
        assert_eq!(nested.len(), 1);
        assert_eq!(nested.first().unwrap().text(), "Nested");
    }

    #[test]
    fn test_match_multiple() {
        let html = r#"<div>Div</div><span>Span</span><p>Para</p>"#;
        let doc = Document::parse(html);

        let selection = doc.select("div, span");
        assert_eq!(selection.len(), 2);
    }

    #[test]
    fn test_match_attribute() {
        let html =
            r#"<a href="https://example.com">Link 1</a><a href="http://test.com">Link 2</a>"#;
        let doc = Document::parse(html);

        let https_links = doc.select("[href^=\"https\"]");
        assert_eq!(https_links.len(), 1);
    }

    #[test]
    fn test_nth_child() {
        let html = r#"<ul><li>1</li><li>2</li><li>3</li><li>4</li></ul>"#;
        let doc = Document::parse(html);

        let even = doc.select("li:nth-child(even)");
        assert_eq!(even.len(), 2);

        let odd = doc.select("li:nth-child(odd)");
        assert_eq!(odd.len(), 2);
    }

    #[test]
    fn test_first_last_child() {
        let html = r#"<ul><li>First</li><li>Middle</li><li>Last</li></ul>"#;
        let doc = Document::parse(html);

        let first = doc.select("li:first-child");
        assert_eq!(first.len(), 1);
        assert_eq!(first.first().unwrap().text(), "First");

        let last = doc.select("li:last-child");
        assert_eq!(last.len(), 1);
        assert_eq!(last.first().unwrap().text(), "Last");
    }

    #[test]
    fn test_not() {
        let html = r#"<div class="show">Visible</div><div class="hide">Hidden</div>"#;
        let doc = Document::parse(html);

        let visible = doc.select("div:not(.hide)");
        assert_eq!(visible.len(), 1);
        assert_eq!(visible.first().unwrap().text(), "Visible");
    }

    #[test]
    fn test_empty() {
        let html = r#"<div class="empty"></div><div class="full">Content</div>"#;
        let doc = Document::parse(html);

        let empty = doc.select("div:empty");
        assert_eq!(empty.len(), 1);
        assert!(empty.first().unwrap().has_class("empty"));
    }

    #[test]
    fn test_complex_selector() {
        let html = r#"
            <div class="container">
                <ul class="list">
                    <li class="item active">Active</li>
                    <li class="item">Normal</li>
                    <li class="item disabled">Disabled</li>
                </ul>
            </div>
        "#;
        let doc = Document::parse(html);

        let active_items = doc.select(".container .list .item.active");
        assert_eq!(active_items.len(), 1);

        let non_disabled = doc.select(".item:not(.disabled)");
        assert_eq!(non_disabled.len(), 2);
    }
}
