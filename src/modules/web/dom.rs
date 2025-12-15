/// DOM Parser - HTML to DOM tree
///
/// Provides a fast, zero-dependency HTML parser that builds
/// a DOM tree for querying and manipulation.
///
/// Features:
/// - Handles malformed HTML gracefully
/// - Self-closing tag support
/// - Attribute parsing with quotes handling
/// - Text and comment node support
/// - Base URL resolution for relative links
use std::collections::HashMap;
use std::fmt;

/// A DOM Node - either Element reference, Text, or Comment
#[derive(Debug, Clone)]
pub enum Node {
    /// Reference to element by index in the document's elements array
    ElementRef(usize),
    Text(String),
    Comment(String),
}

/// An HTML Element with tag, attributes, and children
#[derive(Debug, Clone)]
pub struct Element {
    pub tag: String,
    pub attributes: HashMap<String, String>,
    pub children: Vec<Node>,
    pub parent_index: Option<usize>,
    pub self_index: usize,
}

impl Element {
    pub fn new(tag: &str, self_index: usize) -> Self {
        Self {
            tag: tag.to_lowercase(),
            attributes: HashMap::new(),
            children: Vec::new(),
            parent_index: None,
            self_index,
        }
    }

    /// Get an attribute value
    pub fn attr(&self, name: &str) -> Option<&String> {
        self.attributes.get(&name.to_lowercase())
    }

    /// Check if element has an attribute
    pub fn has_attr(&self, name: &str) -> bool {
        self.attributes.contains_key(&name.to_lowercase())
    }

    /// Get all attribute names and values
    pub fn attrs(&self) -> impl Iterator<Item = (&String, &String)> {
        self.attributes.iter()
    }

    /// Check if element has a specific class
    pub fn has_class(&self, class_name: &str) -> bool {
        self.attributes
            .get("class")
            .map(|classes| {
                classes
                    .split_whitespace()
                    .any(|c| c.eq_ignore_ascii_case(class_name))
            })
            .unwrap_or(false)
    }

    /// Get all classes
    pub fn classes(&self) -> Vec<&str> {
        self.attributes
            .get("class")
            .map(|classes| classes.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// Get combined text content of this element and all descendants
    /// Note: For proper text extraction with nested elements, use Document::element_text()
    pub fn text(&self) -> String {
        let mut result = String::new();
        self.collect_text_shallow(&mut result);
        result
    }

    /// Collect text from immediate children only (not resolving ElementRef)
    fn collect_text_shallow(&self, buffer: &mut String) {
        for child in &self.children {
            match child {
                Node::Text(text) => {
                    if !buffer.is_empty() && !buffer.ends_with(' ') && !text.starts_with(' ') {
                        buffer.push(' ');
                    }
                    buffer.push_str(text.trim());
                }
                Node::ElementRef(_) => {
                    // ElementRef needs Document to resolve - use Document::element_text() for full traversal
                }
                Node::Comment(_) => {}
            }
        }
    }

    /// Get inner HTML as string (shallow - doesn't resolve ElementRef)
    /// For full HTML with nested elements, use Document::element_html()
    pub fn html(&self) -> String {
        let mut result = String::new();
        for child in &self.children {
            match child {
                Node::Text(text) => result.push_str(&escape_html_text(text)),
                Node::Comment(comment) => result.push_str(&format!("<!--{}-->", comment)),
                Node::ElementRef(_) => {
                    // ElementRef needs Document to resolve
                }
            }
        }
        result
    }

    /// Get outer HTML as string (including this element's tag)
    /// Note: This is shallow - use Document::element_outer_html() for full nested HTML
    pub fn outer_html(&self) -> String {
        self.to_html_string_shallow()
    }

    fn to_html_string_shallow(&self) -> String {
        let mut result = String::new();

        // Opening tag
        result.push('<');
        result.push_str(&self.tag);

        for (name, value) in &self.attributes {
            result.push(' ');
            result.push_str(name);
            result.push_str("=\"");
            result.push_str(&escape_html_attr(value));
            result.push('"');
        }

        if self.is_void_element() {
            result.push_str(" />");
        } else {
            result.push('>');

            // Children (shallow - only text and comments)
            for child in &self.children {
                match child {
                    Node::Text(text) => result.push_str(&escape_html_text(text)),
                    Node::Comment(comment) => result.push_str(&format!("<!--{}-->", comment)),
                    Node::ElementRef(_) => {
                        // ElementRef needs Document to resolve
                    }
                }
            }

            // Closing tag
            result.push_str("</");
            result.push_str(&self.tag);
            result.push('>');
        }

        result
    }

    /// Check if this is a void element (self-closing)
    pub fn is_void_element(&self) -> bool {
        matches!(
            self.tag.as_str(),
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
}

impl Node {
    /// Get element index if this is an ElementRef
    pub fn as_element_ref(&self) -> Option<usize> {
        match self {
            Node::ElementRef(idx) => Some(*idx),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&String> {
        match self {
            Node::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn is_element(&self) -> bool {
        matches!(self, Node::ElementRef(_))
    }

    pub fn is_text(&self) -> bool {
        matches!(self, Node::Text(_))
    }

    pub fn is_comment(&self) -> bool {
        matches!(self, Node::Comment(_))
    }
}

/// A parsed HTML Document
#[derive(Debug)]
pub struct Document {
    /// All elements in the document (flat storage for efficient querying)
    elements: Vec<Element>,
    /// Root element indices
    roots: Vec<usize>,
    /// Base URL for resolving relative links
    pub base_url: Option<String>,
    /// Document title (from <title> tag)
    title: Option<String>,
}

impl Document {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            roots: Vec::new(),
            base_url: None,
            title: None,
        }
    }

    /// Parse HTML string into a Document
    pub fn parse(html: &str) -> Self {
        let mut parser = HtmlParser::new(html);
        parser.parse()
    }

    /// Parse with a base URL for resolving relative links
    pub fn parse_with_base(html: &str, base_url: &str) -> Self {
        let mut doc = Self::parse(html);
        doc.base_url = Some(base_url.to_string());
        doc
    }

    /// Get document title
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Get root element indices
    pub fn roots(&self) -> &[usize] {
        &self.roots
    }

    /// Get all elements
    pub fn all_elements(&self) -> impl Iterator<Item = &Element> {
        self.elements.iter()
    }

    /// Get element by index
    pub fn get_element(&self, index: usize) -> Option<&Element> {
        self.elements.get(index)
    }

    /// Find elements by tag name
    pub fn get_elements_by_tag(&self, tag: &str) -> Vec<&Element> {
        let tag_lower = tag.to_lowercase();
        self.elements
            .iter()
            .filter(|e| e.tag == tag_lower)
            .collect()
    }

    /// Find element by ID
    pub fn get_element_by_id(&self, id: &str) -> Option<&Element> {
        self.elements
            .iter()
            .find(|e| e.attributes.get("id").map(|v| v == id).unwrap_or(false))
    }

    /// Find elements by class name
    pub fn get_elements_by_class(&self, class_name: &str) -> Vec<&Element> {
        self.elements
            .iter()
            .filter(|e| e.has_class(class_name))
            .collect()
    }

    /// Get all text content from the document
    pub fn text(&self) -> String {
        let mut result = String::new();
        for root_idx in &self.roots {
            self.collect_element_text(*root_idx, &mut result);
        }
        result
    }

    /// Get text content of an element by index (with full traversal)
    pub fn element_text(&self, idx: usize) -> String {
        let mut result = String::new();
        self.collect_element_text(idx, &mut result);
        result
    }

    /// Recursively collect text from an element and its descendants
    fn collect_element_text(&self, idx: usize, buffer: &mut String) {
        if let Some(elem) = self.elements.get(idx) {
            for child in &elem.children {
                match child {
                    Node::Text(text) => {
                        if !buffer.is_empty() && !buffer.ends_with(' ') && !text.starts_with(' ') {
                            buffer.push(' ');
                        }
                        buffer.push_str(text.trim());
                    }
                    Node::ElementRef(child_idx) => {
                        self.collect_element_text(*child_idx, buffer);
                    }
                    Node::Comment(_) => {}
                }
            }
        }
    }

    /// Get inner HTML of an element by index (with full traversal)
    pub fn element_html(&self, idx: usize) -> String {
        let mut result = String::new();
        if let Some(elem) = self.elements.get(idx) {
            for child in &elem.children {
                self.node_to_html(child, &mut result);
            }
        }
        result
    }

    /// Get outer HTML of an element by index (with full traversal)
    pub fn element_outer_html(&self, idx: usize) -> String {
        let mut result = String::new();
        self.element_to_html(idx, &mut result);
        result
    }

    /// Convert a Node to HTML string
    fn node_to_html(&self, node: &Node, buffer: &mut String) {
        match node {
            Node::Text(text) => buffer.push_str(&escape_html_text(text)),
            Node::Comment(comment) => buffer.push_str(&format!("<!--{}-->", comment)),
            Node::ElementRef(idx) => self.element_to_html(*idx, buffer),
        }
    }

    /// Convert an Element to HTML string
    fn element_to_html(&self, idx: usize, buffer: &mut String) {
        if let Some(elem) = self.elements.get(idx) {
            // Opening tag
            buffer.push('<');
            buffer.push_str(&elem.tag);

            for (name, value) in &elem.attributes {
                buffer.push(' ');
                buffer.push_str(name);
                buffer.push_str("=\"");
                buffer.push_str(&escape_html_attr(value));
                buffer.push('"');
            }

            if elem.is_void_element() {
                buffer.push_str(" />");
            } else {
                buffer.push('>');

                // Children
                for child in &elem.children {
                    self.node_to_html(child, buffer);
                }

                // Closing tag
                buffer.push_str("</");
                buffer.push_str(&elem.tag);
                buffer.push('>');
            }
        }
    }

    /// Resolve a relative URL against the base URL
    pub fn resolve_url(&self, href: &str) -> String {
        if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//") {
            return href.to_string();
        }

        if let Some(ref base) = self.base_url {
            resolve_relative_url(base, href)
        } else {
            href.to_string()
        }
    }
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HTML Parser
// ============================================================================

/// Token types for the HTML tokenizer
#[derive(Debug, Clone)]
enum Token {
    StartTag {
        name: String,
        attributes: HashMap<String, String>,
        self_closing: bool,
    },
    EndTag {
        name: String,
    },
    Text(String),
    Comment(String),
    Doctype(String),
}

/// HTML Parser that builds a Document
struct HtmlParser<'a> {
    input: &'a str,
    pos: usize,
    document: Document,
    /// Stack of open element indices
    open_elements: Vec<usize>,
}

impl<'a> HtmlParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            document: Document::new(),
            open_elements: Vec::new(),
        }
    }

    fn parse(mut self) -> Document {
        while self.pos < self.input.len() {
            if let Some(token) = self.next_token() {
                self.process_token(token);
            }
        }

        // Auto-close any remaining open elements
        self.open_elements.clear();

        self.document
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn peek_ahead(&self, n: usize) -> Option<char> {
        self.input[self.pos..].chars().nth(n)
    }

    fn advance(&mut self) {
        if let Some(c) = self.peek() {
            self.pos += c.len_utf8();
        }
    }

    fn starts_with(&self, s: &str) -> bool {
        self.input[self.pos..].starts_with(s)
    }

    fn starts_with_ignore_case(&self, s: &str) -> bool {
        let remaining = &self.input[self.pos..];
        if remaining.len() < s.len() {
            return false;
        }
        remaining[..s.len()].eq_ignore_ascii_case(s)
    }

    fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.advance();
        }
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos >= self.input.len() {
            return None;
        }

        if self.starts_with("<!--") {
            return Some(self.parse_comment());
        }

        if self.starts_with_ignore_case("<!doctype") {
            return Some(self.parse_doctype());
        }

        if self.starts_with("</") {
            return Some(self.parse_end_tag());
        }

        if self.starts_with("<")
            && self
                .peek_ahead(1)
                .map(|c| c.is_alphabetic())
                .unwrap_or(false)
        {
            return Some(self.parse_start_tag());
        }

        // Text content
        Some(self.parse_text())
    }

    fn parse_comment(&mut self) -> Token {
        self.skip(4); // Skip "<!--"

        let start = self.pos;
        while self.pos < self.input.len() {
            if self.starts_with("-->") {
                let comment = self.input[start..self.pos].to_string();
                self.skip(3);
                return Token::Comment(comment);
            }
            self.advance();
        }

        Token::Comment(self.input[start..].to_string())
    }

    fn parse_doctype(&mut self) -> Token {
        self.skip(9); // Skip "<!DOCTYPE" or "<!doctype"

        let start = self.pos;
        while self.pos < self.input.len() {
            if self.peek() == Some('>') {
                let doctype = self.input[start..self.pos].trim().to_string();
                self.advance();
                return Token::Doctype(doctype);
            }
            self.advance();
        }

        Token::Doctype(self.input[start..].to_string())
    }

    fn parse_start_tag(&mut self) -> Token {
        self.advance(); // Skip '<'

        // Parse tag name
        let name = self.parse_tag_name();

        // Parse attributes
        let mut attributes = HashMap::new();
        loop {
            self.skip_whitespace();

            if self.peek() == Some('>') {
                self.advance();
                return Token::StartTag {
                    name,
                    attributes,
                    self_closing: false,
                };
            }

            if self.starts_with("/>") {
                self.skip(2);
                return Token::StartTag {
                    name,
                    attributes,
                    self_closing: true,
                };
            }

            if self.pos >= self.input.len() {
                break;
            }

            // Parse attribute
            if let Some((attr_name, attr_value)) = self.parse_attribute() {
                attributes.insert(attr_name.to_lowercase(), attr_value);
            } else {
                // Invalid attribute, skip character
                self.advance();
            }
        }

        Token::StartTag {
            name,
            attributes,
            self_closing: false,
        }
    }

    fn parse_end_tag(&mut self) -> Token {
        self.skip(2); // Skip "</"

        let name = self.parse_tag_name();

        // Skip to closing '>'
        while self.pos < self.input.len() && self.peek() != Some('>') {
            self.advance();
        }
        if self.peek() == Some('>') {
            self.advance();
        }

        Token::EndTag { name }
    }

    fn parse_tag_name(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.peek().unwrap();
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ':' {
                self.advance();
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_lowercase()
    }

    fn parse_attribute(&mut self) -> Option<(String, String)> {
        let start = self.pos;

        // Parse attribute name
        while self.pos < self.input.len() {
            let c = self.peek()?;
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ':' {
                self.advance();
            } else {
                break;
            }
        }

        if self.pos == start {
            return None;
        }

        let name = self.input[start..self.pos].to_string();

        self.skip_whitespace();

        // Check for '='
        if self.peek() != Some('=') {
            // Boolean attribute
            return Some((name, String::new()));
        }

        self.advance(); // Skip '='
        self.skip_whitespace();

        // Parse value
        let value = if self.peek() == Some('"') {
            self.parse_quoted_value('"')
        } else if self.peek() == Some('\'') {
            self.parse_quoted_value('\'')
        } else {
            self.parse_unquoted_value()
        };

        Some((name, value))
    }

    fn parse_quoted_value(&mut self, quote: char) -> String {
        self.advance(); // Skip opening quote

        let start = self.pos;
        while self.pos < self.input.len() && self.peek() != Some(quote) {
            self.advance();
        }

        let value = self.input[start..self.pos].to_string();

        if self.peek() == Some(quote) {
            self.advance(); // Skip closing quote
        }

        decode_html_entities(&value)
    }

    fn parse_unquoted_value(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.peek().unwrap();
            if c.is_whitespace() || c == '>' || c == '/' {
                break;
            }
            self.advance();
        }
        decode_html_entities(&self.input[start..self.pos])
    }

    fn parse_text(&mut self) -> Token {
        let start = self.pos;

        // Check if we're in a raw text element (script, style, textarea, etc.)
        let in_raw_text = self.open_elements.last().and_then(|&idx| {
            self.document.elements.get(idx).map(|e| {
                matches!(
                    e.tag.as_str(),
                    "script" | "style" | "textarea" | "title" | "xmp"
                )
            })
        });

        if in_raw_text == Some(true) {
            // Find the closing tag
            let tag = self
                .open_elements
                .last()
                .and_then(|&idx| self.document.elements.get(idx))
                .map(|e| e.tag.clone())
                .unwrap_or_default();

            let end_tag = format!("</{}", tag);
            while self.pos < self.input.len() {
                if self.starts_with_ignore_case(&end_tag) {
                    break;
                }
                self.advance();
            }
        } else {
            while self.pos < self.input.len() && self.peek() != Some('<') {
                self.advance();
            }
        }

        let text = self.input[start..self.pos].to_string();
        Token::Text(decode_html_entities(&text))
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            if let Some(c) = self.peek() {
                if c.is_whitespace() {
                    self.advance();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn process_token(&mut self, token: Token) {
        match token {
            Token::StartTag {
                name,
                attributes,
                self_closing,
            } => {
                let idx = self.document.elements.len();
                let mut element = Element::new(&name, idx);
                element.attributes = attributes;

                // Set parent
                if let Some(&parent_idx) = self.open_elements.last() {
                    element.parent_index = Some(parent_idx);
                }

                // Check for base URL
                if name == "base" {
                    if let Some(href) = element.attributes.get("href") {
                        self.document.base_url = Some(href.clone());
                    }
                }

                // Check for title
                if name == "title" && self.document.title.is_none() {
                    // Title will be set when we process text inside
                }

                self.document.elements.push(element);

                // Add to parent's children as ElementRef (index-based reference)
                if let Some(&parent_idx) = self.open_elements.last() {
                    self.document.elements[parent_idx]
                        .children
                        .push(Node::ElementRef(idx));
                } else {
                    self.document.roots.push(idx);
                }

                // Push to stack if not self-closing and not void element
                let is_void = self.document.elements[idx].is_void_element();
                if !self_closing && !is_void {
                    self.open_elements.push(idx);
                }
            }

            Token::EndTag { name } => {
                // Find matching open element
                let mut found_idx = None;
                for (i, &elem_idx) in self.open_elements.iter().rev().enumerate() {
                    if let Some(elem) = self.document.elements.get(elem_idx) {
                        if elem.tag == name {
                            found_idx = Some(self.open_elements.len() - 1 - i);
                            break;
                        }
                    }
                }

                // Pop elements up to and including the matching one
                if let Some(idx) = found_idx {
                    // Check if this was a title element
                    if name == "title" && self.document.title.is_none() {
                        if let Some(&elem_idx) = self.open_elements.get(idx) {
                            if let Some(elem) = self.document.elements.get(elem_idx) {
                                self.document.title = Some(elem.text());
                            }
                        }
                    }

                    self.open_elements.truncate(idx);
                }
            }

            Token::Text(text) => {
                // Collapse whitespace for non-preformatted content
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    if let Some(&parent_idx) = self.open_elements.last() {
                        self.document.elements[parent_idx]
                            .children
                            .push(Node::Text(text.clone()));
                    }
                }
            }

            Token::Comment(comment) => {
                if let Some(&parent_idx) = self.open_elements.last() {
                    self.document.elements[parent_idx]
                        .children
                        .push(Node::Comment(comment));
                }
            }

            Token::Doctype(_) => {
                // Ignore doctype for now
            }
        }
    }
}

// ============================================================================
// Selection API (Cheerio-like)
// ============================================================================

/// A selection of elements (like jQuery/Cheerio's $() result)
#[derive(Debug, Clone)]
pub struct Selection<'a> {
    elements: Vec<&'a Element>,
}

impl<'a> Selection<'a> {
    pub fn new(elements: Vec<&'a Element>) -> Self {
        Self { elements }
    }

    pub fn empty() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Get number of elements in selection
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if selection is empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Get first element
    pub fn first(&self) -> Option<&Element> {
        self.elements.first().copied()
    }

    /// Get last element
    pub fn last(&self) -> Option<&Element> {
        self.elements.last().copied()
    }

    /// Get element at index
    pub fn get(&self, index: usize) -> Option<&Element> {
        self.elements.get(index).copied()
    }

    /// Iterate over elements
    pub fn iter(&self) -> impl Iterator<Item = &Element> {
        self.elements.iter().copied()
    }

    /// Get combined text content of all elements
    pub fn text(&self) -> String {
        self.elements
            .iter()
            .map(|e| e.text())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get attribute value from first element
    pub fn attr(&self, name: &str) -> Option<&String> {
        self.first().and_then(|e| e.attr(name))
    }

    /// Get inner HTML of first element
    pub fn html(&self) -> String {
        self.first().map(|e| e.html()).unwrap_or_default()
    }

    /// Check if any element has the given class
    pub fn has_class(&self, class_name: &str) -> bool {
        self.elements.iter().any(|e| e.has_class(class_name))
    }

    /// Map over elements
    pub fn map<F, T>(&self, f: F) -> Vec<T>
    where
        F: Fn(&Element) -> T,
    {
        self.elements.iter().map(|e| f(*e)).collect()
    }

    /// Filter elements
    pub fn filter<F>(&self, f: F) -> Selection<'a>
    where
        F: Fn(&Element) -> bool,
    {
        Selection {
            elements: self.elements.iter().filter(|e| f(*e)).copied().collect(),
        }
    }

    /// Each - iterate with callback
    pub fn each<F>(&self, mut f: F)
    where
        F: FnMut(usize, &Element),
    {
        for (i, elem) in self.elements.iter().enumerate() {
            f(i, *elem);
        }
    }
}

impl Document {
    /// Select all elements matching a selector (basic implementation)
    /// Full CSS selector support is in the selector module
    pub fn select_by_tag(&self, tag: &str) -> Selection {
        Selection::new(self.get_elements_by_tag(tag))
    }

    pub fn select_by_class(&self, class: &str) -> Selection {
        Selection::new(self.get_elements_by_class(class))
    }

    pub fn select_by_id(&self, id: &str) -> Selection {
        Selection::new(self.get_element_by_id(id).into_iter().collect::<Vec<_>>())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn escape_html_text(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(c),
        }
    }
    result
}

fn escape_html_attr(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            _ => result.push(c),
        }
    }
    result
}

fn decode_html_entities(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            while let Some(&nc) = chars.peek() {
                if nc == ';' {
                    chars.next();
                    break;
                }
                if !nc.is_alphanumeric() && nc != '#' {
                    break;
                }
                entity.push(chars.next().unwrap());
            }

            match entity.as_str() {
                "amp" => result.push('&'),
                "lt" => result.push('<'),
                "gt" => result.push('>'),
                "quot" => result.push('"'),
                "apos" => result.push('\''),
                "nbsp" => result.push('\u{00A0}'),
                "copy" => result.push('\u{00A9}'),
                "reg" => result.push('\u{00AE}'),
                "trade" => result.push('\u{2122}'),
                "mdash" => result.push('\u{2014}'),
                "ndash" => result.push('\u{2013}'),
                "hellip" => result.push('\u{2026}'),
                "bull" => result.push('\u{2022}'),
                s if s.starts_with('#') => {
                    let code = if s.starts_with("#x") || s.starts_with("#X") {
                        u32::from_str_radix(&s[2..], 16).ok()
                    } else {
                        s[1..].parse().ok()
                    };
                    if let Some(code) = code {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                        }
                    }
                }
                _ => {
                    // Unknown entity, preserve it
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

fn resolve_relative_url(base: &str, href: &str) -> String {
    // Handle protocol-relative URLs
    if href.starts_with("//") {
        if base.starts_with("https://") {
            return format!("https:{}", href);
        } else {
            return format!("http:{}", href);
        }
    }

    // Extract protocol and rest from base
    let (protocol, rest) = if let Some(pos) = base.find("://") {
        (&base[..pos + 3], &base[pos + 3..])
    } else {
        ("", base)
    };

    // Handle absolute path
    if href.starts_with('/') {
        // Extract host from rest
        let host = rest.split('/').next().unwrap_or("");
        return format!("{}{}{}", protocol, host, href);
    }

    // Handle relative path
    // Get base directory (without filename)
    let base_path = if rest.ends_with('/') {
        rest.to_string()
    } else if let Some(pos) = rest.rfind('/') {
        rest[..=pos].to_string()
    } else {
        format!("{}/", rest)
    };

    // Split into parts
    let mut result_parts: Vec<&str> = base_path.split('/').filter(|s| !s.is_empty()).collect();

    for part in href.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                // Don't pop the host
                if result_parts.len() > 1 {
                    result_parts.pop();
                }
            }
            _ => result_parts.push(part),
        }
    }

    // Reconstruct URL
    if !protocol.is_empty() {
        format!("{}{}", protocol, result_parts.join("/"))
    } else {
        format!("/{}", result_parts.join("/"))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_html() {
        let html = "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>";
        let doc = Document::parse(html);

        assert!(doc.title().is_some());
        assert_eq!(doc.title(), Some("Test"));
    }

    #[test]
    fn test_parse_attributes() {
        let html =
            r#"<a href="https://example.com" class="link external" id="main-link">Click</a>"#;
        let doc = Document::parse(html);

        let links = doc.get_elements_by_tag("a");
        assert_eq!(links.len(), 1);

        let link = links[0];
        assert_eq!(link.attr("href"), Some(&"https://example.com".to_string()));
        assert!(link.has_class("link"));
        assert!(link.has_class("external"));
        assert_eq!(link.attr("id"), Some(&"main-link".to_string()));
    }

    #[test]
    fn test_text_extraction() {
        let html = "<div><p>Hello</p><p>World</p></div>";
        let doc = Document::parse(html);

        let divs = doc.get_elements_by_tag("div");
        assert_eq!(divs.len(), 1);

        // Use Document method for full text traversal (includes nested elements)
        let text = doc.element_text(divs[0].self_index);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_self_closing_tags() {
        let html = r#"<img src="image.png" /><br><input type="text">"#;
        let doc = Document::parse(html);

        let imgs = doc.get_elements_by_tag("img");
        assert_eq!(imgs.len(), 1);

        let brs = doc.get_elements_by_tag("br");
        assert_eq!(brs.len(), 1);

        let inputs = doc.get_elements_by_tag("input");
        assert_eq!(inputs.len(), 1);
    }

    #[test]
    fn test_html_entities() {
        let html = "<p>&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;</p>";
        let doc = Document::parse(html);

        let text = doc.text();
        assert!(text.contains("<script>"));
        assert!(text.contains("</script>"));
    }

    #[test]
    fn test_malformed_html() {
        let html = "<div><p>Unclosed paragraph<span>Nested</div>";
        let doc = Document::parse(html);

        // Should still parse without panicking
        assert!(!doc.elements.is_empty());
    }

    #[test]
    fn test_selection_api() {
        let html = r#"
            <ul>
                <li class="item">One</li>
                <li class="item">Two</li>
                <li class="item active">Three</li>
            </ul>
        "#;
        let doc = Document::parse(html);

        let items = doc.select_by_class("item");
        assert_eq!(items.len(), 3);

        let active = doc.select_by_class("active");
        assert_eq!(active.len(), 1);
        assert!(active.first().unwrap().text().contains("Three"));
    }

    #[test]
    fn test_resolve_relative_url() {
        assert_eq!(
            resolve_relative_url("https://example.com/path/page.html", "../other.html"),
            "https://example.com/other.html"
        );

        assert_eq!(
            resolve_relative_url("https://example.com/path/", "sub/page.html"),
            "https://example.com/path/sub/page.html"
        );

        assert_eq!(
            resolve_relative_url("https://example.com/path/page.html", "/absolute.html"),
            "https://example.com/absolute.html"
        );
    }

    #[test]
    fn test_inner_html() {
        let html = "<div><p>Para 1</p><p>Para 2</p></div>";
        let doc = Document::parse(html);

        let divs = doc.get_elements_by_tag("div");
        // Use Document method for full HTML traversal (includes nested elements)
        let inner = doc.element_html(divs[0].self_index);

        assert!(inner.contains("<p>"));
        assert!(inner.contains("Para 1"));
    }

    #[test]
    fn test_outer_html() {
        let html = r#"<a href="link">Text</a>"#;
        let doc = Document::parse(html);

        let links = doc.get_elements_by_tag("a");
        let outer = links[0].outer_html();

        assert!(outer.contains("<a"));
        assert!(outer.contains("href="));
        assert!(outer.contains("</a>"));
    }

    #[test]
    fn test_get_by_id() {
        let html = r#"<div id="header">Header</div><div id="content">Content</div>"#;
        let doc = Document::parse(html);

        let header = doc.get_element_by_id("header");
        assert!(header.is_some());
        assert_eq!(header.unwrap().text(), "Header");

        let missing = doc.get_element_by_id("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_comments() {
        let html = "<!-- This is a comment --><p>Content</p>";
        let doc = Document::parse(html);

        let paras = doc.get_elements_by_tag("p");
        assert_eq!(paras.len(), 1);
    }

    #[test]
    fn test_script_content() {
        let html = r#"<script>var x = '<div>Not a tag</div>';</script><div>Real div</div>"#;
        let doc = Document::parse(html);

        // The <div> inside script should not be parsed as an element
        let divs = doc.get_elements_by_tag("div");
        assert_eq!(divs.len(), 1);
        assert_eq!(divs[0].text(), "Real div");
    }

    #[test]
    fn test_nested_elements() {
        let html = r#"
            <div class="outer">
                <div class="inner">
                    <span>Deep</span>
                </div>
            </div>
        "#;
        let doc = Document::parse(html);

        let outer = doc.select_by_class("outer");
        assert_eq!(outer.len(), 1);

        let inner = doc.select_by_class("inner");
        assert_eq!(inner.len(), 1);

        let spans = doc.get_elements_by_tag("span");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text(), "Deep");
    }
}
