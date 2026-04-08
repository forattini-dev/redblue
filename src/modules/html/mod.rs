#![allow(dead_code)]

/// HTML Module - Arena-based HTML parsing and CSS selector engine
///
/// Provides a fast, zero-dependency HTML parser that builds an arena-allocated
/// DOM tree, paired with a full CSS selector engine for querying elements.
///
/// ## Architecture
///
/// - **parser**: Tokenizer + tree builder producing an arena-backed HtmlDocument
/// - **selector**: Hand-written CSS selector parser and matcher
///
/// ## Usage
///
/// ```ignore
/// use crate::modules::html::parser::HtmlDocument;
/// use crate::modules::html::selector::{parse_selector, select_all, matches};
///
/// let doc = HtmlDocument::parse("<div class='x'><p>hello</p></div>");
///
/// // Convenience API
/// let nodes = doc.select("div.x > p");
/// let first = doc.select_one("p");
///
/// // Lower-level API
/// let sel = parse_selector("p").unwrap();
/// let all = select_all(&doc, &sel);
/// ```
pub mod extractors;
pub mod parser;
pub mod selector;

// Re-export primary types for convenient access
pub use extractors::{
  ExtractedForm, ExtractedImage, ExtractedLink, ExtractedMeta, ExtractedScript, ExtractedStyle,
  ExtractedTable, FormField, LinkType, SelectOption,
};
pub use parser::{Arena, HtmlDocument, Node, NodeType};
pub use selector::{
  matches, parse_selector, select_all, select_first, AttrOp, AttrSelector, CombinatorOp, NthExpr,
  PseudoSelector, Selector,
};
