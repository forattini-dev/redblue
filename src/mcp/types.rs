//! MCP Server Types
//!
//! Core types for MCP tool definitions and results.

use crate::utils::json::JsonValue;

/// Tool handler function signature
pub type ToolHandler<T> = fn(&mut T, &JsonValue) -> Result<ToolResult, String>;

/// Definition of a tool field/parameter
#[derive(Clone)]
pub struct ToolField {
    pub name: &'static str,
    pub field_type: &'static str,
    pub description: &'static str,
    pub required: bool,
}

/// Complete tool definition including handler
pub struct ToolDefinition<T> {
    pub name: &'static str,
    pub description: &'static str,
    pub fields: &'static [ToolField],
    pub handler: ToolHandler<T>,
}

/// Result from a tool execution
pub struct ToolResult {
    pub text: String,
    pub data: JsonValue,
}

/// Documentation search hit
pub struct DocHit {
    pub path: String,
    pub line: usize,
    pub snippet: String,
}

impl ToolResult {
    /// Create a simple text result
    pub fn text(msg: impl Into<String>) -> Self {
        Self {
            text: msg.into(),
            data: JsonValue::Null,
        }
    }

    /// Create a result with text and JSON data
    pub fn with_data(text: impl Into<String>, data: JsonValue) -> Self {
        Self {
            text: text.into(),
            data,
        }
    }
}

/// Hex encoding/decoding helper module for MCP tools
pub mod hex {
    /// Encode bytes to lowercase hex string
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Decode hex string to bytes
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        let s = s.trim();
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();

        if s.is_empty() {
            return Ok(Vec::new());
        }

        if s.len() % 2 != 0 {
            return Err("Invalid hex length");
        }

        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let high = decode_nibble(pair[0])?;
                let low = decode_nibble(pair[1])?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    fn decode_nibble(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("Invalid hex character"),
        }
    }
}
