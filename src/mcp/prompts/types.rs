//! MCP Prompt types
//!
//! Shared types for prompt definitions and generation.

use std::collections::HashMap;

/// Argument type for validation and hints
#[derive(Debug, Clone, PartialEq)]
pub enum ArgumentType {
  /// Free-form string
  String,
  /// Integer number
  Integer,
  /// Boolean true/false
  Boolean,
  /// One of a set of values
  Enum,
  /// Array of values
  Array,
  /// URL (http/https)
  Url,
  /// IP address (v4 or v6)
  IpAddress,
  /// Domain name
  Domain,
  /// CIDR range (e.g., 192.168.1.0/24)
  Cidr,
  /// Port number (1-65535)
  Port,
  /// CVE identifier (e.g., CVE-2024-1234)
  CveId,
}

impl Default for ArgumentType {
  fn default() -> Self {
    ArgumentType::String
  }
}

/// An argument for a prompt
#[derive(Debug, Clone, Default)]
pub struct PromptArgument {
  /// Argument name
  pub name: String,
  /// Description of the argument
  pub description: String,
  /// Whether this argument is required
  pub required: bool,
  /// Type of the argument for validation
  #[allow(dead_code)]
  pub arg_type: ArgumentType,
  /// Example values to help the user
  #[allow(dead_code)]
  pub examples: Vec<String>,
  /// Valid values for Enum type
  #[allow(dead_code)]
  pub enum_values: Option<Vec<String>>,
}

impl PromptArgument {
  /// Create a new required string argument
  pub fn required(name: &str, description: &str) -> Self {
    Self {
      name: name.into(),
      description: description.into(),
      required: true,
      arg_type: ArgumentType::String,
      examples: Vec::new(),
      enum_values: None,
    }
  }

  /// Create a new optional string argument
  pub fn optional(name: &str, description: &str) -> Self {
    Self {
      name: name.into(),
      description: description.into(),
      required: false,
      arg_type: ArgumentType::String,
      examples: Vec::new(),
      enum_values: None,
    }
  }

  /// Set the argument type
  pub fn with_type(mut self, arg_type: ArgumentType) -> Self {
    self.arg_type = arg_type;
    self
  }

  /// Add example values
  pub fn with_examples(mut self, examples: Vec<&str>) -> Self {
    self.examples = examples.into_iter().map(String::from).collect();
    self
  }

  /// Set enum values (also sets type to Enum)
  pub fn with_enum(mut self, values: Vec<&str>) -> Self {
    self.arg_type = ArgumentType::Enum;
    self.enum_values = Some(values.into_iter().map(String::from).collect());
    self
  }
}

/// A prompt template definition
#[derive(Debug, Clone)]
pub struct Prompt {
  /// Unique identifier for the prompt
  pub name: String,
  /// Human-readable description
  pub description: String,
  /// Arguments the prompt accepts
  pub arguments: Vec<PromptArgument>,
}

/// A message in a prompt response
#[derive(Debug, Clone)]
pub struct PromptMessage {
  /// Role: "user" or "assistant"
  pub role: String,
  /// Content of the message
  pub content: String,
}

/// Result of getting a prompt
#[derive(Debug, Clone)]
pub struct PromptResult {
  /// Description of the prompt
  pub description: String,
  /// Messages to send
  pub messages: Vec<PromptMessage>,
}

/// Type alias for argument maps
pub type Args = HashMap<String, String>;

/// Helper to get optional arg with default
pub fn get_arg<'a>(args: &'a Args, key: &str, default: &'a str) -> &'a str {
  args.get(key).map(|s| s.as_str()).unwrap_or(default)
}

/// Helper to get required arg
pub fn get_required_arg<'a>(args: &'a Args, key: &str) -> &'a str {
  args.get(key).map(|s| s.as_str()).unwrap_or("unknown")
}
