//! Recipe Parser
//!
//! Parses recipe strings into executable operations.

use std::collections::HashMap;

/// A single operation in a recipe
#[derive(Debug, Clone)]
pub struct Operation {
    /// Operation name (codec or cipher name)
    pub name: String,
    /// Operation mode (encode/decode/encrypt/decrypt)
    pub mode: OperationMode,
    /// Operation arguments
    pub args: HashMap<String, String>,
}

/// Operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMode {
    Encode,
    Decode,
    Encrypt,
    Decrypt,
    Crack,
}

/// A complete recipe
#[derive(Debug, Clone)]
pub struct Recipe {
    /// Ordered list of operations
    pub operations: Vec<Operation>,
    /// Recipe name (optional)
    pub name: Option<String>,
    /// Recipe description (optional)
    pub description: Option<String>,
}

/// Recipe parser
pub struct RecipeParser;

impl RecipeParser {
    /// Parse a recipe string
    ///
    /// Format: `operation1(args) | operation2(args) | ...`
    ///
    /// Examples:
    /// - `base64_decode | hex_encode`
    /// - `caesar_decrypt(shift=3) | base64_encode`
    /// - `xor_encrypt(key=0x42) | hex_encode`
    pub fn parse(input: &str) -> Result<Recipe, String> {
        let mut operations = Vec::new();

        for part in input.split('|') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let op = Self::parse_operation(part)?;
            operations.push(op);
        }

        if operations.is_empty() {
            return Err("Empty recipe".to_string());
        }

        Ok(Recipe {
            operations,
            name: None,
            description: None,
        })
    }

    /// Parse a single operation
    fn parse_operation(input: &str) -> Result<Operation, String> {
        // Parse format: name_mode(args) or name_mode
        let input = input.trim();

        // Extract args if present
        let (name_mode, args) = if let Some(paren_start) = input.find('(') {
            let paren_end = input
                .rfind(')')
                .ok_or_else(|| format!("Missing closing parenthesis in: {}", input))?;

            let args_str = &input[paren_start + 1..paren_end];
            let args = Self::parse_args(args_str)?;
            (&input[..paren_start], args)
        } else {
            (input, HashMap::new())
        };

        // Parse name and mode
        let (name, mode) = Self::parse_name_mode(name_mode)?;

        Ok(Operation { name, mode, args })
    }

    /// Parse operation name and mode
    fn parse_name_mode(input: &str) -> Result<(String, OperationMode), String> {
        let input = input.trim().to_lowercase();

        // Check for explicit mode suffix
        if let Some(name) = input.strip_suffix("_encode") {
            return Ok((name.to_string(), OperationMode::Encode));
        }
        if let Some(name) = input.strip_suffix("_decode") {
            return Ok((name.to_string(), OperationMode::Decode));
        }
        if let Some(name) = input.strip_suffix("_encrypt") {
            return Ok((name.to_string(), OperationMode::Encrypt));
        }
        if let Some(name) = input.strip_suffix("_decrypt") {
            return Ok((name.to_string(), OperationMode::Decrypt));
        }
        if let Some(name) = input.strip_suffix("_crack") {
            return Ok((name.to_string(), OperationMode::Crack));
        }

        // Default to decode for common codecs
        let default_decode = [
            "base64", "base32", "hex", "url", "html", "unicode", "rot13", "rot47", "rot5", "atbash",
        ];

        if default_decode.contains(&input.as_str()) {
            // For self-inverse operations, default to decode
            Ok((input, OperationMode::Decode))
        } else {
            // Unknown - default to decode
            Ok((input, OperationMode::Decode))
        }
    }

    /// Parse arguments string
    fn parse_args(input: &str) -> Result<HashMap<String, String>, String> {
        let mut args = HashMap::new();

        if input.trim().is_empty() {
            return Ok(args);
        }

        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim().to_string();
                let value = value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                args.insert(key, value);
            } else {
                // Positional argument - use index as key
                args.insert(args.len().to_string(), part.to_string());
            }
        }

        Ok(args)
    }

    /// Parse a JSON recipe
    pub fn parse_json(json: &str) -> Result<Recipe, String> {
        // Simple JSON parsing without external crate
        // Format: {"operations": [{"name": "base64", "mode": "decode", "args": {}}]}

        let json = json.trim();
        if !json.starts_with('{') || !json.ends_with('}') {
            return Err("Invalid JSON: must be an object".to_string());
        }

        // Extract operations array
        let ops_start = json
            .find("\"operations\"")
            .ok_or("Missing 'operations' field")?;
        let array_start = json[ops_start..]
            .find('[')
            .ok_or("Missing operations array")?
            + ops_start;
        let array_end = Self::find_matching_bracket(&json[array_start..])? + array_start;

        let ops_json = &json[array_start + 1..array_end];

        // Parse each operation
        let mut operations = Vec::new();
        let mut depth = 0;
        let mut start = 0;

        for (i, c) in ops_json.char_indices() {
            match c {
                '{' => {
                    if depth == 0 {
                        start = i;
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let op_json = &ops_json[start..=i];
                        let op = Self::parse_json_operation(op_json)?;
                        operations.push(op);
                    }
                }
                _ => {}
            }
        }

        Ok(Recipe {
            operations,
            name: None,
            description: None,
        })
    }

    fn find_matching_bracket(s: &str) -> Result<usize, String> {
        let mut depth = 0;
        for (i, c) in s.char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(i);
                    }
                }
                _ => {}
            }
        }
        Err("Unmatched bracket".to_string())
    }

    fn parse_json_operation(json: &str) -> Result<Operation, String> {
        // Extract name
        let name = Self::extract_json_string(json, "name")?;

        // Extract mode
        let mode_str =
            Self::extract_json_string(json, "mode").unwrap_or_else(|_| "decode".to_string());
        let mode = match mode_str.as_str() {
            "encode" => OperationMode::Encode,
            "decode" => OperationMode::Decode,
            "encrypt" => OperationMode::Encrypt,
            "decrypt" => OperationMode::Decrypt,
            "crack" => OperationMode::Crack,
            _ => OperationMode::Decode,
        };

        // Args would need more complex parsing - simplified for now
        let args = HashMap::new();

        Ok(Operation { name, mode, args })
    }

    fn extract_json_string(json: &str, key: &str) -> Result<String, String> {
        let pattern = format!("\"{}\"", key);
        let key_pos = json
            .find(&pattern)
            .ok_or_else(|| format!("Missing key: {}", key))?;

        let after_key = &json[key_pos + pattern.len()..];
        let colon_pos = after_key
            .find(':')
            .ok_or_else(|| format!("Missing colon after: {}", key))?;

        let after_colon = after_key[colon_pos + 1..].trim_start();

        if after_colon.starts_with('"') {
            let end = after_colon[1..]
                .find('"')
                .ok_or_else(|| format!("Unclosed string for: {}", key))?;
            Ok(after_colon[1..end + 1].to_string())
        } else {
            // Non-string value
            let end = after_colon
                .find(|c: char| c == ',' || c == '}' || c == ']')
                .unwrap_or(after_colon.len());
            Ok(after_colon[..end].trim().to_string())
        }
    }
}

impl Recipe {
    /// Create a new empty recipe
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            name: None,
            description: None,
        }
    }

    /// Add an operation
    pub fn add(&mut self, op: Operation) {
        self.operations.push(op);
    }

    /// Builder: add encode operation
    pub fn encode(mut self, codec: &str) -> Self {
        self.operations.push(Operation {
            name: codec.to_string(),
            mode: OperationMode::Encode,
            args: HashMap::new(),
        });
        self
    }

    /// Builder: add decode operation
    pub fn decode(mut self, codec: &str) -> Self {
        self.operations.push(Operation {
            name: codec.to_string(),
            mode: OperationMode::Decode,
            args: HashMap::new(),
        });
        self
    }

    /// Builder: add encrypt operation
    pub fn encrypt(mut self, cipher: &str, key: &str) -> Self {
        let mut args = HashMap::new();
        args.insert("key".to_string(), key.to_string());
        self.operations.push(Operation {
            name: cipher.to_string(),
            mode: OperationMode::Encrypt,
            args,
        });
        self
    }

    /// Builder: add decrypt operation
    pub fn decrypt(mut self, cipher: &str, key: &str) -> Self {
        let mut args = HashMap::new();
        args.insert("key".to_string(), key.to_string());
        self.operations.push(Operation {
            name: cipher.to_string(),
            mode: OperationMode::Decrypt,
            args,
        });
        self
    }
}

impl Default for Recipe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let recipe = RecipeParser::parse("base64_decode").unwrap();
        assert_eq!(recipe.operations.len(), 1);
        assert_eq!(recipe.operations[0].name, "base64");
        assert_eq!(recipe.operations[0].mode, OperationMode::Decode);
    }

    #[test]
    fn test_parse_chain() {
        let recipe = RecipeParser::parse("base64_decode | hex_encode").unwrap();
        assert_eq!(recipe.operations.len(), 2);
        assert_eq!(recipe.operations[0].name, "base64");
        assert_eq!(recipe.operations[0].mode, OperationMode::Decode);
        assert_eq!(recipe.operations[1].name, "hex");
        assert_eq!(recipe.operations[1].mode, OperationMode::Encode);
    }

    #[test]
    fn test_parse_with_args() {
        let recipe = RecipeParser::parse("caesar_decrypt(shift=3)").unwrap();
        assert_eq!(recipe.operations.len(), 1);
        assert_eq!(recipe.operations[0].name, "caesar");
        assert_eq!(recipe.operations[0].mode, OperationMode::Decrypt);
        assert_eq!(
            recipe.operations[0].args.get("shift"),
            Some(&"3".to_string())
        );
    }

    #[test]
    fn test_builder() {
        let recipe = Recipe::new()
            .decode("base64")
            .encode("hex")
            .encrypt("xor", "0x42");

        assert_eq!(recipe.operations.len(), 3);
        assert_eq!(recipe.operations[0].name, "base64");
        assert_eq!(recipe.operations[1].name, "hex");
        assert_eq!(recipe.operations[2].name, "xor");
    }
}
