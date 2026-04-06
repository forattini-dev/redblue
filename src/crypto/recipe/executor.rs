//! Recipe Executor
//!
//! Executes recipes to transform data through multiple operations.

use super::parser::{Operation, OperationMode, Recipe};
use crate::crypto::cipher::{CipherKey, CipherRegistry};
use crate::crypto::codec::CodecRegistry;

/// Execution result for a single step
#[derive(Debug, Clone)]
pub struct StepResult {
  /// Operation that was executed
  pub operation: String,
  /// Mode that was used
  pub mode: String,
  /// Output of this step
  pub output: Vec<u8>,
  /// Any notes or warnings
  pub notes: Option<String>,
}

/// Full execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
  /// Input data
  pub input: Vec<u8>,
  /// Final output
  pub output: Vec<u8>,
  /// Results from each step
  pub steps: Vec<StepResult>,
  /// Whether execution was successful
  pub success: bool,
  /// Error message if failed
  pub error: Option<String>,
}

/// Recipe executor
pub struct RecipeExecutor {
  codec_registry: CodecRegistry,
  cipher_registry: CipherRegistry,
}

impl Default for RecipeExecutor {
  fn default() -> Self {
    Self::new()
  }
}

impl RecipeExecutor {
  /// Create new executor
  pub fn new() -> Self {
    Self {
      codec_registry: CodecRegistry::new(),
      cipher_registry: CipherRegistry::new(),
    }
  }

  /// Execute a recipe on input data
  pub fn execute(&self, recipe: &Recipe, input: &[u8]) -> ExecutionResult {
    let mut current = input.to_vec();
    let mut steps = Vec::new();

    for op in &recipe.operations {
      match self.execute_operation(op, &current) {
        Ok(result) => {
          steps.push(StepResult {
            operation: op.name.clone(),
            mode: format!("{:?}", op.mode),
            output: result.clone(),
            notes: None,
          });
          current = result;
        }
        Err(e) => {
          return ExecutionResult {
            input: input.to_vec(),
            output: current,
            steps,
            success: false,
            error: Some(e),
          };
        }
      }
    }

    ExecutionResult {
      input: input.to_vec(),
      output: current,
      steps,
      success: true,
      error: None,
    }
  }

  /// Execute a single operation
  fn execute_operation(&self, op: &Operation, input: &[u8]) -> Result<Vec<u8>, String> {
    // Try codec first
    if let Some(codec) = self.codec_registry.get(&op.name) {
      return match op.mode {
        OperationMode::Encode => codec.encode(input).map_err(|e| e.to_string()),
        OperationMode::Decode => codec.decode(input).map_err(|e| e.to_string()),
        _ => Err(format!(
          "Codec {} doesn't support {:?} mode",
          op.name, op.mode
        )),
      };
    }

    // Try cipher
    if let Some(cipher) = self.cipher_registry.get(&op.name) {
      let key = self.parse_cipher_key(&op.name, &op.args)?;

      return match op.mode {
        OperationMode::Encrypt | OperationMode::Encode => {
          cipher.encrypt(input, &key).map_err(|e| e.to_string())
        }
        OperationMode::Decrypt | OperationMode::Decode => {
          cipher.decrypt(input, &key).map_err(|e| e.to_string())
        }
        OperationMode::Crack => {
          let results = cipher.crack(input);
          if let Some(best) = results.first() {
            Ok(best.plaintext.as_bytes().to_vec())
          } else {
            Err("Could not crack cipher".to_string())
          }
        }
      };
    }

    Err(format!("Unknown operation: {}", op.name))
  }

  /// Parse cipher key from arguments
  fn parse_cipher_key(
    &self,
    cipher_name: &str,
    args: &std::collections::HashMap<String, String>,
  ) -> Result<CipherKey, String> {
    match cipher_name {
      "caesar" => {
        let shift = args
          .get("shift")
          .or_else(|| args.get("0"))
          .map(|s| s.parse::<i32>())
          .transpose()
          .map_err(|_| "Invalid shift value")?
          .unwrap_or(3);
        Ok(CipherKey::Shift(shift))
      }
      "rot13" | "rot47" | "rot5" | "atbash" => Ok(CipherKey::None),
      "vigenere" => {
        let key = args
          .get("key")
          .or_else(|| args.get("0"))
          .ok_or("Vigenère cipher requires a key")?;
        Ok(CipherKey::Text(key.clone()))
      }
      "xor" => {
        let key = args
          .get("key")
          .or_else(|| args.get("0"))
          .ok_or("XOR cipher requires a key")?;

        // Parse key as hex or string
        let key_bytes = if key.starts_with("0x") {
          let hex = &key[2..];
          hex
            .as_bytes()
            .chunks(2)
            .map(|chunk| {
              let s = std::str::from_utf8(chunk).unwrap_or("00");
              u8::from_str_radix(s, 16).unwrap_or(0)
            })
            .collect()
        } else {
          key.as_bytes().to_vec()
        };

        Ok(CipherKey::Bytes(key_bytes))
      }
      "affine" => {
        let a = args
          .get("a")
          .map(|s| s.parse::<i32>())
          .transpose()
          .map_err(|_| "Invalid 'a' value")?
          .unwrap_or(5);
        let b = args
          .get("b")
          .map(|s| s.parse::<i32>())
          .transpose()
          .map_err(|_| "Invalid 'b' value")?
          .unwrap_or(8);
        Ok(CipherKey::Affine(a, b))
      }
      "railfence" => {
        let rails = args
          .get("rails")
          .or_else(|| args.get("0"))
          .map(|s| s.parse::<usize>())
          .transpose()
          .map_err(|_| "Invalid rails value")?
          .unwrap_or(3);
        Ok(CipherKey::Rails(rails))
      }
      _ => {
        // Default to no key
        Ok(CipherKey::None)
      }
    }
  }

  /// Execute a recipe string directly
  pub fn execute_string(&self, recipe_str: &str, input: &[u8]) -> ExecutionResult {
    match super::parser::RecipeParser::parse(recipe_str) {
      Ok(recipe) => self.execute(&recipe, input),
      Err(e) => ExecutionResult {
        input: input.to_vec(),
        output: Vec::new(),
        steps: Vec::new(),
        success: false,
        error: Some(e),
      },
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_execute_base64_decode() {
    let executor = RecipeExecutor::new();
    let result = executor.execute_string("base64_decode", b"SGVsbG8gV29ybGQ=");

    assert!(result.success);
    assert_eq!(result.output, b"Hello World");
  }

  #[test]
  fn test_execute_chain() {
    let executor = RecipeExecutor::new();
    // Encode to hex, then base64
    let result = executor.execute_string("hex_encode | base64_encode", b"Hi");

    assert!(result.success);
    assert_eq!(result.steps.len(), 2);

    // Reverse it
    let reversed = executor.execute_string("base64_decode | hex_decode", &result.output);
    assert!(reversed.success);
    assert_eq!(reversed.output, b"Hi");
  }

  #[test]
  fn test_execute_cipher() {
    let executor = RecipeExecutor::new();
    let result = executor.execute_string("caesar_encrypt(shift=3)", b"HELLO");

    assert!(result.success);
    assert_eq!(result.output, b"KHOOR");

    // Decrypt
    let decrypted = executor.execute_string("caesar_decrypt(shift=3)", &result.output);
    assert!(decrypted.success);
    assert_eq!(decrypted.output, b"HELLO");
  }

  #[test]
  fn test_execute_rot13() {
    let executor = RecipeExecutor::new();
    let result = executor.execute_string("rot13", b"Hello");

    assert!(result.success);
    assert_eq!(result.output, b"Uryyb");
  }

  #[test]
  fn test_execute_xor() {
    let executor = RecipeExecutor::new();
    let result = executor.execute_string("xor_encrypt(key=0x42)", b"Hello");

    assert!(result.success);

    // XOR is self-inverse
    let decrypted = executor.execute_string("xor_decrypt(key=0x42)", &result.output);
    assert!(decrypted.success);
    assert_eq!(decrypted.output, b"Hello");
  }

  #[test]
  fn test_execute_unknown_operation() {
    let executor = RecipeExecutor::new();
    let result = executor.execute_string("nonexistent_codec", b"test");

    assert!(!result.success);
    assert!(result.error.is_some());
  }
}
