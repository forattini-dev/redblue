//! Cipher command - Classical ciphers (Caesar, ROT13, Vigenère, XOR, etc.)

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::crypto::cipher::{CipherKey, CipherRegistry};
use crate::json;
use std::fs;

use super::helpers::hex_encode;

/// Classical cipher command
pub struct CryptoCipherCommand;

impl Command for CryptoCipherCommand {
  fn domain(&self) -> &str {
    "crypto"
  }

  fn resource(&self) -> &str {
    "cipher"
  }

  fn description(&self) -> &str {
    "Classical ciphers (Caesar, ROT13, Vigenère, XOR, Atbash, Affine, Rail Fence)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "encrypt",
        summary: "Encrypt using a classical cipher",
        usage: "rb crypto cipher encrypt <cipher> <input> [--key KEY]",
      },
      Route {
        verb: "decrypt",
        summary: "Decrypt using a classical cipher",
        usage: "rb crypto cipher decrypt <cipher> <input> [--key KEY]",
      },
      Route {
        verb: "crack",
        summary: "Attempt to crack ciphertext",
        usage: "rb crypto cipher crack <cipher> <ciphertext>",
      },
      Route {
        verb: "list",
        summary: "List available ciphers",
        usage: "rb crypto cipher list",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("key", "Cipher key (format depends on cipher)")
        .with_short('k')
        .with_arg("KEY"),
      Flag::new("shift", "Shift value for Caesar cipher")
        .with_short('s')
        .with_arg("N"),
      Flag::new("rails", "Number of rails for Rail Fence").with_arg("N"),
      Flag::new("a", "Multiplier for Affine cipher").with_arg("N"),
      Flag::new("b", "Offset for Affine cipher").with_arg("N"),
      Flag::new("format", "Output format (text, json)").with_default("text"),
      Flag::new("file", "Read input from file")
        .with_short('f')
        .with_arg("FILE"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Caesar encrypt",
        "rb crypto cipher encrypt caesar 'HELLO' --shift 3",
      ),
      (
        "Caesar decrypt",
        "rb crypto cipher decrypt caesar 'KHOOR' --shift 3",
      ),
      ("ROT13", "rb crypto cipher encrypt rot13 'Hello World'"),
      (
        "Vigenère encrypt",
        "rb crypto cipher encrypt vigenere 'HELLO' --key SECRET",
      ),
      (
        "XOR with hex key",
        "rb crypto cipher encrypt xor 'Hello' --key 0x42",
      ),
      (
        "Crack Caesar",
        "rb crypto cipher crack caesar 'KHOOR ZRUOG'",
      ),
      ("List ciphers", "rb crypto cipher list"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "encrypt" => self.encrypt(ctx),
      "decrypt" => self.decrypt(ctx),
      "crack" => self.crack(ctx),
      "list" => self.list_ciphers(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!(
        "Unknown verb '{}'. Use: rb crypto cipher help",
        verb
      )),
    }
  }
}

impl CryptoCipherCommand {
  fn get_input(&self, ctx: &CliContext) -> Result<Vec<u8>, String> {
    if let Some(file) = ctx.get_flag("file") {
      fs::read(&file).map_err(|e| format!("Failed to read file '{}': {}", file, e))
    } else if let Some(arg) = ctx.args.first() {
      Ok(arg.as_bytes().to_vec())
    } else {
      Err("No input provided.".to_string())
    }
  }

  fn parse_key(&self, ctx: &CliContext, cipher_name: &str) -> Result<CipherKey, String> {
    match cipher_name {
      "caesar" => {
        let shift = ctx
          .get_flag("shift")
          .or_else(|| ctx.get_flag("key"))
          .map(|s| s.parse::<i32>())
          .transpose()
          .map_err(|_| "Invalid shift value")?
          .unwrap_or(3);
        Ok(CipherKey::Shift(shift))
      }
      "rot13" | "rot47" | "rot5" | "atbash" => Ok(CipherKey::None),
      "vigenere" => {
        let key = ctx
          .get_flag("key")
          .ok_or("Vigenère cipher requires --key")?;
        Ok(CipherKey::Text(key.to_string()))
      }
      "xor" => {
        let key = ctx.get_flag("key").ok_or("XOR cipher requires --key")?;
        // Parse as hex if starts with 0x
        let bytes = if key.starts_with("0x") {
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
        Ok(CipherKey::Bytes(bytes))
      }
      "affine" => {
        let a = ctx
          .get_flag("a")
          .map(|s| s.parse::<i32>())
          .transpose()
          .map_err(|_| "Invalid 'a' value")?
          .unwrap_or(5);
        let b = ctx
          .get_flag("b")
          .map(|s| s.parse::<i32>())
          .transpose()
          .map_err(|_| "Invalid 'b' value")?
          .unwrap_or(8);
        Ok(CipherKey::Affine(a, b))
      }
      "railfence" => {
        let rails = ctx
          .get_flag("rails")
          .or_else(|| ctx.get_flag("key"))
          .map(|s| s.parse::<usize>())
          .transpose()
          .map_err(|_| "Invalid rails value")?
          .unwrap_or(3);
        Ok(CipherKey::Rails(rails))
      }
      "playfair" => {
        let key = ctx
          .get_flag("key")
          .ok_or("Playfair cipher requires --key")?;
        Ok(CipherKey::Text(key.to_string()))
      }
      "bacon" => Ok(CipherKey::None),
      _ => Ok(CipherKey::None),
    }
  }

  fn encrypt(&self, ctx: &CliContext) -> Result<(), String> {
    let cipher_name = ctx
      .target
      .as_ref()
      .ok_or("Missing cipher name. Usage: rb crypto cipher encrypt <cipher> <input>")?;

    let input = self.get_input(ctx)?;
    let key = self.parse_key(ctx, cipher_name)?;

    let registry = CipherRegistry::new();
    let cipher = registry.get(cipher_name).ok_or_else(|| {
      format!(
        "Unknown cipher '{}'. Use 'rb crypto cipher list' to see available ciphers.",
        cipher_name
      )
    })?;

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let encrypted = cipher.encrypt(&input, &key).map_err(|e| e.to_string())?;

    if format == "json" {
      let value = if let Ok(s) = String::from_utf8(encrypted.clone()) {
        json!({
            "cipher": cipher_name,
            "operation": "encrypt",
            "output": s,
        })
      } else {
        json!({
            "cipher": cipher_name,
            "operation": "encrypt",
            "output_hex": hex_encode(&encrypted),
        })
      };
      Output::json_value(&value);
    } else if let Ok(s) = String::from_utf8(encrypted.clone()) {
      println!("{}", s);
    } else {
      println!("{}", hex_encode(&encrypted));
    }

    Ok(())
  }

  fn decrypt(&self, ctx: &CliContext) -> Result<(), String> {
    let cipher_name = ctx
      .target
      .as_ref()
      .ok_or("Missing cipher name. Usage: rb crypto cipher decrypt <cipher> <input>")?;

    let input = self.get_input(ctx)?;
    let key = self.parse_key(ctx, cipher_name)?;

    let registry = CipherRegistry::new();
    let cipher = registry.get(cipher_name).ok_or_else(|| {
      format!(
        "Unknown cipher '{}'. Use 'rb crypto cipher list' to see available ciphers.",
        cipher_name
      )
    })?;

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let decrypted = cipher.decrypt(&input, &key).map_err(|e| e.to_string())?;

    if format == "json" {
      let value = if let Ok(s) = String::from_utf8(decrypted.clone()) {
        json!({
            "cipher": cipher_name,
            "operation": "decrypt",
            "output": s,
        })
      } else {
        json!({
            "cipher": cipher_name,
            "operation": "decrypt",
            "output_hex": hex_encode(&decrypted),
        })
      };
      Output::json_value(&value);
    } else if let Ok(s) = String::from_utf8(decrypted.clone()) {
      println!("{}", s);
    } else {
      println!("{}", hex_encode(&decrypted));
    }

    Ok(())
  }

  fn crack(&self, ctx: &CliContext) -> Result<(), String> {
    let cipher_name = ctx
      .target
      .as_ref()
      .ok_or("Missing cipher name. Usage: rb crypto cipher crack <cipher> <ciphertext>")?;

    let input = self.get_input(ctx)?;

    let registry = CipherRegistry::new();
    let cipher = registry.get(cipher_name).ok_or_else(|| {
      format!(
        "Unknown cipher '{}'. Use 'rb crypto cipher list' to see available ciphers.",
        cipher_name
      )
    })?;

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let results = cipher.crack(&input);

    if format == "json" {
      let results_json: Vec<_> = results
        .iter()
        .map(|result| {
          json!({
              "plaintext": result.plaintext.clone(),
              "key": format!("{:?}", result.key),
              "confidence": result.confidence,
          })
        })
        .collect();
      Output::json_value(&json!(results_json));
    } else {
      Output::header(&format!("Cracking {} cipher", cipher_name));
      println!();
      if results.is_empty() {
        Output::info("No results found.");
      } else {
        for (i, result) in results.iter().enumerate() {
          println!(
            "  #{} ({:.0}% confidence)",
            i + 1,
            result.confidence * 100.0
          );
          println!("     Key: {:?}", result.key);
          println!("     Text: {}", result.plaintext);
          println!();
        }
      }
    }

    Ok(())
  }

  fn list_ciphers(&self, ctx: &CliContext) -> Result<(), String> {
    let registry = CipherRegistry::new();
    let ciphers = registry.list();
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    if format == "json" {
      let ciphers_json: Vec<_> = ciphers
        .iter()
        .filter_map(|name| {
          registry.get(name).map(|cipher| {
            json!({
                "name": name,
                "description": cipher.description(),
            })
          })
        })
        .collect();
      Output::json_value(&json!(ciphers_json));
    } else {
      Output::header("Available Ciphers");
      println!();
      for name in ciphers {
        if let Some(cipher) = registry.get(name) {
          println!("  {:16} {}", name, cipher.description());
        }
      }
    }

    Ok(())
  }
}
