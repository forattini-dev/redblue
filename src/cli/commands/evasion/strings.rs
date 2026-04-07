//! Compile-time string encryption command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::evasion::strings;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionStringsCommand;

impl Command for EvasionStringsCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "strings"
  }

  fn description(&self) -> &str {
    "Compile-time string encryption"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "encrypt",
        summary: "Encrypt a string (compile-time style)",
        usage: "rb evasion strings encrypt <string> [--key <n>]",
      },
      Route {
        verb: "sensitive",
        summary: "Show pre-encrypted sensitive strings",
        usage: "rb evasion strings sensitive",
      },
      Route {
        verb: "demo",
        summary: "Demo string encryption types",
        usage: "rb evasion strings demo",
      },
    ]
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("key", "Encryption key (0-255)")
        .with_short('k')
        .with_default("0x5A"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Encrypt string", "rb evasion strings encrypt \"cmd.exe\""),
      ("Show sensitive", "rb evasion strings sensitive"),
      ("Demo types", "rb evasion strings demo"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("encrypt");

    match verb {
      "encrypt" => execute_strings_encrypt(ctx),
      "sensitive" => execute_strings_sensitive(),
      "demo" => execute_strings_demo(),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_strings_encrypt(ctx: &CliContext) -> Result<(), String> {
  let data = ctx.target.as_ref().ok_or("Missing string to encrypt")?;

  let key: u8 = ctx
    .flags
    .get("key")
    .and_then(|s| {
      if s.starts_with("0x") || s.starts_with("0X") {
        u8::from_str_radix(&s[2..], 16).ok()
      } else {
        s.parse().ok()
      }
    })
    .unwrap_or(0x5A);

  Output::header("String Encryption");
  println!();

  // Encrypt the plaintext manually
  let encrypted_bytes: Vec<u8> = data.bytes().map(|b| b ^ key).collect();
  let encrypted = strings::EncryptedString::new(&encrypted_bytes, key);

  Output::item("Original", data);
  Output::item("Key", &format!("0x{:02X}", key));

  let hex: String = encrypted
    .encrypted_bytes()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
  Output::item("Encrypted (hex)", &hex);

  let recovered = encrypted.decrypt();
  Output::item("Decrypted", &recovered);

  println!();
  Output::info("Rust code to embed:");
  println!(
    "    const ENCRYPTED: &[u8] = &[{}];",
    encrypted
      .encrypted_bytes()
      .iter()
      .map(|b| format!("0x{:02x}", b))
      .collect::<Vec<_>>()
      .join(", ")
  );
  println!("    const KEY: u8 = 0x{:02X};", key);
  println!("    let s = EncryptedString::new(ENCRYPTED, KEY).decrypt();");

  Ok(())
}

fn execute_strings_sensitive() -> Result<(), String> {
  Output::header("Pre-Encrypted Sensitive Strings");
  println!();

  Output::info("Common strings that would trigger AV if plaintext:");
  println!();

  println!(
    "    cmd_exe:         \"{}\"",
    strings::SensitiveStrings::cmd_exe().decrypt_with_build_key()
  );
  println!(
    "    powershell:      \"{}\"",
    strings::SensitiveStrings::powershell().decrypt_with_build_key()
  );
  println!(
    "    bash:            \"{}\"",
    strings::SensitiveStrings::bash().decrypt_with_build_key()
  );
  println!(
    "    sh:              \"{}\"",
    strings::SensitiveStrings::sh().decrypt_with_build_key()
  );
  println!(
    "    nc:              \"{}\"",
    strings::SensitiveStrings::nc().decrypt_with_build_key()
  );
  println!(
    "    curl:            \"{}\"",
    strings::SensitiveStrings::curl().decrypt_with_build_key()
  );
  println!(
    "    wget:            \"{}\"",
    strings::SensitiveStrings::wget().decrypt_with_build_key()
  );

  println!();
  Output::info("These strings are stored encrypted and only decrypted at runtime");

  Ok(())
}

fn execute_strings_demo() -> Result<(), String> {
  Output::header("String Encryption Types");
  println!();

  // EncryptedString
  Output::info("1. EncryptedString (heap allocated):");
  let es = strings::EncryptedString::from_plaintext("password123");
  println!("    Original:  password123");
  println!("    Decrypted: {}", es.decrypt_with_build_key());
  println!("    Storage:   Heap (Vec<u8>)");

  println!();

  // StackString
  Output::info("2. StackString (stack allocated):");
  let ss = strings::StackString::new("secret_key");
  println!("    Original:  secret_key");
  println!("    Decrypted: {}", ss.decrypt());
  println!("    Storage:   Stack (encrypted on create)");

  println!();

  // SecureString
  Output::info("3. SecureString (zeroed on drop):");
  let secure = strings::SecureString::new("api_token_xyz");
  println!("    Original:  api_token_xyz");
  println!("    Value:     {}", secure.as_str());
  println!("    Storage:   Heap, zeroed on drop");

  println!();
  Output::success("All strings are XOR encrypted in memory");

  Ok(())
}
