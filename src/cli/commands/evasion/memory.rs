//! Memory encryption and protection command

use super::{GREEN, RESET};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::memory;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionMemoryCommand;

impl Command for EvasionMemoryCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "memory"
  }

  fn description(&self) -> &str {
    "Memory encryption and protection techniques"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "encrypt",
        summary: "Encrypt a string in memory",
        usage: "rb evasion memory encrypt <string>",
      },
      Route {
        verb: "demo",
        summary: "Demo secure buffer operations",
        usage: "rb evasion memory demo",
      },
      Route {
        verb: "rotate",
        summary: "Rotate memory encryption key",
        usage: "rb evasion memory rotate",
      },
      Route {
        verb: "vault",
        summary: "Demo SecureVault for protected variable storage",
        usage: "rb evasion memory vault",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![Flag::new("format", "Output format (text, json)")
      .with_short('f')
      .with_default("text")]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Encrypt string",
        "rb evasion memory encrypt \"password123\"",
      ),
      ("Demo operations", "rb evasion memory demo"),
      ("Rotate key", "rb evasion memory rotate"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("demo");

    match verb {
      "encrypt" => execute_memory_encrypt(ctx),
      "demo" => execute_memory_demo(),
      "rotate" => execute_memory_rotate(),
      "vault" => execute_memory_vault(),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_memory_encrypt(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";

  let data = ctx.target.as_ref().ok_or("Missing string to encrypt")?;

  let buf = memory::SecureBuffer::from_data(data.as_bytes());
  let integrity = buf.verify_integrity();
  let encrypted_hex: String = buf
    .encrypted_data()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
  let recovered = buf.read_string();

  if is_json {
    Output::json_value(&json!({
        "original": data,
        "size": buf.len(),
        "integrity": integrity,
        "encrypted_hex": encrypted_hex,
        "recovered": recovered
    }));
    return Ok(());
  }

  Output::header("Memory Encryption");
  println!();

  Output::item("Original", data);
  Output::item("Size", &format!("{} bytes", buf.len()));
  Output::item("Integrity", if integrity { "OK" } else { "CORRUPT" });

  Output::item("Encrypted (hex)", &encrypted_hex);

  // Demonstrate roundtrip
  Output::item("Recovered", &recovered);

  println!();
  Output::info("Memory is encrypted in-place using XOR with rolling key");
  Output::info("Data is zeroed on drop (SecureBuffer::drop)");

  Ok(())
}

fn execute_memory_demo() -> Result<(), String> {
  Output::header("Secure Memory Demo");
  println!();

  // Demo SecureString
  Output::info("1. SecureString:");
  let secure_str = memory::SecureString::new("my_secret_password");
  println!("    Stored: [encrypted in memory]");
  println!("    Length: {} bytes", secure_str.len());
  println!("    Valid: {}", secure_str.is_valid());
  println!("    Recovered: {}", secure_str.get());

  println!();

  // Demo SecureCredential
  Output::info("2. SecureCredential:");
  let cred = memory::SecureCredential::new("admin", "super_secret_123");
  println!("    Username: {}", cred.username());
  println!("    Password: {}", cred.password());
  println!(
    "    Integrity: {}",
    if cred.verify() { "OK" } else { "CORRUPT" }
  );

  println!();

  // Demo MemoryGuard
  Output::info("3. MemoryGuard (overflow detection):");
  let mut guard = memory::MemoryGuard::new(100);
  guard.data_mut()[0] = 0x41;
  println!("    Size: 100 bytes");
  println!("    Guards intact: {}", guard.check_guards());
  println!("    First byte: 0x{:02X}", guard.data()[0]);

  println!();
  Output::success("All memory structures zeroed on drop");

  Ok(())
}

fn execute_memory_rotate() -> Result<(), String> {
  Output::header("Key Rotation");
  println!();

  Output::info("Rotating memory encryption key...");
  memory::rotate_key();
  Output::success("Key rotated");
  println!();
  Output::info("New buffers will use the new key");
  Output::warning("Existing buffers retain their original key");

  Ok(())
}

fn execute_memory_vault() -> Result<(), String> {
  Output::header("SecureVault Demo");
  println!();

  Output::info("SecureVault provides multi-layer protection for sensitive variables:");
  println!("    1. XOR encryption with rotating keys");
  println!("    2. Memory locking (prevents swap to disk)");
  println!("    3. Integrity canaries (detect tampering)");
  println!("    4. Decoy entries (confuse memory forensics)");
  println!("    5. Automatic zeroing on drop");
  println!("    6. Access-time-limited decryption");
  println!();

  // Create vault
  Output::info("Creating SecureVault...");
  let mut vault = memory::SecureVault::new();
  println!("    Vault created with {} decoy entries", 6);
  println!();

  // Store secrets
  Output::info("Storing secrets:");
  vault.store("API_KEY", "sk_live_xyz123456789");
  vault.store("DB_PASSWORD", "super_secret_db_pass!");
  vault.store("JWT_SECRET", "my_jwt_signing_key_here");

  println!("    Stored: API_KEY");
  println!("    Stored: DB_PASSWORD");
  println!("    Stored: JWT_SECRET");
  println!("    Total entries: {}", vault.len());
  println!();

  // Retrieve secrets
  Output::info("Retrieving secrets (temporary decryption):");
  if let Some(api_key) = vault.get("API_KEY") {
    // Note: Display shows [REDACTED], we use as_str() to show it works
    println!("    API_KEY value: {}", api_key.as_str());
    println!("    Display trait: {}", api_key); // Shows [REDACTED]
    println!("    Debug trait: {:?}", api_key); // Shows VaultEntry([REDACTED N bytes])
  }
  println!();

  // Integrity check
  Output::info("Integrity verification:");
  println!("    All entries intact: {}", vault.verify_integrity());
  println!();

  // Lock/unlock demo
  Output::info("Lock/unlock mechanism:");
  println!("    Locking vault (re-encrypts with new key)...");
  vault.lock();
  println!("    Is locked: {}", vault.is_locked());
  println!(
    "    Access while locked: {:?}",
    vault.get("API_KEY").map(|_| "success").unwrap_or("denied")
  );

  println!("    Unlocking vault...");
  vault.unlock();
  println!("    Is locked: {}", vault.is_locked());
  println!(
    "    Access after unlock: {:?}",
    vault.get("API_KEY").map(|_| "success").unwrap_or("denied")
  );
  println!();

  // Usage example
  Output::info("Usage example:");
  println!();
  println!("    {}let mut vault = SecureVault::new();", GREEN);
  println!("    vault.store(\"API_KEY\", \"sk_live_abc123\");");
  println!("    ");
  println!("    // Access with automatic re-encryption after use");
  println!("    if let Some(key) = vault.get(\"API_KEY\") {{");
  println!("        use_api_key(key.as_str());");
  println!("        // key is automatically zeroed when dropped");
  println!("    }}");
  println!("    ");
  println!("    // Lock vault when not needed");
  println!("    vault.lock();{}", RESET);
  println!();

  Output::success("Vault automatically wiped on drop (emergency_wipe)");

  Ok(())
}
