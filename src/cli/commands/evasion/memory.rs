//! Memory encryption and protection command

use super::{GREEN, RESET};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::evasion::{heap_jitter, memory, sleep_encrypt};

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

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let json_support = match verb {
      "encrypt" => crate::cli::schema::JsonSupport::Guaranteed,
      _ => crate::cli::schema::JsonSupport::BestEffort,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(json_support)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
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
      Route {
        verb: "heap",
        summary: "Spray decoy allocations to camouflage heap pattern",
        usage: "rb evasion memory heap [--profile <name>] [--count <n>]",
      },
      Route {
        verb: "sleep",
        summary: "Demo encrypted sleep (encrypt heap, sleep, decrypt)",
        usage: "rb evasion memory sleep [--duration <ms>]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
      Flag::new(
        "profile",
        "Heap jitter profile (browser, nodejs, system, random)",
      )
      .with_short('p')
      .with_default("browser"),
      Flag::new("count", "Number of decoy allocations to spray")
        .with_short('c')
        .with_default("50"),
      Flag::new("duration", "Sleep duration in milliseconds")
        .with_short('d')
        .with_default("3000"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Encrypt string",
        "rb evasion memory encrypt \"password123\"",
      ),
      ("Demo operations", "rb evasion memory demo"),
      ("Rotate key", "rb evasion memory rotate"),
      (
        "Heap camouflage (browser)",
        "rb evasion memory heap --profile browser --count 50",
      ),
      (
        "Heap camouflage (nodejs)",
        "rb evasion memory heap --profile nodejs",
      ),
      (
        "Encrypted sleep 5s",
        "rb evasion memory sleep --duration 5000",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("demo");

    match verb {
      "encrypt" => execute_memory_encrypt(ctx),
      "demo" => execute_memory_demo(),
      "rotate" => execute_memory_rotate(),
      "vault" => execute_memory_vault(),
      "heap" => execute_heap_camouflage(ctx),
      "sleep" => execute_encrypted_sleep(ctx),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_memory_encrypt(ctx: &CliContext) -> Result<(), String> {
  let data = ctx.target.as_ref().ok_or("Missing string to encrypt")?;

  let buf = memory::SecureBuffer::from_data(data.as_bytes());
  let integrity = buf.verify_integrity();
  let encrypted_hex: String = buf
    .encrypted_data()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
  let recovered = buf.read_string();

  let payload = json!({
      "original": data,
      "size": buf.len(),
      "integrity": integrity,
      "encrypted_hex": encrypted_hex,
      "recovered": recovered
  });
  if render::render_machine_output(ctx, "rb evasion memory encrypt", &payload)? {
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

fn execute_heap_camouflage(ctx: &CliContext) -> Result<(), String> {
  let profile_name = ctx
    .flags
    .get("profile")
    .map(|s| s.as_str())
    .unwrap_or("browser");

  let profile = heap_jitter::JitterProfile::from_name(profile_name).ok_or_else(|| {
    format!(
      "Unknown profile '{}'. Available: browser, nodejs, system, random",
      profile_name
    )
  })?;

  let count: usize = ctx
    .flags
    .get("count")
    .and_then(|s| s.parse().ok())
    .unwrap_or(50);

  let machine_output = ctx.wants_machine_output();

  if !machine_output {
    Output::header("Heap Allocation Camouflage");
    println!();
    Output::info(&format!(
      "Profile: {} ({})",
      profile.name(),
      profile_description(profile)
    ));
    Output::info(&format!("Decoys: {}", count));
    println!();
    Output::spinner_start("Spraying heap");
  }

  let mut jitter = heap_jitter::HeapJitter::new(profile);
  jitter.activate();
  let result = jitter.camouflage(count);

  let payload = json!({
      "profile": result.profile,
      "decoys_created": result.decoys_created,
      "total_decoys": result.total_decoys,
      "total_memory_bytes": result.total_memory_bytes,
      "timing_noise_us": result.timing_noise_us,
      "jitter_active": heap_jitter::HeapJitter::is_active(),
  });
  if render::render_machine_output(ctx, "rb evasion memory heap", &payload)? {
    return Ok(());
  }

  Output::spinner_done();
  println!();

  Output::item("Profile", &result.profile);
  Output::item("Decoys sprayed", &result.decoys_created.to_string());
  Output::item(
    "Total decoy memory",
    &format_bytes(result.total_memory_bytes),
  );
  Output::item("Timing noise", &format!("{}us", result.timing_noise_us));

  println!();
  Output::info("How it works:");
  println!("    EDR/AV builds histograms of allocation sizes to fingerprint processes.");
  println!(
    "    Decoy allocations flood the heap with sizes typical of '{}',",
    profile.name()
  );
  println!("    making redblue's allocation pattern indistinguishable from legitimate software.");
  println!();
  Output::info("Allocation jitter also pads every real allocation with random bytes,");
  Output::info("so the same code path produces different sizes each run.");

  println!();
  Output::success("Heap pattern camouflaged.");

  Ok(())
}

fn execute_encrypted_sleep(ctx: &CliContext) -> Result<(), String> {
  let duration_ms: u64 = ctx
    .flags
    .get("duration")
    .and_then(|s| s.parse().ok())
    .unwrap_or(3000);

  let machine_output = ctx.wants_machine_output();

  // Create demo sensitive data
  let mut secret1 = b"API_KEY=sk_live_demo_1234567890abcdef".to_vec();
  let mut secret2 = b"DB_PASSWORD=super_secret_database_pass!".to_vec();
  let mut secret3 = b"BEACON_URL=https://c2.example.com/callback".to_vec();

  if !machine_output {
    Output::header("Encrypted Sleep Demo");
    println!();
    Output::info("Registering sensitive memory regions:");
    println!("    Region 1: {} bytes (API key)", secret1.len());
    println!("    Region 2: {} bytes (DB password)", secret2.len());
    println!("    Region 3: {} bytes (Beacon URL)", secret3.len());
    println!();
  }

  let mut encryptor = sleep_encrypt::SleepEncryptor::new();
  // Safety: the Vecs are not resized or dropped while the encryptor is alive.
  unsafe {
    encryptor.register_vec(&mut secret1);
    encryptor.register_vec(&mut secret2);
    encryptor.register_vec(&mut secret3);
  }

  if !machine_output {
    Output::info("Before sleep (plaintext in memory):");
    println!("    secret1: {}", String::from_utf8_lossy(&secret1));
    println!();

    Output::spinner_start(&format!(
      "Encrypted sleep ({}ms) - memory is ciphertext",
      duration_ms
    ));
  }

  let start = std::time::Instant::now();
  encryptor.encrypted_sleep(std::time::Duration::from_millis(duration_ms));
  let actual_ms = start.elapsed().as_millis() as u64;

  let stats = encryptor.stats();

  let payload = json!({
      "duration_requested_ms": duration_ms,
      "duration_actual_ms": actual_ms,
      "regions": stats.regions,
      "total_bytes_protected": stats.total_bytes,
      "is_encrypted": stats.is_encrypted,
      "total_sleeps": stats.total_sleeps,
      "data_restored": secret1 == b"API_KEY=sk_live_demo_1234567890abcdef",
  });
  if render::render_machine_output(ctx, "rb evasion memory sleep", &payload)? {
    return Ok(());
  }

  Output::spinner_done();
  println!();

  Output::info("After wake (plaintext restored):");
  println!("    secret1: {}", String::from_utf8_lossy(&secret1));
  println!();

  Output::item("Duration", &format!("{}ms", actual_ms));
  Output::item("Regions protected", &stats.regions.to_string());
  Output::item("Bytes encrypted", &format_bytes(stats.total_bytes));
  Output::item(
    "Data integrity",
    if secret1 == b"API_KEY=sk_live_demo_1234567890abcdef" {
      "OK (plaintext restored)"
    } else {
      "CORRUPT"
    },
  );

  println!();
  Output::info("How it works:");
  println!("    Before sleep: all registered memory is XOR-encrypted with a one-time key.");
  println!("    During sleep: memory scanners see only ciphertext. No strings, no keys.");
  println!("    After wake:   data is decrypted and the key is securely zeroed.");
  println!();
  Output::info("Critical for C2 agents: beaconing intervals are idle time where EDR scans memory.");

  println!();
  Output::success("Memory was encrypted during entire sleep period.");

  Ok(())
}

fn format_bytes(bytes: usize) -> String {
  if bytes >= 1024 * 1024 {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
  } else if bytes >= 1024 {
    format!("{:.1} KB", bytes as f64 / 1024.0)
  } else {
    format!("{} bytes", bytes)
  }
}

fn profile_description(profile: heap_jitter::JitterProfile) -> &'static str {
  match profile {
    heap_jitter::JitterProfile::Browser => "mimics Chromium allocation patterns",
    heap_jitter::JitterProfile::NodeJs => "mimics Node.js/V8 heap pages",
    heap_jitter::JitterProfile::SystemService => "mimics system daemon allocations",
    heap_jitter::JitterProfile::Random => "maximum unpredictability",
  }
}
