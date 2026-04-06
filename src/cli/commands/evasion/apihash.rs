//! API hashing command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::api_hash;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionApihashCommand;

impl Command for EvasionApihashCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "apihash"
  }

  fn description(&self) -> &str {
    "API hashing for dynamic function resolution"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "hash",
        summary: "Hash an API function name",
        usage: "rb evasion apihash hash <name> [--algo <alg>]",
      },
      Route {
        verb: "list",
        summary: "List pre-computed Windows API hashes",
        usage: "rb evasion apihash list [--dll <name>]",
      },
      Route {
        verb: "syscalls",
        summary: "List Linux syscall numbers",
        usage: "rb evasion apihash syscalls",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("algo", "Hash algorithm (ror13, djb2, fnv1a, crc32)")
        .with_short('a')
        .with_default("ror13"),
      Flag::new("dll", "Filter by DLL name").with_short('d'),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Hash function name", "rb evasion apihash hash LoadLibraryA"),
      (
        "Use DJB2",
        "rb evasion apihash hash VirtualAlloc --algo djb2",
      ),
      (
        "List kernel32 hashes",
        "rb evasion apihash list --dll kernel32",
      ),
      ("List syscalls", "rb evasion apihash syscalls"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("hash");

    match verb {
      "hash" => execute_apihash_hash(ctx),
      "list" => execute_apihash_list(ctx),
      "syscalls" => execute_apihash_syscalls(),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_apihash_hash(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";

  let name = ctx.target.as_ref().ok_or("Missing function name to hash")?;
  let algo = ctx.flags.get("algo").map(|s| s.as_str()).unwrap_or("ror13");

  let hash = match algo {
    "ror13" => api_hash::ror13_hash(name),
    "djb2" => api_hash::djb2_hash(name),
    "fnv1a" => api_hash::fnv1a_hash(name),
    "crc32" => api_hash::crc32_hash(name),
    _ => return Err(format!("Unknown algorithm: {}", algo)),
  };

  if is_json {
    Output::json_value(&json!({
        "function": name,
        "algorithm": algo,
        "hash": hash,
        "hash_hex": format!("0x{:08X}", hash),
        "all_algorithms": json!({
            "ror13": format!("0x{:08X}", api_hash::ror13_hash(name)),
            "djb2": format!("0x{:08X}", api_hash::djb2_hash(name)),
            "fnv1a": format!("0x{:08X}", api_hash::fnv1a_hash(name)),
            "crc32": format!("0x{:08X}", api_hash::crc32_hash(name))
        })
    }));
    return Ok(());
  }

  Output::header("API Hash");
  println!();

  Output::item("Function", name);
  Output::item("Algorithm", algo);

  Output::item("Hash", &format!("0x{:08X}", hash));

  println!();
  Output::info("All algorithms for comparison:");
  println!("    ROR13:  0x{:08X}", api_hash::ror13_hash(name));
  println!("    DJB2:   0x{:08X}", api_hash::djb2_hash(name));
  println!("    FNV-1a: 0x{:08X}", api_hash::fnv1a_hash(name));
  println!("    CRC32:  0x{:08X}", api_hash::crc32_hash(name));

  Ok(())
}

fn execute_apihash_list(ctx: &CliContext) -> Result<(), String> {
  let dll_filter = ctx.flags.get("dll").map(|s| s.to_lowercase());

  Output::header("Pre-computed API Hashes (ROR13)");
  println!();

  let hashes = api_hash::WindowsApiHashes::new(api_hash::HashAlgorithm::Ror13);

  // kernel32
  if dll_filter.is_none() || dll_filter.as_deref() == Some("kernel32") {
    Output::info("kernel32.dll:");
    if let Some(h) = hashes.get_hash("LoadLibraryA") {
      println!("    LoadLibraryA:      0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("GetProcAddress") {
      println!("    GetProcAddress:    0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("VirtualAlloc") {
      println!("    VirtualAlloc:      0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("VirtualProtect") {
      println!("    VirtualProtect:    0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("VirtualFree") {
      println!("    VirtualFree:       0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("CreateThread") {
      println!("    CreateThread:      0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("WaitForSingleObject") {
      println!("    WaitForSingleObj:  0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("CloseHandle") {
      println!("    CloseHandle:       0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("GetModuleHandleA") {
      println!("    GetModuleHandleA:  0x{:08X}", h);
    }
    println!();
  }

  // ntdll
  if dll_filter.is_none() || dll_filter.as_deref() == Some("ntdll") {
    Output::info("ntdll.dll:");
    if let Some(h) = hashes.get_hash("NtAllocateVirtualMemory") {
      println!("    NtAllocateVirtualMemory:  0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("NtProtectVirtualMemory") {
      println!("    NtProtectVirtualMemory:   0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("NtCreateThreadEx") {
      println!("    NtCreateThreadEx:         0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("NtWriteVirtualMemory") {
      println!("    NtWriteVirtualMemory:     0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("RtlMoveMemory") {
      println!("    RtlMoveMemory:            0x{:08X}", h);
    }
    println!();
  }

  // user32
  if dll_filter.is_none() || dll_filter.as_deref() == Some("user32") {
    Output::info("user32.dll:");
    if let Some(h) = hashes.get_hash("MessageBoxA") {
      println!("    MessageBoxA:  0x{:08X}", h);
    }
    println!();
  }

  // advapi32
  if dll_filter.is_none() || dll_filter.as_deref() == Some("advapi32") {
    Output::info("advapi32.dll:");
    if let Some(h) = hashes.get_hash("OpenProcessToken") {
      println!("    OpenProcessToken:      0x{:08X}", h);
    }
    if let Some(h) = hashes.get_hash("AdjustTokenPrivileges") {
      println!("    AdjustTokenPrivileges: 0x{:08X}", h);
    }
    println!();
  }

  Ok(())
}

fn execute_apihash_syscalls() -> Result<(), String> {
  Output::header("Linux Syscalls (x86_64)");
  println!();

  Output::info("Common Syscalls:");
  println!("    read:       {}", api_hash::LinuxSyscalls::SYS_READ);
  println!("    write:      {}", api_hash::LinuxSyscalls::SYS_WRITE);
  println!("    open:       {}", api_hash::LinuxSyscalls::SYS_OPEN);
  println!("    close:      {}", api_hash::LinuxSyscalls::SYS_CLOSE);
  println!("    mmap:       {}", api_hash::LinuxSyscalls::SYS_MMAP);
  println!("    mprotect:   {}", api_hash::LinuxSyscalls::SYS_MPROTECT);
  println!("    munmap:     {}", api_hash::LinuxSyscalls::SYS_MUNMAP);
  println!("    fork:       {}", api_hash::LinuxSyscalls::SYS_FORK);
  println!("    execve:     {}", api_hash::LinuxSyscalls::SYS_EXECVE);
  println!("    exit:       {}", api_hash::LinuxSyscalls::SYS_EXIT);
  println!("    socket:     {}", api_hash::LinuxSyscalls::SYS_SOCKET);
  println!("    connect:    {}", api_hash::LinuxSyscalls::SYS_CONNECT);
  println!("    bind:       {}", api_hash::LinuxSyscalls::SYS_BIND);
  println!("    listen:     {}", api_hash::LinuxSyscalls::SYS_LISTEN);
  println!("    accept:     {}", api_hash::LinuxSyscalls::SYS_ACCEPT);
  println!("    ptrace:     {}", api_hash::LinuxSyscalls::SYS_PTRACE);
  println!("    clone:      {}", api_hash::LinuxSyscalls::SYS_CLONE);
  println!("    getpid:     {}", api_hash::LinuxSyscalls::SYS_GETPID);
  println!("    getuid:     {}", api_hash::LinuxSyscalls::SYS_GETUID);

  Ok(())
}
