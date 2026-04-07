//! GOT Target Analysis
//!
//! Heuristic analysis of GOT entries to rank the best exploitation targets.
//! For each imported function, determines:
//! - Whether the first argument is likely user-controlled (string input)
//! - What replacement function turns the call into code execution
//! - The difficulty and reliability of the attack

use super::checksec::RelroLevel;
use super::Binary;

/// Priority for a GOT hijacking target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetPriority {
  /// Not useful for GOT hijacking
  None = 0,
  /// Useful for control flow manipulation only
  Low = 1,
  /// Exploitable but requires specific heap/buffer state
  Medium = 2,
  /// High-value target, commonly exploitable
  High = 3,
  /// Ideal target — first argument is almost always user-controlled
  Critical = 4,
}

impl std::fmt::Display for TargetPriority {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::None => write!(f, "none"),
      Self::Low => write!(f, "low"),
      Self::Medium => write!(f, "medium"),
      Self::High => write!(f, "high"),
      Self::Critical => write!(f, "critical"),
    }
  }
}

/// A single GOT entry analysis result.
#[derive(Debug, Clone)]
pub struct GotTarget {
  /// Function name (e.g. "printf")
  pub name: String,
  /// GOT address where the resolved libc pointer lives
  pub got_addr: u64,
  /// PLT stub address (if available)
  pub plt_addr: Option<u64>,
  /// Exploitation priority
  pub priority: TargetPriority,
  /// Recommended replacement function
  pub replace_with: &'static str,
  /// What the hijack achieves
  pub effect: &'static str,
  /// Why this target is useful
  pub rationale: &'static str,
  /// Category of the attack
  pub category: &'static str,
}

/// Full GOT target analysis result.
#[derive(Debug)]
pub struct GotAnalysis {
  /// Whether the binary is exploitable via GOT hijacking
  pub exploitable: bool,
  /// RELRO level detected
  pub relro: RelroLevel,
  /// Ranked targets (best first)
  pub targets: Vec<GotTarget>,
  /// Functions useful for leaking libc addresses
  pub leak_candidates: Vec<LeakCandidate>,
}

/// A function that can be used to leak a libc address from the GOT.
#[derive(Debug, Clone)]
pub struct LeakCandidate {
  /// Function name
  pub name: String,
  /// GOT address to read
  pub got_addr: u64,
  /// How to perform the leak
  pub technique: &'static str,
}

/// Analyze a binary's GOT entries and rank exploitation targets.
pub fn analyze_got_targets(binary: &Binary) -> GotAnalysis {
  let exploitable = binary.security.relro != RelroLevel::Full;
  let mut targets = Vec::new();
  let mut leak_candidates = Vec::new();

  for (name, &got_addr) in &binary.got {
    let plt_addr = binary.plt.get(name).copied();
    let classification = classify_function(name);

    if classification.priority != TargetPriority::None {
      targets.push(GotTarget {
        name: name.clone(),
        got_addr,
        plt_addr,
        priority: classification.priority,
        replace_with: classification.replace_with,
        effect: classification.effect,
        rationale: classification.rationale,
        category: classification.category,
      });
    }

    // Every resolved GOT entry is a leak candidate
    let technique = leak_technique(name);
    if !technique.is_empty() {
      leak_candidates.push(LeakCandidate {
        name: name.clone(),
        got_addr,
        technique,
      });
    }
  }

  // Sort targets by priority (highest first), then alphabetically
  targets.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.name.cmp(&b.name)));

  // Sort leak candidates by usefulness
  leak_candidates.sort_by(|a, b| {
    leak_rank(&b.name)
      .cmp(&leak_rank(&a.name))
      .then(a.name.cmp(&b.name))
  });

  GotAnalysis {
    exploitable,
    relro: binary.security.relro,
    targets,
    leak_candidates,
  }
}

struct FuncClassification {
  priority: TargetPriority,
  replace_with: &'static str,
  effect: &'static str,
  rationale: &'static str,
  category: &'static str,
}

/// Classify a libc function by its exploitability when its GOT entry is hijacked.
fn classify_function(name: &str) -> FuncClassification {
  match name {
    // ── CRITICAL: first arg is almost always user-controlled string ──
    "printf" | "__printf_chk" => FuncClassification {
      priority: TargetPriority::Critical,
      replace_with: "system",
      effect: "printf(user_input) → system(user_input) → shell",
      rationale: "First arg is format string, often user-controlled",
      category: "code execution",
    },

    "puts" => FuncClassification {
      priority: TargetPriority::Critical,
      replace_with: "system",
      effect: "puts(buffer) → system(buffer) → shell if buffer = '/bin/sh'",
      rationale: "First arg is string buffer, commonly contains user data",
      category: "code execution",
    },

    "fprintf" | "__fprintf_chk" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "fprintf(stream, user_input) → system(stream) — need stream = '/bin/sh'",
      rationale: "First arg is FILE*, second is format string; less direct than printf",
      category: "code execution",
    },

    "sprintf" | "snprintf" | "__sprintf_chk" | "__snprintf_chk" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "sprintf(buf, ...) → system(buf) → shell if buf controlled",
      rationale: "First arg is destination buffer, often on stack or heap",
      category: "code execution",
    },

    // ── HIGH: string comparison / manipulation with user input ──
    "strcmp" | "strncmp" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "strcmp(user_input, expected) → system(user_input) → shell",
      rationale: "First arg in auth checks is typically user-provided",
      category: "code execution",
    },

    "strcpy" | "strncpy" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "strcpy(dst, src) → system(dst) → shell if dst controlled",
      rationale: "Destination buffer often writable and controllable",
      category: "code execution",
    },

    "strlen" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "strlen(user_string) → system(user_string) → shell",
      rationale: "Called on user-provided strings for validation",
      category: "code execution",
    },

    "strdup" | "__strdup" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "strdup(input) → system(input) → shell",
      rationale: "Duplicates user-provided strings",
      category: "code execution",
    },

    "strtol" | "strtoul" | "atoi" | "atol" => FuncClassification {
      priority: TargetPriority::High,
      replace_with: "system",
      effect: "atoi(input) → system(input) → shell with numeric input as command",
      rationale: "Parses user-provided numeric strings",
      category: "code execution",
    },

    // ── MEDIUM: heap functions — need control over chunk content ──
    "free" => FuncClassification {
      priority: TargetPriority::Medium,
      replace_with: "system",
      effect: "free(chunk_ptr) → system(chunk_ptr) → shell if chunk starts with '/bin/sh'",
      rationale: "Chunk content must be controlled; common in heap exploits",
      category: "code execution",
    },

    "realloc" => FuncClassification {
      priority: TargetPriority::Medium,
      replace_with: "system",
      effect: "realloc(ptr, size) → system(ptr) → shell if ptr content controlled",
      rationale: "First arg is heap pointer; requires heap content control",
      category: "code execution",
    },

    // ── MEDIUM: I/O functions ──
    "gets" | "fgets" => FuncClassification {
      priority: TargetPriority::Medium,
      replace_with: "system",
      effect: "gets(buf) → system(buf) → shell on second call after buf filled",
      rationale: "Buffer contains user input after the first call",
      category: "code execution",
    },

    "read" => FuncClassification {
      priority: TargetPriority::Medium,
      replace_with: "system",
      effect: "read(fd, buf, n) → system(fd) — fd is int, limited usefulness",
      rationale: "First arg is file descriptor (integer), not ideal for system()",
      category: "code execution",
    },

    "write" => FuncClassification {
      priority: TargetPriority::Medium,
      replace_with: "system",
      effect: "write(fd, buf, n) → system(fd) — same limitation as read()",
      rationale: "Useful for leaking but first arg is fd, not string",
      category: "leak",
    },

    // ── LOW: control flow manipulation ──
    "__stack_chk_fail" => FuncClassification {
      priority: TargetPriority::Low,
      replace_with: "ret (gadget)",
      effect: "Canary check fails → returns normally instead of aborting",
      rationale: "Redirect to a 'ret' gadget to silently bypass stack canary",
      category: "canary bypass",
    },

    "exit" | "_exit" => FuncClassification {
      priority: TargetPriority::Low,
      replace_with: "main / target function",
      effect: "exit() → restart or redirect to attacker-controlled code",
      rationale: "Hijack program termination for persistence or re-exploitation",
      category: "control flow",
    },

    "abort" | "__assert_fail" => FuncClassification {
      priority: TargetPriority::Low,
      replace_with: "ret (gadget)",
      effect: "Error handler bypassed — program continues despite assertion failure",
      rationale: "Prevent crash on error conditions, keep exploit running",
      category: "error bypass",
    },

    "__cxa_finalize" => FuncClassification {
      priority: TargetPriority::Low,
      replace_with: "target function",
      effect: "Destructor hijack — runs attacker code at program shutdown",
      rationale: "Called during library unload; useful for cleanup-stage payloads",
      category: "control flow",
    },

    "setbuf" | "setvbuf" => FuncClassification {
      priority: TargetPriority::Low,
      replace_with: "system",
      effect: "setbuf(stream, buf) → system(stream) — FILE* as arg",
      rationale: "First arg is FILE*, not directly useful as command string",
      category: "code execution",
    },

    // ── Everything else ──
    _ => FuncClassification {
      priority: TargetPriority::None,
      replace_with: "",
      effect: "",
      rationale: "",
      category: "",
    },
  }
}

/// Determine the best technique for leaking an address via this function's GOT entry.
fn leak_technique(name: &str) -> &'static str {
  match name {
    "puts" => "Easiest: call puts(got_entry) via ROP — prints until null byte",
    "printf" | "__printf_chk" => "Format string: %s with GOT addr on stack, or call via ROP",
    "write" => "ROP: call write(1, got_entry, 8) to leak exactly 8 bytes",
    "fprintf" | "__fprintf_chk" => "ROP: call fprintf(stdout, \"%s\", got_entry)",
    "send" => "ROP: call send(sockfd, got_entry, 8, 0) for remote leaks",
    "__libc_start_main" => "Reliable leak target — always resolved, stable offset in libc",
    "read" | "fgets" | "gets" => "GOT entry is readable but function not ideal for output",
    "strlen" | "strcmp" | "strcpy" | "strncmp" | "strncpy" => {
      "GOT entry readable; use puts() or write() via ROP to output the address"
    }
    "malloc" | "calloc" | "realloc" | "free" => {
      "GOT entry readable; leak via output function to compute heap/libc base"
    }
    _ => "",
  }
}

/// Rank a function for leak usefulness (higher = better).
fn leak_rank(name: &str) -> u8 {
  match name {
    "puts" => 10,                                    // easiest to call via ROP
    "write" => 9,                                    // precise: exactly N bytes
    "printf" | "__printf_chk" => 8,                  // needs format string or ROP
    "__libc_start_main" => 7,                        // always present, stable offset
    "fprintf" | "__fprintf_chk" => 6,                // needs stdout + format
    "send" => 5,                                     // remote
    "strlen" | "strcmp" | "strcpy" | "strncmp" => 3, // readable but not output functions
    "malloc" | "free" | "calloc" | "realloc" => 2,   // heap libc pointers
    "read" | "fgets" | "gets" => 1,                  // input functions, low leak value
    _ => 0,
  }
}

/// Format the full analysis as human-readable text.
pub fn format_analysis(analysis: &GotAnalysis) -> String {
  let mut out = String::new();

  // Header
  out.push_str(&format!(
    "GOT Target Analysis  (RELRO: {})\n",
    analysis.relro
  ));

  if !analysis.exploitable {
    out.push_str("\n  Full RELRO — GOT is read-only. GOT hijacking not possible.\n");
    out.push_str("  Consider ret2dlresolve if lazy binding is still active.\n");
    return out;
  }

  out.push_str(&format!(
    "  {} exploitable targets found\n\n",
    analysis.targets.len()
  ));

  // Targets by priority
  if !analysis.targets.is_empty() {
    out.push_str("Hijack Targets (best first):\n\n");

    for target in &analysis.targets {
      out.push_str(&format!(
        "  [{}] {}@got → 0x{:x}\n",
        target.priority, target.name, target.got_addr
      ));
      out.push_str(&format!("    Replace with: {}\n", target.replace_with));
      out.push_str(&format!("    Effect:       {}\n", target.effect));
      out.push_str(&format!("    Rationale:    {}\n", target.rationale));
      out.push_str(&format!("    Category:     {}\n\n", target.category));
    }
  }

  // Leak candidates
  if !analysis.leak_candidates.is_empty() {
    out.push_str("Leak Candidates (read GOT to defeat ASLR):\n\n");

    for candidate in &analysis.leak_candidates {
      out.push_str(&format!(
        "  {}@got → 0x{:x}\n",
        candidate.name, candidate.got_addr
      ));
      out.push_str(&format!("    {}\n\n", candidate.technique));
    }
  }

  out
}

/// Format the analysis as JSON.
pub fn format_analysis_json(analysis: &GotAnalysis) -> String {
  let mut out = String::from("{");

  out.push_str(&format!(
    "\"exploitable\":{},\"relro\":\"{}\",",
    analysis.exploitable, analysis.relro
  ));

  // Targets
  out.push_str("\"targets\":[");
  for (i, t) in analysis.targets.iter().enumerate() {
    if i > 0 {
      out.push(',');
    }
    out.push_str(&format!(
      "{{\"name\":\"{}\",\"got\":\"0x{:x}\",\"priority\":\"{}\",\
       \"replace_with\":\"{}\",\"effect\":{},\"category\":\"{}\"}}",
      t.name,
      t.got_addr,
      t.priority,
      t.replace_with,
      json_escape(t.effect),
      t.category,
    ));
  }
  out.push_str("],");

  // Leak candidates
  out.push_str("\"leak_candidates\":[");
  for (i, c) in analysis.leak_candidates.iter().enumerate() {
    if i > 0 {
      out.push(',');
    }
    out.push_str(&format!(
      "{{\"name\":\"{}\",\"got\":\"0x{:x}\",\"technique\":{}}}",
      c.name,
      c.got_addr,
      json_escape(c.technique),
    ));
  }
  out.push_str("]}");

  out
}

fn json_escape(s: &str) -> String {
  format!(
    "\"{}\"",
    s.replace('\\', "\\\\")
      .replace('"', "\\\"")
      .replace('\n', "\\n")
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_classify_critical_targets() {
    let c = classify_function("printf");
    assert_eq!(c.priority, TargetPriority::Critical);
    assert_eq!(c.replace_with, "system");

    let c = classify_function("puts");
    assert_eq!(c.priority, TargetPriority::Critical);
  }

  #[test]
  fn test_classify_high_targets() {
    for name in ["strcmp", "strlen", "strcpy", "strdup", "atoi", "sprintf"] {
      let c = classify_function(name);
      assert!(
        c.priority >= TargetPriority::High,
        "{} should be High or above, got {:?}",
        name,
        c.priority
      );
    }
  }

  #[test]
  fn test_classify_medium_targets() {
    let c = classify_function("free");
    assert_eq!(c.priority, TargetPriority::Medium);
  }

  #[test]
  fn test_classify_low_targets() {
    let c = classify_function("__stack_chk_fail");
    assert_eq!(c.priority, TargetPriority::Low);
    assert_eq!(c.category, "canary bypass");

    let c = classify_function("exit");
    assert_eq!(c.priority, TargetPriority::Low);
  }

  #[test]
  fn test_classify_unknown_is_none() {
    let c = classify_function("some_random_function");
    assert_eq!(c.priority, TargetPriority::None);
  }

  #[test]
  fn test_leak_rank_ordering() {
    assert!(leak_rank("puts") > leak_rank("write"));
    assert!(leak_rank("write") > leak_rank("printf"));
    assert!(leak_rank("printf") > leak_rank("malloc"));
    assert!(leak_rank("malloc") > leak_rank("unknown_func"));
  }

  #[test]
  fn test_priority_ordering() {
    assert!(TargetPriority::Critical > TargetPriority::High);
    assert!(TargetPriority::High > TargetPriority::Medium);
    assert!(TargetPriority::Medium > TargetPriority::Low);
    assert!(TargetPriority::Low > TargetPriority::None);
  }
}
