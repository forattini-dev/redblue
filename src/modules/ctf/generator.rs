//! CTF Challenge Generator
//!
//! Generate challenges from security scan findings.

use super::flags::FlagGenerator;
use std::collections::HashMap;

/// Challenge difficulty levels (juice-shop-ctf style)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeDifficulty {
  /// Level 1: Trivial (100 points)
  Trivial,
  /// Level 2: Easy (250 points)
  Easy,
  /// Level 3: Medium (450 points)
  Medium,
  /// Level 4: Hard (700 points)
  Hard,
  /// Level 5: Expert (1000 points)
  Expert,
  /// Level 6: Insane (1350 points)
  Insane,
}

impl ChallengeDifficulty {
  /// Get point value for difficulty
  pub fn points(&self) -> u32 {
    match self {
      Self::Trivial => 100,
      Self::Easy => 250,
      Self::Medium => 450,
      Self::Hard => 700,
      Self::Expert => 1000,
      Self::Insane => 1350,
    }
  }

  /// Get level number (1-6)
  pub fn level(&self) -> u8 {
    match self {
      Self::Trivial => 1,
      Self::Easy => 2,
      Self::Medium => 3,
      Self::Hard => 4,
      Self::Expert => 5,
      Self::Insane => 6,
    }
  }

  /// Create from severity string
  pub fn from_severity(severity: &str) -> Self {
    match severity.to_lowercase().as_str() {
      "info" | "informational" => Self::Trivial,
      "low" => Self::Easy,
      "medium" => Self::Medium,
      "high" => Self::Hard,
      "critical" => Self::Expert,
      _ => Self::Medium,
    }
  }

  /// Get display name
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Trivial => "Trivial",
      Self::Easy => "Easy",
      Self::Medium => "Medium",
      Self::Hard => "Hard",
      Self::Expert => "Expert",
      Self::Insane => "Insane",
    }
  }
}

/// Challenge categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChallengeCategory {
  Web,
  Crypto,
  Forensics,
  Pwn,
  Reverse,
  Misc,
  Network,
  Recon,
  Custom(String),
}

impl ChallengeCategory {
  /// Get display name
  pub fn as_str(&self) -> &str {
    match self {
      Self::Web => "Web",
      Self::Crypto => "Crypto",
      Self::Forensics => "Forensics",
      Self::Pwn => "Pwn",
      Self::Reverse => "Reverse",
      Self::Misc => "Misc",
      Self::Network => "Network",
      Self::Recon => "Recon",
      Self::Custom(s) => s,
    }
  }

  /// Create from string
  pub fn from_str(s: &str) -> Self {
    match s.to_lowercase().as_str() {
      "web" => Self::Web,
      "crypto" | "cryptography" => Self::Crypto,
      "forensics" => Self::Forensics,
      "pwn" | "binary" | "exploitation" => Self::Pwn,
      "reverse" | "reversing" => Self::Reverse,
      "misc" | "miscellaneous" => Self::Misc,
      "network" => Self::Network,
      "recon" | "osint" => Self::Recon,
      _ => Self::Custom(s.to_string()),
    }
  }
}

/// Hint for a challenge
#[derive(Debug, Clone)]
pub struct Hint {
  /// Hint text
  pub text: String,
  /// Cost in points (0 = free)
  pub cost: u32,
}

impl Hint {
  /// Create free hint
  pub fn free(text: &str) -> Self {
    Self {
      text: text.to_string(),
      cost: 0,
    }
  }

  /// Create paid hint
  pub fn paid(text: &str, cost: u32) -> Self {
    Self {
      text: text.to_string(),
      cost,
    }
  }
}

/// CTF Challenge
#[derive(Debug, Clone)]
pub struct Challenge {
  /// Unique challenge name/ID
  pub name: String,
  /// Display title
  pub title: String,
  /// Description (markdown)
  pub description: String,
  /// Category
  pub category: ChallengeCategory,
  /// Difficulty level
  pub difficulty: ChallengeDifficulty,
  /// Point value (can be custom or auto from difficulty)
  pub points: Option<u32>,
  /// Flag value
  pub flag: Option<String>,
  /// Hints
  pub hints: Vec<Hint>,
  /// Tags
  pub tags: Vec<String>,
  /// Source vulnerability (if generated from scan)
  pub source_vuln: Option<String>,
  /// Extra metadata
  pub metadata: HashMap<String, String>,
}

impl Challenge {
  /// Create new challenge
  pub fn new(name: &str, title: &str) -> Self {
    Self {
      name: name.to_string(),
      title: title.to_string(),
      description: String::new(),
      category: ChallengeCategory::Misc,
      difficulty: ChallengeDifficulty::Medium,
      points: None,
      flag: None,
      hints: Vec::new(),
      tags: Vec::new(),
      source_vuln: None,
      metadata: HashMap::new(),
    }
  }

  /// Set description
  pub fn with_description(mut self, desc: &str) -> Self {
    self.description = desc.to_string();
    self
  }

  /// Set category
  pub fn with_category(mut self, category: ChallengeCategory) -> Self {
    self.category = category;
    self
  }

  /// Set difficulty
  pub fn with_difficulty(mut self, difficulty: ChallengeDifficulty) -> Self {
    self.difficulty = difficulty;
    self
  }

  /// Set custom points
  pub fn with_points(mut self, points: u32) -> Self {
    self.points = Some(points);
    self
  }

  /// Set flag
  pub fn with_flag(mut self, flag: &str) -> Self {
    self.flag = Some(flag.to_string());
    self
  }

  /// Add hint
  pub fn add_hint(mut self, hint: Hint) -> Self {
    self.hints.push(hint);
    self
  }

  /// Add tag
  pub fn add_tag(mut self, tag: &str) -> Self {
    self.tags.push(tag.to_string());
    self
  }

  /// Set source vulnerability
  pub fn from_vuln(mut self, vuln_id: &str) -> Self {
    self.source_vuln = Some(vuln_id.to_string());
    self
  }

  /// Add metadata
  pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
    self.metadata.insert(key.to_string(), value.to_string());
    self
  }

  /// Get effective point value
  pub fn get_points(&self) -> u32 {
    self.points.unwrap_or_else(|| self.difficulty.points())
  }
}

/// Hint mode for export
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintMode {
  /// All hints are free
  Free,
  /// Hints cost points (10% of challenge value per hint)
  Paid,
  /// No hints in export
  None,
}

/// Challenge generator from findings
pub struct ChallengeGenerator {
  /// Flag generator
  flag_gen: FlagGenerator,
  /// Hint mode
  hint_mode: HintMode,
  /// Category mapping from vuln types
  category_map: HashMap<String, ChallengeCategory>,
}

impl ChallengeGenerator {
  /// Create new generator
  pub fn new(secret: &[u8]) -> Self {
    let mut category_map = HashMap::new();
    category_map.insert("sqli".to_string(), ChallengeCategory::Web);
    category_map.insert("xss".to_string(), ChallengeCategory::Web);
    category_map.insert("ssti".to_string(), ChallengeCategory::Web);
    category_map.insert("xxe".to_string(), ChallengeCategory::Web);
    category_map.insert("ssrf".to_string(), ChallengeCategory::Web);
    category_map.insert("rce".to_string(), ChallengeCategory::Pwn);
    category_map.insert("lfi".to_string(), ChallengeCategory::Web);
    category_map.insert("buffer_overflow".to_string(), ChallengeCategory::Pwn);
    category_map.insert("crypto".to_string(), ChallengeCategory::Crypto);
    category_map.insert("weak_crypto".to_string(), ChallengeCategory::Crypto);
    category_map.insert("subdomain".to_string(), ChallengeCategory::Recon);
    category_map.insert("info_disclosure".to_string(), ChallengeCategory::Recon);

    Self {
      flag_gen: FlagGenerator::new(secret),
      hint_mode: HintMode::Paid,
      category_map,
    }
  }

  /// Set hint mode
  pub fn with_hint_mode(mut self, mode: HintMode) -> Self {
    self.hint_mode = mode;
    self
  }

  /// Set flag prefix
  pub fn with_flag_prefix(mut self, prefix: &str) -> Self {
    self.flag_gen = self.flag_gen.with_prefix(prefix);
    self
  }

  /// Generate challenge from vulnerability finding
  pub fn from_finding(&self, finding: &Finding) -> Challenge {
    let name = slugify(&finding.title);
    let category = self
      .category_map
      .get(&finding.vuln_type)
      .cloned()
      .unwrap_or(ChallengeCategory::Misc);
    let difficulty = ChallengeDifficulty::from_severity(&finding.severity);

    let flag = self.flag_gen.generate(&name);

    let mut challenge = Challenge::new(&name, &finding.title)
      .with_description(&finding.description)
      .with_category(category)
      .with_difficulty(difficulty)
      .with_flag(&flag)
      .from_vuln(&finding.id);

    // Add hints from remediation steps
    for (i, step) in finding.remediation.iter().enumerate() {
      let hint_cost = match self.hint_mode {
        HintMode::Free => 0,
        HintMode::Paid => difficulty.points() / 10,
        HintMode::None => continue,
      };
      challenge = challenge.add_hint(Hint {
        text: step.clone(),
        cost: hint_cost * (i as u32 + 1),
      });
    }

    // Add tags
    challenge = challenge.add_tag(&finding.vuln_type);
    if !finding.severity.is_empty() {
      challenge = challenge.add_tag(&finding.severity.to_lowercase());
    }

    challenge
  }

  /// Generate challenges from multiple findings
  pub fn from_findings(&self, findings: &[Finding]) -> Vec<Challenge> {
    findings.iter().map(|f| self.from_finding(f)).collect()
  }
}

/// Security finding (input for challenge generation)
#[derive(Debug, Clone)]
pub struct Finding {
  /// Unique ID
  pub id: String,
  /// Title
  pub title: String,
  /// Description
  pub description: String,
  /// Vulnerability type (sqli, xss, etc.)
  pub vuln_type: String,
  /// Severity (info, low, medium, high, critical)
  pub severity: String,
  /// Remediation steps (become hints)
  pub remediation: Vec<String>,
}

impl Finding {
  /// Create new finding
  pub fn new(id: &str, title: &str) -> Self {
    Self {
      id: id.to_string(),
      title: title.to_string(),
      description: String::new(),
      vuln_type: String::new(),
      severity: "medium".to_string(),
      remediation: Vec::new(),
    }
  }

  /// Set description
  pub fn with_description(mut self, desc: &str) -> Self {
    self.description = desc.to_string();
    self
  }

  /// Set vulnerability type
  pub fn with_vuln_type(mut self, vtype: &str) -> Self {
    self.vuln_type = vtype.to_string();
    self
  }

  /// Set severity
  pub fn with_severity(mut self, severity: &str) -> Self {
    self.severity = severity.to_string();
    self
  }

  /// Add remediation step
  pub fn add_remediation(mut self, step: &str) -> Self {
    self.remediation.push(step.to_string());
    self
  }
}

/// Convert string to slug (URL-safe identifier)
fn slugify(s: &str) -> String {
  s.to_lowercase()
    .chars()
    .map(|c| if c.is_alphanumeric() { c } else { '-' })
    .collect::<String>()
    .split('-')
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("-")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_difficulty_points() {
    assert_eq!(ChallengeDifficulty::Trivial.points(), 100);
    assert_eq!(ChallengeDifficulty::Easy.points(), 250);
    assert_eq!(ChallengeDifficulty::Medium.points(), 450);
    assert_eq!(ChallengeDifficulty::Hard.points(), 700);
    assert_eq!(ChallengeDifficulty::Expert.points(), 1000);
    assert_eq!(ChallengeDifficulty::Insane.points(), 1350);
  }

  #[test]
  fn test_from_severity() {
    assert_eq!(
      ChallengeDifficulty::from_severity("info"),
      ChallengeDifficulty::Trivial
    );
    assert_eq!(
      ChallengeDifficulty::from_severity("critical"),
      ChallengeDifficulty::Expert
    );
  }

  #[test]
  fn test_challenge_creation() {
    let challenge = Challenge::new("sqli-login", "SQL Injection in Login")
      .with_description("Find the SQL injection vulnerability")
      .with_category(ChallengeCategory::Web)
      .with_difficulty(ChallengeDifficulty::Medium)
      .with_flag("flag{test123}")
      .add_hint(Hint::free("Check the login form"));

    assert_eq!(challenge.name, "sqli-login");
    assert_eq!(challenge.get_points(), 450);
    assert_eq!(challenge.hints.len(), 1);
  }

  #[test]
  fn test_generator_from_finding() {
    let gen = ChallengeGenerator::new(b"secret_key");

    let finding = Finding::new("V001", "SQL Injection in Search")
      .with_description("The search parameter is vulnerable to SQL injection")
      .with_vuln_type("sqli")
      .with_severity("high")
      .add_remediation("Use parameterized queries")
      .add_remediation("Validate user input");

    let challenge = gen.from_finding(&finding);

    assert_eq!(challenge.category, ChallengeCategory::Web);
    assert_eq!(challenge.difficulty, ChallengeDifficulty::Hard);
    assert!(challenge.flag.is_some());
    assert_eq!(challenge.hints.len(), 2);
  }

  #[test]
  fn test_slugify() {
    assert_eq!(slugify("Hello World!"), "hello-world");
    assert_eq!(slugify("SQL Injection - Login"), "sql-injection-login");
    assert_eq!(slugify("  Test  123  "), "test-123");
  }
}
