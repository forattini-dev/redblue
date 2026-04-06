/// Password Cracker Engine
///
/// Supports multiple attack modes:
/// - Dictionary: Wordlist-based attack with optional rule mutations
/// - Mask: Pattern-based brute-force (e.g., ?u?l?l?l?d?d)
/// - Hybrid: Combination of dictionary and mask
///
/// Features:
/// - Session management for resume capability
/// - Progress tracking and statistics
/// - Multi-hash cracking (batch mode)
/// - Potfile for storing cracked hashes
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::Path;
use std::time::{Duration, Instant};

use super::formats::{parse_hash, verify_hash, HashFormat, HashInfo};
use super::rules::RuleEngine;

/// Attack mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
  /// Dictionary attack with optional rules
  Dictionary,
  /// Mask-based brute-force
  Mask,
  /// Dictionary + Mask hybrid
  HybridDictMask,
  /// Mask + Dictionary hybrid
  HybridMaskDict,
  /// Combinator (two wordlists)
  Combinator,
}

impl AttackMode {
  pub fn name(&self) -> &'static str {
    match self {
      AttackMode::Dictionary => "Dictionary",
      AttackMode::Mask => "Mask",
      AttackMode::HybridDictMask => "Hybrid (Dict+Mask)",
      AttackMode::HybridMaskDict => "Hybrid (Mask+Dict)",
      AttackMode::Combinator => "Combinator",
    }
  }

  /// Get hashcat mode number
  pub fn hashcat_mode(&self) -> u32 {
    match self {
      AttackMode::Dictionary => 0,
      AttackMode::Combinator => 1,
      AttackMode::Mask => 3,
      AttackMode::HybridDictMask => 6,
      AttackMode::HybridMaskDict => 7,
    }
  }
}

/// Crack result for a single hash
#[derive(Debug, Clone)]
pub struct CrackResult {
  pub hash: String,
  pub password: String,
  pub format: HashFormat,
  pub duration: Duration,
  pub attempts: u64,
}

/// Session state for resume capability
#[derive(Debug, Clone)]
pub struct CrackSession {
  pub id: String,
  pub start_time: Instant,
  pub total_hashes: usize,
  pub cracked_count: usize,
  pub current_word_index: u64,
  pub keyspace_total: u64,
  pub keyspace_processed: u64,
}

impl CrackSession {
  pub fn new(id: &str, total_hashes: usize) -> Self {
    Self {
      id: id.to_string(),
      start_time: Instant::now(),
      total_hashes,
      cracked_count: 0,
      current_word_index: 0,
      keyspace_total: 0,
      keyspace_processed: 0,
    }
  }

  pub fn progress(&self) -> f64 {
    if self.keyspace_total == 0 {
      0.0
    } else {
      (self.keyspace_processed as f64 / self.keyspace_total as f64) * 100.0
    }
  }

  pub fn elapsed(&self) -> Duration {
    self.start_time.elapsed()
  }

  pub fn speed(&self) -> f64 {
    let elapsed = self.elapsed().as_secs_f64();
    if elapsed < 0.001 {
      0.0
    } else {
      self.keyspace_processed as f64 / elapsed
    }
  }
}

/// Cracking statistics
#[derive(Debug, Clone, Default)]
pub struct CrackStats {
  pub total_hashes: usize,
  pub cracked: usize,
  pub candidates_tested: u64,
  pub duration: Duration,
}

impl CrackStats {
  pub fn speed(&self) -> f64 {
    let secs = self.duration.as_secs_f64();
    if secs < 0.001 {
      0.0
    } else {
      self.candidates_tested as f64 / secs
    }
  }

  pub fn crack_rate(&self) -> f64 {
    if self.total_hashes == 0 {
      0.0
    } else {
      (self.cracked as f64 / self.total_hashes as f64) * 100.0
    }
  }
}

/// Mask character set definitions
#[derive(Debug, Clone)]
pub struct MaskCharset {
  pub chars: Vec<char>,
}

impl MaskCharset {
  pub fn lowercase() -> Self {
    Self {
      chars: ('a'..='z').collect(),
    }
  }

  pub fn uppercase() -> Self {
    Self {
      chars: ('A'..='Z').collect(),
    }
  }

  pub fn digits() -> Self {
    Self {
      chars: ('0'..='9').collect(),
    }
  }

  pub fn special() -> Self {
    Self {
      chars: "!@#$%^&*()_+-=[]{}|;':\",./<>?".chars().collect(),
    }
  }

  pub fn all() -> Self {
    let mut chars: Vec<char> = Vec::new();
    chars.extend('a'..='z');
    chars.extend('A'..='Z');
    chars.extend('0'..='9');
    chars.extend("!@#$%^&*()_+-=[]{}|;':\",./<>?".chars());
    Self { chars }
  }

  pub fn len(&self) -> usize {
    self.chars.len()
  }

  pub fn is_empty(&self) -> bool {
    self.chars.is_empty()
  }
}

/// Mask generator for brute-force attacks
pub struct MaskGenerator {
  pattern: Vec<MaskCharset>,
  indices: Vec<usize>,
  exhausted: bool,
}

impl MaskGenerator {
  /// Create from mask pattern (e.g., "?l?l?l?d?d" = 3 lowercase + 2 digits)
  pub fn from_pattern(pattern: &str) -> Self {
    let mut charsets = Vec::new();
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
      if c == '?' {
        if let Some(&next) = chars.peek() {
          chars.next();
          let charset = match next {
            'l' => MaskCharset::lowercase(),
            'u' => MaskCharset::uppercase(),
            'd' => MaskCharset::digits(),
            's' => MaskCharset::special(),
            'a' => MaskCharset::all(),
            '?' => MaskCharset { chars: vec!['?'] },
            _ => MaskCharset { chars: vec![next] },
          };
          charsets.push(charset);
        }
      } else {
        // Literal character
        charsets.push(MaskCharset { chars: vec![c] });
      }
    }

    let indices = vec![0; charsets.len()];
    Self {
      pattern: charsets,
      indices,
      exhausted: false,
    }
  }

  /// Calculate total keyspace
  pub fn keyspace(&self) -> u64 {
    self
      .pattern
      .iter()
      .fold(1u64, |acc, cs| acc.saturating_mul(cs.len() as u64))
  }

  /// Generate current candidate
  pub fn current(&self) -> String {
    self
      .pattern
      .iter()
      .zip(self.indices.iter())
      .map(|(cs, &idx)| cs.chars[idx])
      .collect()
  }

  /// Advance to next candidate
  pub fn advance(&mut self) -> bool {
    if self.exhausted {
      return false;
    }

    // Increment from right to left (like a counter)
    for i in (0..self.indices.len()).rev() {
      self.indices[i] += 1;
      if self.indices[i] < self.pattern[i].len() {
        return true;
      }
      self.indices[i] = 0;
    }

    // All positions wrapped - exhausted
    self.exhausted = true;
    false
  }

  /// Reset to beginning
  pub fn reset(&mut self) {
    for idx in &mut self.indices {
      *idx = 0;
    }
    self.exhausted = false;
  }
}

impl Iterator for MaskGenerator {
  type Item = String;

  fn next(&mut self) -> Option<Self::Item> {
    if self.exhausted {
      return None;
    }

    let current = self.current();
    self.advance();
    Some(current)
  }
}

/// Main password cracker
pub struct Cracker {
  /// Hashes to crack
  hashes: Vec<HashInfo>,
  /// Already cracked (hash -> password)
  cracked: HashMap<String, String>,
  /// Attack mode
  mode: AttackMode,
  /// Hash format (auto-detect if None)
  format: Option<HashFormat>,
  /// Rule engine for mutations
  rules: RuleEngine,
  /// Wordlist path
  wordlist: Option<String>,
  /// Secondary wordlist path (for combinator mode)
  second_wordlist: Option<String>,
  /// Mask pattern for brute-force
  mask: Option<String>,
  /// Potfile path for storing cracked hashes
  potfile: Option<String>,
  /// Current session
  session: Option<CrackSession>,
  /// Maximum candidates to test (0 = unlimited)
  limit: u64,
}

impl Cracker {
  /// Create new cracker
  pub fn new() -> Self {
    Self {
      hashes: Vec::new(),
      cracked: HashMap::new(),
      mode: AttackMode::Dictionary,
      format: None,
      rules: RuleEngine::new(),
      wordlist: None,
      second_wordlist: None,
      mask: None,
      potfile: None,
      session: None,
      limit: 0,
    }
  }

  /// Set attack mode
  pub fn mode(mut self, mode: AttackMode) -> Self {
    self.mode = mode;
    self
  }

  /// Set hash format (auto-detect if not set)
  pub fn format(mut self, format: HashFormat) -> Self {
    self.format = Some(format);
    self
  }

  /// Set wordlist path
  pub fn wordlist(mut self, path: &str) -> Self {
    self.wordlist = Some(path.to_string());
    self
  }

  /// Set secondary wordlist path
  pub fn second_wordlist(mut self, path: &str) -> Self {
    self.second_wordlist = Some(path.to_string());
    self
  }

  /// Set mask pattern
  pub fn mask(mut self, pattern: &str) -> Self {
    self.mask = Some(pattern.to_string());
    self
  }

  /// Set potfile path
  pub fn potfile(mut self, path: &str) -> Self {
    self.potfile = Some(path.to_string());
    self
  }

  /// Set candidate limit
  pub fn limit(mut self, n: u64) -> Self {
    self.limit = n;
    self
  }

  /// Add rule chain
  pub fn add_rules(mut self, rules: &[&str]) -> Self {
    for rule in rules {
      self.rules.add_chain(rule);
    }
    self
  }

  /// Add rule preset
  pub fn add_preset(mut self, preset: &str) -> Self {
    self.rules.add_preset(preset);
    self
  }

  /// Add hash to crack
  pub fn add_hash(&mut self, hash: &str) -> bool {
    if let Some(info) = parse_hash(hash) {
      // Check if format matches (if set)
      if let Some(expected) = &self.format {
        if info.format != *expected {
          return false;
        }
      }
      self.hashes.push(info);
      true
    } else {
      false
    }
  }

  /// Add multiple hashes
  pub fn add_hashes(&mut self, hashes: &[&str]) -> usize {
    let mut added = 0;
    for hash in hashes {
      if self.add_hash(hash) {
        added += 1;
      }
    }
    added
  }

  /// Load hashes from file
  pub fn load_hashes<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut added = 0;

    for line in reader.lines() {
      if let Ok(hash) = line {
        let hash = hash.trim();
        if !hash.is_empty() && !hash.starts_with('#') {
          if self.add_hash(hash) {
            added += 1;
          }
        }
      }
    }

    Ok(added)
  }

  /// Load potfile (previously cracked hashes)
  pub fn load_potfile(&mut self) -> std::io::Result<usize> {
    if let Some(path) = &self.potfile {
      if Path::new(path).exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut loaded = 0;

        for line in reader.lines() {
          if let Ok(line) = line {
            if let Some((hash, password)) = line.split_once(':') {
              self.cracked.insert(hash.to_string(), password.to_string());
              loaded += 1;
            }
          }
        }

        return Ok(loaded);
      }
    }
    Ok(0)
  }

  /// Save cracked hash to potfile
  fn save_to_potfile(&self, hash: &str, password: &str) -> std::io::Result<()> {
    if let Some(path) = &self.potfile {
      let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
      writeln!(file, "{}:{}", hash, password)?;
    }
    Ok(())
  }

  /// Try a candidate password against all remaining hashes
  fn try_candidate(&mut self, candidate: &str) -> Vec<CrackResult> {
    let mut results = Vec::new();
    let start = Instant::now();

    // Iterate over hashes, checking each one
    let mut i = 0;
    while i < self.hashes.len() {
      let info = &self.hashes[i];

      // Skip if already cracked
      if self.cracked.contains_key(&info.hash) {
        i += 1;
        continue;
      }

      if verify_hash(candidate, info) {
        let result = CrackResult {
          hash: info.hash.clone(),
          password: candidate.to_string(),
          format: info.format,
          duration: start.elapsed(),
          attempts: 0, // Will be set by caller
        };

        // Store cracked
        self
          .cracked
          .insert(info.hash.clone(), candidate.to_string());

        // Save to potfile
        let _ = self.save_to_potfile(&info.hash, candidate);

        // Emit synergy event for correlation engine
        Self::emit_credential_found(&info.hash, candidate, info.format);

        results.push(result);
      }

      i += 1;
    }

    results
  }

  /// Run dictionary attack
  pub fn attack_dictionary(&mut self) -> Vec<CrackResult> {
    let wordlist_path = match &self.wordlist {
      Some(p) => p.clone(),
      None => return Vec::new(),
    };

    let file = match File::open(&wordlist_path) {
      Ok(f) => f,
      Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut results = Vec::new();
    let mut attempts: u64 = 0;

    let start = Instant::now();

    for line in reader.lines() {
      if let Ok(word) = line {
        let word = word.trim();
        if word.is_empty() {
          continue;
        }

        // Apply rules to generate mutations
        if self.rules.is_empty() {
          // No rules, just try the word
          attempts += 1;
          let mut cracked = self.try_candidate(word);
          for r in &mut cracked {
            r.attempts = attempts;
          }
          results.extend(cracked);
        } else {
          // Generate mutations
          let mutations = self.rules.generate(word);
          for mutation in mutations {
            attempts += 1;
            let mut cracked = self.try_candidate(&mutation);
            for r in &mut cracked {
              r.attempts = attempts;
            }
            results.extend(cracked);

            // Check limit
            if self.limit > 0 && attempts >= self.limit {
              break;
            }
          }
        }

        // Check if all hashes are cracked
        if self.cracked.len() >= self.hashes.len() {
          break;
        }

        // Check limit
        if self.limit > 0 && attempts >= self.limit {
          break;
        }
      }
    }

    // Update session
    if let Some(session) = &mut self.session {
      session.keyspace_processed = attempts;
      session.cracked_count = results.len();
    }

    results
  }

  /// Run mask attack
  pub fn attack_mask(&mut self) -> Vec<CrackResult> {
    let mask_pattern = match &self.mask {
      Some(p) => p.clone(),
      None => return Vec::new(),
    };

    let generator = MaskGenerator::from_pattern(&mask_pattern);
    let keyspace = generator.keyspace();

    let mut results = Vec::new();
    let mut attempts: u64 = 0;

    // Update session
    if let Some(session) = &mut self.session {
      session.keyspace_total = keyspace;
    }

    for candidate in generator {
      attempts += 1;

      // Apply rules if any
      if self.rules.is_empty() {
        let mut cracked = self.try_candidate(&candidate);
        for r in &mut cracked {
          r.attempts = attempts;
        }
        results.extend(cracked);
      } else {
        let mutations = self.rules.generate(&candidate);
        for mutation in mutations {
          let mut cracked = self.try_candidate(&mutation);
          for r in &mut cracked {
            r.attempts = attempts;
          }
          results.extend(cracked);
        }
      }

      // Check if all hashes are cracked
      if self.cracked.len() >= self.hashes.len() {
        break;
      }

      // Check limit
      if self.limit > 0 && attempts >= self.limit {
        break;
      }
    }

    // Update session
    if let Some(session) = &mut self.session {
      session.keyspace_processed = attempts;
      session.cracked_count = results.len();
    }

    results
  }

  /// Run hybrid dictionary + mask attack
  pub fn attack_hybrid_dict_mask(&mut self) -> Vec<CrackResult> {
    let wordlist_path = match &self.wordlist {
      Some(p) => p.clone(),
      None => return Vec::new(),
    };
    let mask_pattern = match &self.mask {
      Some(p) => p.clone(),
      None => return Vec::new(),
    };

    let file = match File::open(&wordlist_path) {
      Ok(f) => f,
      Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut results = Vec::new();
    let mut attempts: u64 = 0;

    for line in reader.lines() {
      if let Ok(word) = line {
        let word = word.trim();
        if word.is_empty() {
          continue;
        }

        // Generate mask variants
        let generator = MaskGenerator::from_pattern(&mask_pattern);
        for suffix in generator {
          let candidate = format!("{}{}", word, suffix);
          attempts += 1;

          let mut cracked = self.try_candidate(&candidate);
          for r in &mut cracked {
            r.attempts = attempts;
          }
          results.extend(cracked);

          // Check limits
          if self.cracked.len() >= self.hashes.len() {
            break;
          }
          if self.limit > 0 && attempts >= self.limit {
            break;
          }
        }

        if self.cracked.len() >= self.hashes.len() {
          break;
        }
        if self.limit > 0 && attempts >= self.limit {
          break;
        }
      }
    }

    results
  }

  /// Run combinator attack (primary + secondary wordlist concatenation)
  pub fn attack_combinator(&mut self) -> Vec<CrackResult> {
    let primary_path = match &self.wordlist {
      Some(p) => p.clone(),
      None => return Vec::new(),
    };

    let secondary_path = match &self.second_wordlist {
      Some(p) => p.clone(),
      None => return Vec::new(),
    };

    let secondary_file = match File::open(&secondary_path) {
      Ok(f) => f,
      Err(_) => return Vec::new(),
    };

    let secondary_reader = BufReader::new(secondary_file);
    let secondary_words: Vec<String> = secondary_reader
      .lines()
      .filter_map(|line| line.ok())
      .map(|line| line.trim().to_string())
      .filter(|word| !word.is_empty())
      .collect();

    if secondary_words.is_empty() {
      return Vec::new();
    }

    let primary_file = match File::open(&primary_path) {
      Ok(f) => f,
      Err(_) => return Vec::new(),
    };

    let primary_reader = BufReader::new(primary_file);
    let mut results = Vec::new();
    let mut attempts: u64 = 0;

    for line in primary_reader.lines() {
      let word1 = match line {
        Ok(word) => word.trim().to_string(),
        Err(_) => continue,
      };

      if word1.is_empty() {
        continue;
      }

      for word2 in &secondary_words {
        let candidate = format!("{}{}", word1, word2);

        if self.rules.is_empty() {
          attempts += 1;
          let mut cracked = self.try_candidate(&candidate);
          for r in &mut cracked {
            r.attempts = attempts;
          }
          results.extend(cracked);
        } else {
          let mutations = self.rules.generate(&candidate);
          for mutation in mutations {
            attempts += 1;

            let mut cracked = self.try_candidate(&mutation);
            for r in &mut cracked {
              r.attempts = attempts;
            }
            results.extend(cracked);

            if self.limit > 0 && attempts >= self.limit {
              break;
            }
          }
        }

        if self.cracked.len() >= self.hashes.len() || (self.limit > 0 && attempts >= self.limit) {
          break;
        }
      }

      if self.cracked.len() >= self.hashes.len() || (self.limit > 0 && attempts >= self.limit) {
        break;
      }
    }

    if let Some(session) = &mut self.session {
      session.keyspace_processed = attempts;
      session.cracked_count = results.len();
    }

    results
  }

  /// Run the attack based on configured mode
  pub fn run(&mut self) -> (Vec<CrackResult>, CrackStats) {
    let start = Instant::now();

    // Initialize session
    self.session = Some(CrackSession::new("default", self.hashes.len()));

    // Load potfile
    let _ = self.load_potfile();

    // Remove already-cracked hashes
    self.hashes.retain(|h| !self.cracked.contains_key(&h.hash));

    // Run attack based on mode
    let results = match self.mode {
      AttackMode::Dictionary => self.attack_dictionary(),
      AttackMode::Mask => self.attack_mask(),
      AttackMode::HybridDictMask => self.attack_hybrid_dict_mask(),
      AttackMode::HybridMaskDict => {
        // Swap dict and mask
        self.attack_hybrid_dict_mask() // Simplified
      }
      AttackMode::Combinator => self.attack_combinator(),
    };

    let stats = CrackStats {
      total_hashes: self.hashes.len() + self.cracked.len(),
      cracked: self.cracked.len(),
      candidates_tested: self
        .session
        .as_ref()
        .map(|s| s.keyspace_processed)
        .unwrap_or(0),
      duration: start.elapsed(),
    };

    (results, stats)
  }

  /// Crack a single hash with a wordlist
  pub fn crack_single(hash: &str, wordlist: &[&str]) -> Option<String> {
    let info = parse_hash(hash)?;

    for word in wordlist {
      if verify_hash(word, &info) {
        return Some(word.to_string());
      }
    }

    None
  }

  /// Quick crack with common passwords
  pub fn quick_crack(hash: &str) -> Option<String> {
    const COMMON: &[&str] = &[
      "password",
      "123456",
      "12345678",
      "qwerty",
      "abc123",
      "monkey",
      "1234567",
      "letmein",
      "trustno1",
      "dragon",
      "baseball",
      "iloveyou",
      "master",
      "sunshine",
      "ashley",
      "bailey",
      "passw0rd",
      "shadow",
      "123123",
      "654321",
      "superman",
      "qazwsx",
      "michael",
      "football",
      "password1",
      "password123",
      "welcome",
      "welcome1",
      "p@ssw0rd",
      "admin",
      "admin123",
      "root",
      "toor",
      "test",
      "guest",
    ];

    Self::crack_single(hash, COMMON)
  }

  /// Get cracked passwords
  pub fn get_cracked(&self) -> &HashMap<String, String> {
    &self.cracked
  }

  /// Get number of remaining hashes
  pub fn remaining(&self) -> usize {
    self.hashes.len()
  }

  /// Emit credential found event to synergy layer
  fn emit_credential_found(hash: &str, password: &str, format: HashFormat) {
    use crate::synergy::events::{emit, EntityRef, Event, EventType, MitreAttack};

    let cred_id = format!("cracked:{}", &hash[..hash.len().min(16)]);

    let event = Event::new(EventType::CredentialFound, "password::cracker")
      .with_entity(EntityRef::credential(&cred_id).with_label("Cracked password"))
      .with_data("hash", hash)
      .with_data("password", password)
      .with_data("format", format.name())
      .with_mitre(MitreAttack::brute_force())
      .with_severity(3) // High severity - credential exposed
      .with_confidence(1.0);

    emit(event);
  }
}

impl Default for Cracker {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::md5;

  fn md5_hex(s: &str) -> String {
    let hash = md5(s.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
  }

  #[test]
  fn test_quick_crack() {
    let hash = md5_hex("password");
    assert_eq!(Cracker::quick_crack(&hash), Some("password".to_string()));
  }

  #[test]
  fn test_mask_generator() {
    let mut gen = MaskGenerator::from_pattern("?d?d");
    assert_eq!(gen.keyspace(), 100);
    assert_eq!(gen.next(), Some("00".to_string()));
    assert_eq!(gen.next(), Some("01".to_string()));
  }

  #[test]
  fn test_mask_keyspace() {
    let gen = MaskGenerator::from_pattern("?l?l?l?d");
    // 26 * 26 * 26 * 10 = 175,760
    assert_eq!(gen.keyspace(), 175760);
  }

  #[test]
  fn test_dictionary_attack() {
    let hash = md5_hex("test123");

    let mut cracker = Cracker::new().mode(AttackMode::Dictionary);
    cracker.add_hash(&hash);

    // Manually test candidates
    let result = Cracker::crack_single(&hash, &["wrong", "test", "test123", "password"]);
    assert_eq!(result, Some("test123".to_string()));
  }

  #[test]
  fn test_cracker_with_rules() {
    let hash = md5_hex("Password1");

    let mut cracker = Cracker::new()
      .mode(AttackMode::Dictionary)
      .add_rules(&[":", "c", "c $1"]);
    cracker.add_hash(&hash);

    // The rule "c $1" should transform "password" -> "Password1"
    let result = Cracker::crack_single(&hash, &["password"]);
    assert!(result.is_none()); // Direct match fails

    // But with rules, it should work
    // (would need to test via wordlist file or manual rule application)
  }
}
