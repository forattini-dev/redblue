//! CTF Platform Export
//!
//! Export challenges to various CTF platform formats.

use super::generator::{Challenge, HintMode};

/// Export format selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
  /// CTFd CSV format
  Ctfd,
  /// Facebook CTF JSON format
  Fbctf,
  /// RootTheBox XML format
  Rtb,
  /// Generic JSON format
  Json,
}

impl ExportFormat {
  /// Get file extension
  pub fn extension(&self) -> &'static str {
    match self {
      Self::Ctfd => "csv",
      Self::Fbctf => "json",
      Self::Rtb => "xml",
      Self::Json => "json",
    }
  }

  /// Parse from string
  pub fn from_str(s: &str) -> Option<Self> {
    match s.to_lowercase().as_str() {
      "ctfd" | "csv" => Some(Self::Ctfd),
      "fbctf" | "facebook" => Some(Self::Fbctf),
      "rtb" | "rootthebox" => Some(Self::Rtb),
      "json" => Some(Self::Json),
      _ => None,
    }
  }
}

/// CTFd CSV exporter
pub struct CtfdExporter {
  hint_mode: HintMode,
}

impl CtfdExporter {
  /// Create new exporter
  pub fn new() -> Self {
    Self {
      hint_mode: HintMode::Paid,
    }
  }

  /// Set hint mode
  pub fn with_hint_mode(mut self, mode: HintMode) -> Self {
    self.hint_mode = mode;
    self
  }

  /// Export challenges to CSV
  pub fn export(&self, challenges: &[Challenge]) -> String {
    let mut csv = String::new();

    // Header
    csv.push_str("name,description,category,value,flags,hints,tags\n");

    for challenge in challenges {
      let name = escape_csv(&challenge.title);
      let desc = escape_csv(&challenge.description);
      let category = escape_csv(challenge.category.as_str());
      let value = challenge.get_points();
      let flag = challenge.flag.as_deref().unwrap_or("");

      // Format hints based on mode
      let hints = match self.hint_mode {
        HintMode::None => String::new(),
        HintMode::Free => challenge
          .hints
          .iter()
          .map(|h| format!("\"{}\":0", escape_csv(&h.text)))
          .collect::<Vec<_>>()
          .join(";"),
        HintMode::Paid => challenge
          .hints
          .iter()
          .map(|h| format!("\"{}\":{}", escape_csv(&h.text), h.cost))
          .collect::<Vec<_>>()
          .join(";"),
      };

      let tags = challenge.tags.join(",");

      csv.push_str(&format!(
        "{},{},{},{},{},{},{}\n",
        name, desc, category, value, flag, hints, tags
      ));
    }

    csv
  }
}

impl Default for CtfdExporter {
  fn default() -> Self {
    Self::new()
  }
}

/// Facebook CTF JSON exporter
pub struct FbctfExporter {
  /// Country codes for challenges (FBCTF uses geographic themes)
  countries: Vec<String>,
}

impl FbctfExporter {
  /// Create new exporter
  pub fn new() -> Self {
    Self {
      countries: vec![
        "US".to_string(),
        "GB".to_string(),
        "DE".to_string(),
        "FR".to_string(),
        "JP".to_string(),
        "AU".to_string(),
        "BR".to_string(),
        "IN".to_string(),
        "RU".to_string(),
        "CN".to_string(),
      ],
    }
  }

  /// Export challenges to FBCTF JSON
  pub fn export(&self, challenges: &[Challenge]) -> String {
    let mut json = String::from("{\n  \"levels\": [\n");

    for (i, challenge) in challenges.iter().enumerate() {
      let country = &self.countries[i % self.countries.len()];
      let comma = if i < challenges.len() - 1 { "," } else { "" };

      json.push_str(&format!(
        r#"    {{
      "type": "flag",
      "title": {},
      "description": {},
      "flag": {},
      "country": "{}",
      "category": {},
      "points": {},
      "bonus": 0,
      "penalty": 0,
      "hints": [{}]
    }}{}"#,
        json_string(&challenge.title),
        json_string(&challenge.description),
        json_string(challenge.flag.as_deref().unwrap_or("")),
        country,
        json_string(challenge.category.as_str()),
        challenge.get_points(),
        challenge
          .hints
          .iter()
          .map(|h| json_string(&h.text))
          .collect::<Vec<_>>()
          .join(", "),
        comma
      ));
      json.push('\n');
    }

    json.push_str("  ]\n}");
    json
  }
}

impl Default for FbctfExporter {
  fn default() -> Self {
    Self::new()
  }
}

/// RootTheBox XML exporter
pub struct RtbExporter {
  /// Corporation name
  corporation: String,
}

impl RtbExporter {
  /// Create new exporter
  pub fn new() -> Self {
    Self {
      corporation: "Target Corp".to_string(),
    }
  }

  /// Set corporation name
  pub fn with_corporation(mut self, name: &str) -> Self {
    self.corporation = name.to_string();
    self
  }

  /// Export challenges to RootTheBox XML
  pub fn export(&self, challenges: &[Challenge]) -> String {
    let mut xml = String::from(
      r#"<?xml version="1.0" encoding="UTF-8"?>
<rootthebox>
  <corporations>
    <corporation name=""#,
    );
    xml.push_str(&escape_xml(&self.corporation));
    xml.push_str("\">\n      <boxes>\n");

    // Group by category
    let mut categories: std::collections::HashMap<String, Vec<&Challenge>> =
      std::collections::HashMap::new();
    for challenge in challenges {
      categories
        .entry(challenge.category.as_str().to_string())
        .or_default()
        .push(challenge);
    }

    for (category, cat_challenges) in &categories {
      xml.push_str(&format!(
        "        <box name=\"{}\">\n          <flags>\n",
        escape_xml(category)
      ));

      for challenge in cat_challenges {
        xml.push_str(&format!(
          r#"            <flag type="static">
              <name>{}</name>
              <token>{}</token>
              <value>{}</value>
              <description><![CDATA[{}]]></description>
              <hints>
"#,
          escape_xml(&challenge.title),
          escape_xml(challenge.flag.as_deref().unwrap_or("")),
          challenge.get_points(),
          challenge.description
        ));

        for hint in &challenge.hints {
          xml.push_str(&format!(
            "                <hint cost=\"{}\">{}</hint>\n",
            hint.cost,
            escape_xml(&hint.text)
          ));
        }

        xml.push_str("              </hints>\n            </flag>\n");
      }

      xml.push_str("          </flags>\n        </box>\n");
    }

    xml.push_str("      </boxes>\n    </corporation>\n  </corporations>\n</rootthebox>");
    xml
  }
}

impl Default for RtbExporter {
  fn default() -> Self {
    Self::new()
  }
}

/// Generic JSON exporter
pub fn export_json(challenges: &[Challenge]) -> String {
  let mut json = String::from("{\n  \"challenges\": [\n");

  for (i, challenge) in challenges.iter().enumerate() {
    let comma = if i < challenges.len() - 1 { "," } else { "" };

    let hints_json: String = challenge
      .hints
      .iter()
      .map(|h| {
        format!(
          "{{\"text\": {}, \"cost\": {}}}",
          json_string(&h.text),
          h.cost
        )
      })
      .collect::<Vec<_>>()
      .join(", ");

    let tags_json = challenge
      .tags
      .iter()
      .map(|t| json_string(t))
      .collect::<Vec<_>>()
      .join(", ");

    json.push_str(&format!(
      r#"    {{
      "name": {},
      "title": {},
      "description": {},
      "category": {},
      "difficulty": "{}",
      "points": {},
      "flag": {},
      "hints": [{}],
      "tags": [{}]
    }}{}"#,
      json_string(&challenge.name),
      json_string(&challenge.title),
      json_string(&challenge.description),
      json_string(challenge.category.as_str()),
      challenge.difficulty.as_str(),
      challenge.get_points(),
      json_string(challenge.flag.as_deref().unwrap_or("")),
      hints_json,
      tags_json,
      comma
    ));
    json.push('\n');
  }

  json.push_str("  ]\n}");
  json
}

/// Escape string for CSV
fn escape_csv(s: &str) -> String {
  if s.contains(',') || s.contains('"') || s.contains('\n') {
    format!("\"{}\"", s.replace('"', "\"\""))
  } else {
    s.to_string()
  }
}

/// Create JSON string (with escaping)
fn json_string(s: &str) -> String {
  let escaped = s
    .replace('\\', "\\\\")
    .replace('"', "\\\"")
    .replace('\n', "\\n")
    .replace('\r', "\\r")
    .replace('\t', "\\t");
  format!("\"{}\"", escaped)
}

/// Escape string for XML
fn escape_xml(s: &str) -> String {
  s.replace('&', "&amp;")
    .replace('<', "&lt;")
    .replace('>', "&gt;")
    .replace('"', "&quot;")
    .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::modules::ctf::generator::{ChallengeCategory, ChallengeDifficulty, Hint};

  fn sample_challenges() -> Vec<Challenge> {
    vec![
      Challenge::new("web-sqli", "SQL Injection")
        .with_description("Find the SQL injection vulnerability")
        .with_category(ChallengeCategory::Web)
        .with_difficulty(ChallengeDifficulty::Medium)
        .with_flag("flag{sql_injection_found}")
        .add_hint(Hint::paid("Check the login form", 45))
        .add_tag("sqli"),
      Challenge::new("crypto-rsa", "Weak RSA")
        .with_description("Break the weak RSA key")
        .with_category(ChallengeCategory::Crypto)
        .with_difficulty(ChallengeDifficulty::Hard)
        .with_flag("flag{rsa_broken}")
        .add_hint(Hint::paid("Small prime factor", 70))
        .add_tag("rsa"),
    ]
  }

  #[test]
  fn test_ctfd_export() {
    let challenges = sample_challenges();
    let csv = CtfdExporter::new().export(&challenges);

    assert!(csv.contains("SQL Injection"));
    assert!(csv.contains("flag{sql_injection_found}"));
    assert!(csv.contains("Web"));
  }

  #[test]
  fn test_fbctf_export() {
    let challenges = sample_challenges();
    let json = FbctfExporter::new().export(&challenges);

    assert!(json.contains("\"type\": \"flag\""));
    assert!(json.contains("SQL Injection"));
    assert!(json.contains("\"country\":"));
  }

  #[test]
  fn test_rtb_export() {
    let challenges = sample_challenges();
    let xml = RtbExporter::new().export(&challenges);

    assert!(xml.contains("<?xml version"));
    assert!(xml.contains("<rootthebox>"));
    assert!(xml.contains("<flag type=\"static\">"));
  }

  #[test]
  fn test_json_export() {
    let challenges = sample_challenges();
    let json = export_json(&challenges);

    assert!(json.contains("\"challenges\":"));
    assert!(json.contains("\"name\": \"web-sqli\""));
    assert!(json.contains("\"difficulty\": \"Medium\""));
  }

  #[test]
  fn test_escape_csv() {
    assert_eq!(escape_csv("hello"), "hello");
    assert_eq!(escape_csv("hello,world"), "\"hello,world\"");
    assert_eq!(escape_csv("say \"hi\""), "\"say \"\"hi\"\"\"");
  }

  #[test]
  fn test_escape_xml() {
    assert_eq!(escape_xml("hello"), "hello");
    assert_eq!(escape_xml("<script>"), "&lt;script&gt;");
    assert_eq!(escape_xml("a & b"), "a &amp; b");
  }
}
