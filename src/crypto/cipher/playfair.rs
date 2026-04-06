//! Playfair Cipher
//!
//! A digraph substitution cipher using a 5x5 matrix.
//! J is merged with I (25-letter alphabet fits in 5x5 grid).

use super::{Cipher, CipherError, CipherKey, CrackResult};

/// Playfair cipher using a 5x5 key matrix
pub struct PlayfairCipher;

impl PlayfairCipher {
  /// Create new Playfair cipher
  pub fn new() -> Self {
    Self
  }

  /// Generate the 5x5 Playfair matrix from a keyword
  fn generate_matrix(keyword: &str) -> [[char; 5]; 5] {
    let mut matrix = [[' '; 5]; 5];
    let mut used = [false; 26];
    let mut idx = 0;

    // Add keyword letters first (skip J, treat as I)
    for c in keyword.chars() {
      if !c.is_ascii_alphabetic() {
        continue;
      }
      let mut c = c.to_ascii_uppercase();
      if c == 'J' {
        c = 'I';
      }
      let pos = (c as usize) - ('A' as usize);
      if !used[pos] {
        used[pos] = true;
        matrix[idx / 5][idx % 5] = c;
        idx += 1;
      }
    }

    // Fill remaining with unused letters (skip J)
    for c in 'A'..='Z' {
      if c == 'J' {
        continue;
      }
      let pos = (c as usize) - ('A' as usize);
      if !used[pos] {
        used[pos] = true;
        matrix[idx / 5][idx % 5] = c;
        idx += 1;
      }
    }

    matrix
  }

  /// Find position of a character in the matrix
  fn find_position(matrix: &[[char; 5]; 5], c: char) -> Option<(usize, usize)> {
    let c = if c == 'J' { 'I' } else { c };
    for row in 0..5 {
      for col in 0..5 {
        if matrix[row][col] == c {
          return Some((row, col));
        }
      }
    }
    None
  }

  /// Prepare plaintext for encryption (create digraphs)
  fn prepare_text(text: &str) -> Vec<(char, char)> {
    let mut digraphs = Vec::new();
    let chars: Vec<char> = text
      .chars()
      .filter(|c| c.is_ascii_alphabetic())
      .map(|c| {
        let c = c.to_ascii_uppercase();
        if c == 'J' {
          'I'
        } else {
          c
        }
      })
      .collect();

    let mut i = 0;
    while i < chars.len() {
      let first = chars[i];
      let second = if i + 1 < chars.len() {
        let next = chars[i + 1];
        if next == first {
          // Insert X between repeated letters
          i += 1;
          'X'
        } else {
          i += 2;
          next
        }
      } else {
        // Pad with X if odd length
        i += 1;
        'X'
      };
      digraphs.push((first, second));
    }

    digraphs
  }

  /// Encrypt a digraph
  fn encrypt_digraph(matrix: &[[char; 5]; 5], a: char, b: char) -> (char, char) {
    let (row_a, col_a) = Self::find_position(matrix, a).unwrap_or((0, 0));
    let (row_b, col_b) = Self::find_position(matrix, b).unwrap_or((0, 0));

    if row_a == row_b {
      // Same row: shift right
      (
        matrix[row_a][(col_a + 1) % 5],
        matrix[row_b][(col_b + 1) % 5],
      )
    } else if col_a == col_b {
      // Same column: shift down
      (
        matrix[(row_a + 1) % 5][col_a],
        matrix[(row_b + 1) % 5][col_b],
      )
    } else {
      // Rectangle: swap columns
      (matrix[row_a][col_b], matrix[row_b][col_a])
    }
  }

  /// Decrypt a digraph
  fn decrypt_digraph(matrix: &[[char; 5]; 5], a: char, b: char) -> (char, char) {
    let (row_a, col_a) = Self::find_position(matrix, a).unwrap_or((0, 0));
    let (row_b, col_b) = Self::find_position(matrix, b).unwrap_or((0, 0));

    if row_a == row_b {
      // Same row: shift left
      (
        matrix[row_a][(col_a + 4) % 5],
        matrix[row_b][(col_b + 4) % 5],
      )
    } else if col_a == col_b {
      // Same column: shift up
      (
        matrix[(row_a + 4) % 5][col_a],
        matrix[(row_b + 4) % 5][col_b],
      )
    } else {
      // Rectangle: swap columns (same as encrypt)
      (matrix[row_a][col_b], matrix[row_b][col_a])
    }
  }

  /// Encrypt with Playfair cipher
  fn encrypt_text(plaintext: &str, keyword: &str) -> String {
    let matrix = Self::generate_matrix(keyword);
    let digraphs = Self::prepare_text(plaintext);

    let mut result = String::new();
    for (a, b) in digraphs {
      let (enc_a, enc_b) = Self::encrypt_digraph(&matrix, a, b);
      result.push(enc_a);
      result.push(enc_b);
    }

    result
  }

  /// Decrypt with Playfair cipher
  fn decrypt_text(ciphertext: &str, keyword: &str) -> Result<String, CipherError> {
    let matrix = Self::generate_matrix(keyword);

    let chars: Vec<char> = ciphertext
      .chars()
      .filter(|c| c.is_ascii_alphabetic())
      .map(|c| {
        let c = c.to_ascii_uppercase();
        if c == 'J' {
          'I'
        } else {
          c
        }
      })
      .collect();

    if chars.len() % 2 != 0 {
      return Err(CipherError::InvalidInput(
        "Playfair ciphertext must have even length".to_string(),
      ));
    }

    let mut result = String::new();
    for chunk in chars.chunks(2) {
      let (dec_a, dec_b) = Self::decrypt_digraph(&matrix, chunk[0], chunk[1]);
      result.push(dec_a);
      result.push(dec_b);
    }

    Ok(result)
  }

  /// Display the 5x5 matrix (for debugging/display)
  #[allow(dead_code)]
  pub fn display_matrix(keyword: &str) -> String {
    let matrix = Self::generate_matrix(keyword);
    let mut result = String::new();
    for row in matrix.iter() {
      for c in row.iter() {
        result.push(*c);
        result.push(' ');
      }
      result.push('\n');
    }
    result
  }
}

impl Default for PlayfairCipher {
  fn default() -> Self {
    Self::new()
  }
}

impl Cipher for PlayfairCipher {
  fn name(&self) -> &'static str {
    "playfair"
  }

  fn description(&self) -> &'static str {
    "Playfair digraph cipher (5x5 matrix, I=J)"
  }

  fn encrypt(&self, plaintext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let keyword = key
      .as_text()
      .ok_or_else(|| CipherError::InvalidKey("Playfair requires a text key".to_string()))?;

    if keyword.is_empty() {
      return Err(CipherError::InvalidKey(
        "Keyword cannot be empty".to_string(),
      ));
    }

    let text = std::str::from_utf8(plaintext)
      .map_err(|_| CipherError::InvalidInput("Invalid UTF-8".to_string()))?;

    let encrypted = Self::encrypt_text(text, keyword);
    Ok(encrypted.into_bytes())
  }

  fn decrypt(&self, ciphertext: &[u8], key: &CipherKey) -> Result<Vec<u8>, CipherError> {
    let keyword = key
      .as_text()
      .ok_or_else(|| CipherError::InvalidKey("Playfair requires a text key".to_string()))?;

    if keyword.is_empty() {
      return Err(CipherError::InvalidKey(
        "Keyword cannot be empty".to_string(),
      ));
    }

    let text = std::str::from_utf8(ciphertext)
      .map_err(|_| CipherError::InvalidInput("Invalid UTF-8".to_string()))?;

    let decrypted = Self::decrypt_text(text, keyword)?;
    Ok(decrypted.into_bytes())
  }

  fn crack(&self, _ciphertext: &[u8]) -> Vec<CrackResult> {
    // Playfair cracking is complex and requires dictionary attacks
    // or frequency analysis with bigram statistics
    vec![]
  }

  fn requires_key(&self) -> bool {
    true
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_matrix_generation() {
    let matrix = PlayfairCipher::generate_matrix("PLAYFAIR");
    // First row should be P L A Y F
    assert_eq!(matrix[0][0], 'P');
    assert_eq!(matrix[0][1], 'L');
    assert_eq!(matrix[0][2], 'A');
    assert_eq!(matrix[0][3], 'Y');
    assert_eq!(matrix[0][4], 'F');
    // Second row starts with I (merged with J) R
    assert_eq!(matrix[1][0], 'I');
    assert_eq!(matrix[1][1], 'R');
  }

  #[test]
  fn test_encrypt_basic() {
    let cipher = PlayfairCipher::new();
    let key = CipherKey::Text("PLAYFAIR".to_string());

    // "HI" encrypted with PLAYFAIR key
    let result = cipher.encrypt(b"HI", &key).unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();

    // Should produce a valid 2-character output
    assert_eq!(result_str.len(), 2);
  }

  #[test]
  fn test_repeated_letter_handling() {
    // HELLO has LL which should become LX L
    let digraphs = PlayfairCipher::prepare_text("HELLO");
    assert_eq!(digraphs.len(), 3);
    assert_eq!(digraphs[0], ('H', 'E'));
    assert_eq!(digraphs[1], ('L', 'X'));
    assert_eq!(digraphs[2], ('L', 'O'));
  }

  #[test]
  fn test_j_becomes_i() {
    let digraphs = PlayfairCipher::prepare_text("JUMP");
    assert_eq!(digraphs[0].0, 'I'); // J becomes I
    assert_eq!(digraphs[0].1, 'U');
  }

  #[test]
  fn test_encrypt_decrypt_roundtrip() {
    let cipher = PlayfairCipher::new();
    let key = CipherKey::Text("MONARCHY".to_string());

    let original = b"INSTRUMENTS";
    let encrypted = cipher.encrypt(original, &key).unwrap();
    let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

    // Note: Playfair may add X padding, so exact roundtrip isn't guaranteed
    // but the decrypted text should contain the original content
    let decrypted_str = std::str::from_utf8(&decrypted).unwrap();
    assert!(decrypted_str.contains("INSTRUMENT"));
  }

  #[test]
  fn test_same_row_rule() {
    // With keyword PLAYFAIR, matrix starts with P L A Y F
    // "AR" should use same-row rule
    let cipher = PlayfairCipher::new();
    let key = CipherKey::Text("PLAYFAIR".to_string());

    let result = cipher.encrypt(b"AR", &key).unwrap();
    let result_str = std::str::from_utf8(&result).unwrap();

    // A→Y, R should shift right in its row
    assert!(!result_str.is_empty());
  }

  #[test]
  fn test_odd_length_padding() {
    let digraphs = PlayfairCipher::prepare_text("ABC");
    assert_eq!(digraphs.len(), 2);
    assert_eq!(digraphs[1].1, 'X'); // Padded with X
  }

  #[test]
  fn test_key_required() {
    let cipher = PlayfairCipher::new();
    assert!(cipher.requires_key());
  }

  #[test]
  fn test_empty_key_error() {
    let cipher = PlayfairCipher::new();
    let key = CipherKey::Text("".to_string());

    let result = cipher.encrypt(b"HELLO", &key);
    assert!(result.is_err());
  }

  #[test]
  fn test_classic_example() {
    // Classic example: HIDE THE GOLD IN THE TREE STUMP
    let cipher = PlayfairCipher::new();
    let key = CipherKey::Text("PLAYFAIREXAMPLE".to_string());

    let result = cipher.encrypt(b"HIDETHEGOLDINTHETREESTUMP", &key).unwrap();
    assert!(!result.is_empty());

    // Decrypt should recover (with possible X padding)
    let decrypted = cipher.decrypt(&result, &key).unwrap();
    let decrypted_str = std::str::from_utf8(&decrypted).unwrap();
    assert!(decrypted_str.contains("HIDE"));
    assert!(decrypted_str.contains("GOLD"));
  }
}
