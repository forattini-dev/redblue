//! Boyer-Moore search algorithm for hex editing
//!
//! Provides efficient pattern searching in large buffers with:
//! - Bad character table for character skipping
//! - Simplified good suffix optimization
//! - Support for hex patterns and text patterns

use super::buffer::PagedBuffer;
use super::source::SourceResult;

/// Boyer-Moore search implementation
pub struct BoyerMooreSearcher {
  /// Pattern to search for
  pattern: Vec<u8>,

  /// Bad character table (skip values for each byte)
  bad_char: [usize; 256],
}

impl BoyerMooreSearcher {
  /// Create a new searcher for the given pattern
  pub fn new(pattern: &[u8]) -> Self {
    let pat_len = pattern.len();
    let mut bad_char = [pat_len; 256];

    // Build bad character table
    // bad_char[c] = distance from last occurrence of c to end of pattern
    for (i, &byte) in pattern.iter().enumerate() {
      bad_char[byte as usize] = pat_len - 1 - i;
    }

    Self {
      pattern: pattern.to_vec(),
      bad_char,
    }
  }

  /// Search for pattern in buffer starting at offset
  pub fn search(&self, buffer: &mut PagedBuffer, start: u64) -> SourceResult<Option<u64>> {
    let text_len = buffer.size();
    let pat_len = self.pattern.len() as u64;

    if pat_len == 0 || pat_len > text_len - start.min(text_len) {
      return Ok(None);
    }

    let mut i = start + pat_len - 1;

    while i < text_len {
      // Read the window to compare
      let window_start = i + 1 - pat_len;
      let window = buffer.read(window_start, pat_len as usize)?;

      if window.len() < self.pattern.len() {
        break;
      }

      // Compare pattern from right to left
      let mut j = (pat_len - 1) as i64;
      while j >= 0 && window[j as usize] == self.pattern[j as usize] {
        j -= 1;
      }

      if j < 0 {
        // Match found
        return Ok(Some(window_start));
      }

      // Calculate skip using bad character rule
      let bad_skip = self.bad_char[window[j as usize] as usize];
      let skip = if bad_skip > j as usize {
        bad_skip - j as usize
      } else {
        1
      };

      i += skip as u64;
    }

    Ok(None)
  }

  /// Find all occurrences of pattern
  pub fn search_all(&self, buffer: &mut PagedBuffer) -> SourceResult<Vec<u64>> {
    let mut results = Vec::new();
    let mut offset = 0u64;

    while let Some(found) = self.search(buffer, offset)? {
      results.push(found);
      offset = found + 1;

      // Safety limit to prevent infinite loops
      if results.len() > 1_000_000 {
        break;
      }
    }

    Ok(results)
  }

  /// Get pattern length
  pub fn pattern_len(&self) -> usize {
    self.pattern.len()
  }
}

/// Simple byte-by-byte search (fallback for small patterns)
pub fn search_simple(
  buffer: &mut PagedBuffer,
  pattern: &[u8],
  start: u64,
) -> SourceResult<Option<u64>> {
  if pattern.is_empty() {
    return Ok(None);
  }

  let end = buffer.size() - pattern.len() as u64;
  let mut offset = start;

  while offset <= end {
    let data = buffer.read(offset, pattern.len())?;
    if data == pattern {
      return Ok(Some(offset));
    }
    offset += 1;
  }

  Ok(None)
}

/// Search for text pattern (case-insensitive option)
pub fn search_text(
  buffer: &mut PagedBuffer,
  text: &str,
  case_insensitive: bool,
  start: u64,
) -> SourceResult<Option<u64>> {
  let pattern = if case_insensitive {
    text.to_lowercase().into_bytes()
  } else {
    text.as_bytes().to_vec()
  };

  if case_insensitive {
    // Need to search byte by byte for case-insensitive
    let end = buffer.size() - pattern.len() as u64;
    let mut offset = start;

    while offset <= end {
      let data = buffer.read(offset, pattern.len())?;
      let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

      if data_lower == pattern {
        return Ok(Some(offset));
      }
      offset += 1;
    }

    Ok(None)
  } else {
    let searcher = BoyerMooreSearcher::new(&pattern);
    searcher.search(buffer, start)
  }
}

/// Search result with context
#[derive(Debug, Clone)]
pub struct SearchResult {
  /// Offset where match was found
  pub offset: u64,

  /// Matched bytes
  pub matched: Vec<u8>,

  /// Context before match
  pub context_before: Vec<u8>,

  /// Context after match
  pub context_after: Vec<u8>,
}

impl SearchResult {
  /// Get context around a match
  pub fn with_context(
    buffer: &mut PagedBuffer,
    offset: u64,
    match_len: usize,
    context_len: usize,
  ) -> SourceResult<Self> {
    let before_start = offset.saturating_sub(context_len as u64);
    let before_len = (offset - before_start) as usize;

    let matched = buffer.read(offset, match_len)?;
    let context_before = buffer.read(before_start, before_len)?;
    let context_after = buffer.read(offset + match_len as u64, context_len)?;

    Ok(Self {
      offset,
      matched,
      context_before,
      context_after,
    })
  }
}

/// Replace pattern with replacement
pub fn replace(
  buffer: &mut PagedBuffer,
  find: &[u8],
  replace: &[u8],
  start: u64,
) -> SourceResult<Option<u64>> {
  let searcher = BoyerMooreSearcher::new(find);

  if let Some(offset) = searcher.search(buffer, start)? {
    // For same-size replacement, just overwrite
    if find.len() == replace.len() {
      buffer.write(offset, replace)?;
    } else {
      // Different size: currently only support same-size replace
      // for simplicity (resize would require more complex handling)
      return Err(super::source::SourceError::WriteFailed);
    }
    Ok(Some(offset))
  } else {
    Ok(None)
  }
}

/// Replace all occurrences of pattern
pub fn replace_all(buffer: &mut PagedBuffer, find: &[u8], replace: &[u8]) -> SourceResult<usize> {
  if find.len() != replace.len() {
    return Err(super::source::SourceError::WriteFailed);
  }

  let mut count = 0;
  let mut offset = 0u64;

  while let Some(found) = {
    let searcher = BoyerMooreSearcher::new(find);
    searcher.search(buffer, offset)?
  } {
    buffer.write(found, replace)?;
    count += 1;
    offset = found + replace.len() as u64;

    // Safety limit
    if count > 1_000_000 {
      break;
    }
  }

  Ok(count)
}

#[cfg(test)]
mod tests {
  use super::super::source::BufferSource;
  use super::*;

  #[test]
  fn test_boyer_moore_search() {
    let data = b"Hello, World! Hello again!".to_vec();
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    let searcher = BoyerMooreSearcher::new(b"World");
    let result = searcher.search(&mut buffer, 0).unwrap();
    assert_eq!(result, Some(7));

    let searcher = BoyerMooreSearcher::new(b"Hello");
    let results = searcher.search_all(&mut buffer).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0], 0);
    assert_eq!(results[1], 14);
  }

  #[test]
  fn test_search_not_found() {
    let data = b"AAAABBBBCCCC".to_vec();
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    let searcher = BoyerMooreSearcher::new(b"XYZ");
    let result = searcher.search(&mut buffer, 0).unwrap();
    assert_eq!(result, None);
  }

  #[test]
  fn test_case_insensitive_search() {
    let data = b"Hello HELLO hello".to_vec();
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    // Case-sensitive should find first only
    let result = search_text(&mut buffer, "Hello", false, 0).unwrap();
    assert_eq!(result, Some(0));

    // Case-insensitive should find first
    let result = search_text(&mut buffer, "hello", true, 0).unwrap();
    assert_eq!(result, Some(0));
  }

  #[test]
  fn test_replace() {
    let data = b"Hello, World!".to_vec();
    let source = Box::new(BufferSource::new(data));
    let mut buffer = PagedBuffer::new(source);

    let result = replace(&mut buffer, b"World", b"Rust!", 0).unwrap();
    assert_eq!(result, Some(7));

    let read = buffer.read(0, 13).unwrap();
    assert_eq!(&read, b"Hello, Rust!!");
  }
}
