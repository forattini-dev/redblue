//! Helper functions for HAR module

use super::types::HarQueryParam;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current time as ISO 8601 string
pub fn iso8601_now() -> String {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default();

  let secs = now.as_secs();
  let millis = now.subsec_millis();

  // Convert to date/time components (simplified, assumes UTC)
  let days_since_epoch = secs / 86400;
  let time_of_day = secs % 86400;

  let hours = time_of_day / 3600;
  let minutes = (time_of_day % 3600) / 60;
  let seconds = time_of_day % 60;

  // Calculate year/month/day from days since epoch (1970-01-01)
  let (year, month, day) = days_to_ymd(days_since_epoch);

  format!(
    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
    year, month, day, hours, minutes, seconds, millis
  )
}

/// Convert days since Unix epoch to year/month/day
pub fn days_to_ymd(days: u64) -> (u32, u32, u32) {
  let mut remaining = days as i64;
  let mut year = 1970i32;

  loop {
    let days_in_year = if is_leap_year(year) { 366 } else { 365 };
    if remaining < days_in_year {
      break;
    }
    remaining -= days_in_year;
    year += 1;
  }

  let leap = is_leap_year(year);
  let days_in_months: [i64; 12] = if leap {
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  } else {
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  };

  let mut month = 1u32;
  for days_in_month in &days_in_months {
    if remaining < *days_in_month {
      break;
    }
    remaining -= *days_in_month;
    month += 1;
  }

  (year as u32, month, (remaining + 1) as u32)
}

/// Check if a year is a leap year
pub fn is_leap_year(year: i32) -> bool {
  (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Parse URL query string into parameters
pub fn parse_query_string(query: &str) -> Vec<HarQueryParam> {
  query
    .split('&')
    .filter(|s| !s.is_empty())
    .map(|pair| {
      let mut parts = pair.splitn(2, '=');
      let name = url_decode(parts.next().unwrap_or(""));
      let value = url_decode(parts.next().unwrap_or(""));
      HarQueryParam {
        name,
        value,
        comment: None,
      }
    })
    .collect()
}

/// URL-decode a string
pub fn url_decode(s: &str) -> String {
  let mut result = String::with_capacity(s.len());
  let mut chars = s.chars();

  while let Some(c) = chars.next() {
    if c == '%' {
      let hex: String = chars.by_ref().take(2).collect();
      if let Ok(byte) = u8::from_str_radix(&hex, 16) {
        result.push(byte as char);
      } else {
        result.push('%');
        result.push_str(&hex);
      }
    } else if c == '+' {
      result.push(' ');
    } else {
      result.push(c);
    }
  }

  result
}

/// Check if content type is text-based
pub fn is_text_content(mime_type: &str) -> bool {
  let text_types = [
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/ld+json",
    "application/xhtml+xml",
  ];

  text_types.iter().any(|t| mime_type.starts_with(t))
}
