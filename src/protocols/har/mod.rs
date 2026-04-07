//! HAR (HTTP Archive) 1.2 Implementation
//! Spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html
//!
//! Provides recording and replay of HTTP transactions
//! with full timing information for analysis.

use std::fs;

// Submodules
mod client;
mod deserialize;
mod helpers;
mod recorder;
mod serialize;
mod types;

// Re-export all types
pub use types::*;

// Re-export serialization
pub use serialize::escape_json_string;

// Re-export deserialization
pub use deserialize::{JsonParser, JsonValue};

// Re-export recorder
pub use recorder::{HarRecorder, TimingCapture};

// Re-export helpers
pub use helpers::{
  days_to_ymd, is_leap_year, is_text_content, iso8601_now, parse_query_string, url_decode,
};

// Re-export client
pub use client::HttpClientWithHar;

// ============================================================================
// File I/O
// ============================================================================

impl Har {
  pub fn save_to_file(&self, path: &str) -> Result<(), String> {
    let json = self.to_json();
    fs::write(path, json).map_err(|e| format!("Failed to write HAR file: {}", e))
  }

  pub fn load_from_file(path: &str) -> Result<Self, String> {
    let json = fs::read_to_string(path).map_err(|e| format!("Failed to read HAR file: {}", e))?;
    Self::from_json(&json)
  }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_json_escape() {
    assert_eq!(escape_json_string("hello"), "hello");
    assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
    assert_eq!(escape_json_string("line1\nline2"), "line1\\nline2");
    assert_eq!(escape_json_string("tab\there"), "tab\\there");
  }

  #[test]
  fn test_har_serialization() {
    let har = Har {
      log: HarLog {
        version: "1.2".to_string(),
        creator: HarCreator {
          name: "test".to_string(),
          version: "1.0".to_string(),
          comment: None,
        },
        browser: None,
        pages: vec![],
        entries: vec![],
        comment: None,
      },
    };

    let json = har.to_json();
    assert!(json.contains("\"version\": \"1.2\""));
    assert!(json.contains("\"name\": \"test\""));
  }

  #[test]
  fn test_har_deserialization() {
    let json = r#"{
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "pages": [],
                "entries": []
            }
        }"#;

    let har = Har::from_json(json).unwrap();
    assert_eq!(har.log.version, "1.2");
    assert_eq!(har.log.creator.name, "test");
  }

  #[test]
  fn test_har_roundtrip() {
    let original = Har {
      log: HarLog {
        version: "1.2".to_string(),
        creator: HarCreator {
          name: "redblue".to_string(),
          version: crate::version::current_version().to_string(),
          comment: Some("Test HAR".to_string()),
        },
        browser: None,
        pages: vec![HarPage {
          started_date_time: "2024-01-01T00:00:00.000Z".to_string(),
          id: "page_1".to_string(),
          title: "Test Page".to_string(),
          page_timings: HarPageTimings {
            on_content_load: Some(100.0),
            on_load: Some(200.0),
            comment: None,
          },
          comment: None,
        }],
        entries: vec![HarEntry {
          pageref: Some("page_1".to_string()),
          started_date_time: "2024-01-01T00:00:00.000Z".to_string(),
          time: 150.0,
          request: HarRequest {
            method: "GET".to_string(),
            url: "https://example.com/test".to_string(),
            http_version: "HTTP/1.1".to_string(),
            cookies: vec![],
            headers: vec![HarHeader {
              name: "Host".to_string(),
              value: "example.com".to_string(),
              comment: None,
            }],
            query_string: vec![],
            post_data: None,
            headers_size: 100,
            body_size: 0,
            comment: None,
          },
          response: HarResponse {
            status: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            cookies: vec![],
            headers: vec![],
            content: HarContent {
              size: 1234,
              compression: None,
              mime_type: "text/html".to_string(),
              text: Some("<html></html>".to_string()),
              encoding: None,
              comment: None,
            },
            redirect_url: "".to_string(),
            headers_size: 200,
            body_size: 1234,
            comment: None,
          },
          cache: HarCache {
            before_request: None,
            after_request: None,
            comment: None,
          },
          timings: HarTimings {
            blocked: 10.0,
            dns: 20.0,
            connect: 30.0,
            send: 5.0,
            wait: 50.0,
            receive: 35.0,
            ssl: 25.0,
            comment: None,
          },
          server_ip_address: Some("93.184.216.34".to_string()),
          connection: None,
          comment: None,
        }],
        comment: None,
      },
    };

    let json = original.to_json();
    let parsed = Har::from_json(&json).unwrap();

    assert_eq!(parsed.log.version, original.log.version);
    assert_eq!(parsed.log.creator.name, original.log.creator.name);
    assert_eq!(parsed.log.pages.len(), original.log.pages.len());
    assert_eq!(parsed.log.entries.len(), original.log.entries.len());

    let entry = &parsed.log.entries[0];
    assert_eq!(entry.request.method, "GET");
    assert_eq!(entry.response.status, 200);
    assert_eq!(entry.timings.wait, 50.0);
  }

  #[test]
  fn test_timing_capture() {
    let mut timing = TimingCapture::new();

    timing.mark_dns_start();
    std::thread::sleep(std::time::Duration::from_millis(10));
    timing.mark_dns_end();

    timing.mark_connect_start();
    std::thread::sleep(std::time::Duration::from_millis(10));
    timing.mark_connect_end();

    let har_timings = timing.to_har_timings();
    assert!(har_timings.dns > 0.0);
    assert!(har_timings.connect > 0.0);
  }

  #[test]
  fn test_query_string_parsing() {
    let params = parse_query_string("foo=bar&baz=qux");
    assert_eq!(params.len(), 2);
    assert_eq!(params[0].name, "foo");
    assert_eq!(params[0].value, "bar");
    assert_eq!(params[1].name, "baz");
    assert_eq!(params[1].value, "qux");
  }

  #[test]
  fn test_url_decode() {
    assert_eq!(url_decode("hello%20world"), "hello world");
    assert_eq!(url_decode("hello+world"), "hello world");
    assert_eq!(url_decode("100%25"), "100%");
  }

  #[test]
  fn test_iso8601_format() {
    let now = iso8601_now();
    assert!(now.contains("T"));
    assert!(now.ends_with("Z"));
    assert_eq!(now.len(), 24); // "YYYY-MM-DDTHH:MM:SS.mmmZ"
  }

  #[test]
  fn test_har_recorder() {
    let mut recorder = HarRecorder::new();

    let page_id = recorder.start_page("Test Page");
    assert_eq!(page_id, "page_1");

    recorder.add_entry(HarEntry {
      pageref: Some(page_id),
      started_date_time: iso8601_now(),
      time: 100.0,
      request: HarRequest {
        method: "GET".to_string(),
        url: "https://example.com".to_string(),
        http_version: "HTTP/1.1".to_string(),
        cookies: vec![],
        headers: vec![],
        query_string: vec![],
        post_data: None,
        headers_size: -1,
        body_size: -1,
        comment: None,
      },
      response: HarResponse {
        status: 200,
        status_text: "OK".to_string(),
        http_version: "HTTP/1.1".to_string(),
        cookies: vec![],
        headers: vec![],
        content: HarContent {
          size: 0,
          compression: None,
          mime_type: "text/html".to_string(),
          text: None,
          encoding: None,
          comment: None,
        },
        redirect_url: "".to_string(),
        headers_size: -1,
        body_size: -1,
        comment: None,
      },
      cache: HarCache {
        before_request: None,
        after_request: None,
        comment: None,
      },
      timings: HarTimings {
        blocked: -1.0,
        dns: -1.0,
        connect: -1.0,
        send: 10.0,
        wait: 80.0,
        receive: 10.0,
        ssl: -1.0,
        comment: None,
      },
      server_ip_address: None,
      connection: None,
      comment: None,
    });

    assert_eq!(recorder.entry_count(), 1);
    assert_eq!(recorder.har.log.pages.len(), 1);
  }
}
