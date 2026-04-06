//! HAR Recorder - captures HTTP transactions

use super::helpers::iso8601_now;
use super::types::*;
use std::time::Instant;

/// Timing capture helper
pub struct TimingCapture {
  pub start: Instant,
  pub dns_start: Option<Instant>,
  pub dns_end: Option<Instant>,
  pub connect_start: Option<Instant>,
  pub connect_end: Option<Instant>,
  pub ssl_start: Option<Instant>,
  pub ssl_end: Option<Instant>,
  pub send_start: Option<Instant>,
  pub send_end: Option<Instant>,
  pub wait_start: Option<Instant>,
  pub first_byte: Option<Instant>,
  pub receive_end: Option<Instant>,
}

impl TimingCapture {
  pub fn new() -> Self {
    Self {
      start: Instant::now(),
      dns_start: None,
      dns_end: None,
      connect_start: None,
      connect_end: None,
      ssl_start: None,
      ssl_end: None,
      send_start: None,
      send_end: None,
      wait_start: None,
      first_byte: None,
      receive_end: None,
    }
  }

  pub fn mark_dns_start(&mut self) {
    self.dns_start = Some(Instant::now());
  }

  pub fn mark_dns_end(&mut self) {
    self.dns_end = Some(Instant::now());
  }

  pub fn mark_connect_start(&mut self) {
    self.connect_start = Some(Instant::now());
  }

  pub fn mark_connect_end(&mut self) {
    self.connect_end = Some(Instant::now());
  }

  pub fn mark_ssl_start(&mut self) {
    self.ssl_start = Some(Instant::now());
  }

  pub fn mark_ssl_end(&mut self) {
    self.ssl_end = Some(Instant::now());
  }

  pub fn mark_send_start(&mut self) {
    self.send_start = Some(Instant::now());
  }

  pub fn mark_send_end(&mut self) {
    self.send_end = Some(Instant::now());
  }

  pub fn mark_wait_start(&mut self) {
    self.wait_start = Some(Instant::now());
  }

  pub fn mark_first_byte(&mut self) {
    self.first_byte = Some(Instant::now());
  }

  pub fn mark_receive_end(&mut self) {
    self.receive_end = Some(Instant::now());
  }

  pub fn to_har_timings(&self) -> HarTimings {
    let duration_ms = |start: Option<Instant>, end: Option<Instant>| -> f64 {
      match (start, end) {
        (Some(s), Some(e)) => e.duration_since(s).as_secs_f64() * 1000.0,
        _ => -1.0,
      }
    };

    let blocked = if let Some(dns_start) = self.dns_start {
      dns_start.duration_since(self.start).as_secs_f64() * 1000.0
    } else if let Some(connect_start) = self.connect_start {
      connect_start.duration_since(self.start).as_secs_f64() * 1000.0
    } else {
      -1.0
    };

    HarTimings {
      blocked,
      dns: duration_ms(self.dns_start, self.dns_end),
      connect: duration_ms(self.connect_start, self.connect_end),
      send: duration_ms(self.send_start, self.send_end),
      wait: duration_ms(self.wait_start, self.first_byte),
      receive: duration_ms(self.first_byte, self.receive_end),
      ssl: duration_ms(self.ssl_start, self.ssl_end),
      comment: None,
    }
  }
}

impl Default for TimingCapture {
  fn default() -> Self {
    Self::new()
  }
}

/// HAR Recorder for capturing HTTP sessions
pub struct HarRecorder {
  pub har: Har,
  page_counter: usize,
}

impl HarRecorder {
  pub fn new() -> Self {
    Self {
      har: Har {
        log: HarLog {
          version: "1.2".to_string(),
          creator: HarCreator {
            name: "redblue".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            comment: None,
          },
          browser: None,
          pages: Vec::new(),
          entries: Vec::new(),
          comment: None,
        },
      },
      page_counter: 0,
    }
  }

  pub fn start_page(&mut self, title: &str) -> String {
    self.page_counter += 1;
    let page_id = format!("page_{}", self.page_counter);

    self.har.log.pages.push(HarPage {
      started_date_time: iso8601_now(),
      id: page_id.clone(),
      title: title.to_string(),
      page_timings: HarPageTimings {
        on_content_load: None,
        on_load: None,
        comment: None,
      },
      comment: None,
    });

    page_id
  }

  pub fn add_entry(&mut self, entry: HarEntry) {
    self.har.log.entries.push(entry);
  }

  pub fn save(&self, path: &str) -> Result<(), String> {
    self.har.save_to_file(path)
  }

  pub fn to_json(&self) -> String {
    self.har.to_json()
  }

  pub fn entry_count(&self) -> usize {
    self.har.log.entries.len()
  }
}

impl Default for HarRecorder {
  fn default() -> Self {
    Self::new()
  }
}
