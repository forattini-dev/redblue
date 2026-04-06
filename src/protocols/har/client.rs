//! HTTP Client with HAR Recording

use super::helpers::{is_text_content, iso8601_now, parse_query_string};
use super::recorder::HarRecorder;
use super::types::*;
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// HTTP Client wrapper that records all transactions to HAR format
pub struct HttpClientWithHar {
  client: HttpClient,
  recorder: Arc<Mutex<HarRecorder>>,
  current_page: Option<String>,
}

impl HttpClientWithHar {
  /// Create a new HTTP client with HAR recording enabled
  pub fn new() -> Self {
    Self {
      client: HttpClient::new(),
      recorder: Arc::new(Mutex::new(HarRecorder::new())),
      current_page: None,
    }
  }

  /// Create from an existing HttpClient
  pub fn from_client(client: HttpClient) -> Self {
    Self {
      client,
      recorder: Arc::new(Mutex::new(HarRecorder::new())),
      current_page: None,
    }
  }

  /// Set request timeout
  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.client = self.client.with_timeout(timeout);
    self
  }

  /// Start a new page for grouping entries
  pub fn start_page(&mut self, title: &str) -> String {
    let mut recorder = self.recorder.lock().unwrap();
    let page_id = recorder.start_page(title);
    self.current_page = Some(page_id.clone());
    page_id
  }

  /// Send HTTP request and record to HAR
  pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
    let start_time = iso8601_now();
    let start_instant = Instant::now();

    // Execute the request
    let response = self.client.send(request)?;

    let elapsed = start_instant.elapsed();
    let total_time_ms = elapsed.as_secs_f64() * 1000.0;

    // Create HAR entry
    let entry = self.create_har_entry(request, &response, &start_time, total_time_ms);

    // Record the entry
    let mut recorder = self.recorder.lock().unwrap();
    recorder.add_entry(entry);

    Ok(response)
  }

  /// HTTP GET request with HAR recording
  pub fn get(&self, url: &str) -> Result<HttpResponse, String> {
    let request = HttpRequest::get(url);
    self.send(&request)
  }

  /// HTTP POST request with HAR recording
  pub fn post(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, String> {
    let request = HttpRequest::post(url).with_body(body);
    self.send(&request)
  }

  /// Get the recorded HAR data
  pub fn get_har(&self) -> Har {
    let recorder = self.recorder.lock().unwrap();
    recorder.har.clone()
  }

  /// Get HAR as JSON string
  pub fn to_json(&self) -> String {
    let recorder = self.recorder.lock().unwrap();
    recorder.to_json()
  }

  /// Save HAR to file
  pub fn save_har(&self, path: &str) -> Result<(), String> {
    let recorder = self.recorder.lock().unwrap();
    recorder.save(path)
  }

  /// Get number of recorded entries
  pub fn entry_count(&self) -> usize {
    let recorder = self.recorder.lock().unwrap();
    recorder.entry_count()
  }

  /// Create a HAR entry from request/response
  fn create_har_entry(
    &self,
    request: &HttpRequest,
    response: &HttpResponse,
    start_time: &str,
    total_time_ms: f64,
  ) -> HarEntry {
    // Build full URL
    let url = request.full_url();

    // Extract query string
    let query_string = if let Some(q_pos) = request.path.find('?') {
      parse_query_string(&request.path[q_pos + 1..])
    } else {
      Vec::new()
    };

    // Convert request headers
    let request_headers: Vec<HarHeader> = request
      .headers
      .iter()
      .map(|(k, v)| HarHeader {
        name: k.clone(),
        value: v.clone(),
        comment: None,
      })
      .collect();

    // Convert response headers
    let response_headers: Vec<HarHeader> = response
      .headers
      .iter()
      .map(|(k, v)| HarHeader {
        name: k.clone(),
        value: v.clone(),
        comment: None,
      })
      .collect();

    // Determine content type
    let mime_type = response
      .headers
      .get("content-type")
      .or_else(|| response.headers.get("Content-Type"))
      .cloned()
      .unwrap_or_else(|| "application/octet-stream".to_string());

    // Build post data if present
    let post_data = if !request.body.is_empty() {
      let text = String::from_utf8_lossy(&request.body).to_string();
      let mime = request
        .headers
        .get("content-type")
        .or_else(|| request.headers.get("Content-Type"))
        .cloned()
        .unwrap_or_else(|| "application/octet-stream".to_string());

      Some(HarPostData {
        mime_type: mime,
        params: Vec::new(),
        text,
        comment: None,
      })
    } else {
      None
    };

    // Build response content
    let response_text = if is_text_content(&mime_type) {
      Some(String::from_utf8_lossy(&response.body).to_string())
    } else {
      None
    };

    HarEntry {
      pageref: self.current_page.clone(),
      started_date_time: start_time.to_string(),
      time: total_time_ms,
      request: HarRequest {
        method: request.method.clone(),
        url,
        http_version: request.version.clone(),
        cookies: Vec::new(),
        headers: request_headers,
        query_string,
        post_data,
        headers_size: -1,
        body_size: request.body.len() as i64,
        comment: None,
      },
      response: HarResponse {
        status: response.status_code,
        status_text: response.status_text.clone(),
        http_version: response.version.clone(),
        cookies: Vec::new(),
        headers: response_headers,
        content: HarContent {
          size: response.body.len() as i64,
          compression: None,
          mime_type,
          text: response_text,
          encoding: None,
          comment: None,
        },
        redirect_url: response
          .headers
          .get("location")
          .or_else(|| response.headers.get("Location"))
          .cloned()
          .unwrap_or_default(),
        headers_size: -1,
        body_size: response.body.len() as i64,
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
        send: total_time_ms * 0.1,    // Estimate
        wait: total_time_ms * 0.7,    // Estimate
        receive: total_time_ms * 0.2, // Estimate
        ssl: -1.0,
        comment: None,
      },
      server_ip_address: None,
      connection: None,
      comment: None,
    }
  }
}

impl Default for HttpClientWithHar {
  fn default() -> Self {
    Self::new()
  }
}
