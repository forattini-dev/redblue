use std::collections::HashMap;

/// Parsed HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequest {
  pub method: String,
  pub path: String,
  pub version: String,
  pub headers: HashMap<String, String>,
  pub body: Vec<u8>,
  pub host: String,
  /// Source IP address of the client making this request
  pub client_addr: Option<String>,
}

impl HttpRequest {
  /// Parse HTTP request from bytes
  pub fn parse(data: &[u8]) -> Option<Self> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();

    let request_line = lines.next()?;
    let parts: Vec<_> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
      return None;
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let version = parts[2].to_string();

    let mut headers = HashMap::new();
    let mut host = String::new();

    for line in lines {
      if line.is_empty() {
        break;
      }
      if let Some(colon) = line.find(':') {
        let key = line[..colon].trim().to_lowercase();
        let value = line[colon + 1..].trim().to_string();
        if key == "host" {
          host = value.clone();
        }
        headers.insert(key, value);
      }
    }

    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n");
    let body = if let Some(pos) = header_end {
      data[pos + 4..].to_vec()
    } else {
      Vec::new()
    };

    Some(HttpRequest {
      method,
      path,
      version,
      headers,
      body,
      host,
      client_addr: None,
    })
  }

  pub fn is_websocket_upgrade(&self) -> bool {
    let connection = self
      .headers
      .get("connection")
      .map(|s| s.to_lowercase())
      .unwrap_or_default();
    let upgrade = self
      .headers
      .get("upgrade")
      .map(|s| s.to_lowercase())
      .unwrap_or_default();

    connection.contains("upgrade") && upgrade.contains("websocket")
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(format!("{} {} {}\r\n", self.method, self.path, self.version).as_bytes());

    for (key, value) in &self.headers {
      buf.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }

    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&self.body);
    buf
  }
}

/// Parsed HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
  pub version: String,
  pub status_code: u16,
  pub status_text: String,
  pub headers: HashMap<String, String>,
  pub body: Vec<u8>,
}

impl HttpResponse {
  pub fn parse(data: &[u8]) -> Option<Self> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();

    let status_line = lines.next()?;
    let parts: Vec<_> = status_line.splitn(3, ' ').collect();
    if parts.len() < 3 {
      return None;
    }

    let version = parts[0].to_string();
    let status_code: u16 = parts[1].parse().ok()?;
    let status_text = parts[2].to_string();

    let mut headers = HashMap::new();
    for line in lines {
      if line.is_empty() {
        break;
      }
      if let Some(colon) = line.find(':') {
        let key = line[..colon].trim().to_lowercase();
        let value = line[colon + 1..].trim().to_string();
        headers.insert(key, value);
      }
    }

    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n");
    let body = if let Some(pos) = header_end {
      data[pos + 4..].to_vec()
    } else {
      Vec::new()
    };

    Some(HttpResponse {
      version,
      status_code,
      status_text,
      headers,
      body,
    })
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(
      format!(
        "{} {} {}\r\n",
        self.version, self.status_code, self.status_text
      )
      .as_bytes(),
    );

    for (key, value) in &self.headers {
      buf.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }

    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&self.body);
    buf
  }

  pub fn simple(status_code: u16, status_text: &str, body: &str) -> Self {
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), body.len().to_string());
    headers.insert("content-type".to_string(), "text/plain".to_string());

    HttpResponse {
      version: "HTTP/1.1".to_string(),
      status_code,
      status_text: status_text.to_string(),
      headers,
      body: body.as_bytes().to_vec(),
    }
  }

  pub fn is_websocket_upgrade(&self) -> bool {
    self.status_code == 101
      && self
        .headers
        .get("upgrade")
        .map(|s| s.to_lowercase().contains("websocket"))
        .unwrap_or(false)
  }

  pub fn strip_security_headers(&mut self) {
    let headers_to_strip = [
      "content-security-policy",
      "content-security-policy-report-only",
      "strict-transport-security",
      "x-frame-options",
      "x-xss-protection",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy",
      "cross-origin-opener-policy",
      "cross-origin-embedder-policy",
      "cross-origin-resource-policy",
    ];

    for header in headers_to_strip {
      self.headers.remove(header);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{HttpRequest, HttpResponse};

  #[test]
  fn test_http_request_parse() {
    let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n";
    let req = HttpRequest::parse(data).unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/path");
    assert_eq!(req.host, "example.com");
  }

  #[test]
  fn test_http_response_parse() {
    let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
    let resp = HttpResponse::parse(data).unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.status_text, "OK");
  }

  #[test]
  fn test_websocket_upgrade_request_detection() {
    let data = b"GET /socket HTTP/1.1\r\n\
                     Host: example.com\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n";
    let req = HttpRequest::parse(data).unwrap();
    assert!(req.is_websocket_upgrade());

    let data_regular = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let req_regular = HttpRequest::parse(data_regular).unwrap();
    assert!(!req_regular.is_websocket_upgrade());

    let data_other = b"GET /h2 HTTP/1.1\r\n\
                          Host: example.com\r\n\
                          Connection: Upgrade\r\n\
                          Upgrade: h2c\r\n\r\n";
    let req_other = HttpRequest::parse(data_other).unwrap();
    assert!(!req_other.is_websocket_upgrade());
  }

  #[test]
  fn test_websocket_upgrade_response_detection() {
    let data = b"HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    let resp = HttpResponse::parse(data).unwrap();
    assert!(resp.is_websocket_upgrade());
    assert_eq!(resp.status_code, 101);

    let data_regular = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    let resp_regular = HttpResponse::parse(data_regular).unwrap();
    assert!(!resp_regular.is_websocket_upgrade());

    let data_other = b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: h2c\r\n\r\n";
    let resp_other = HttpResponse::parse(data_other).unwrap();
    assert!(!resp_other.is_websocket_upgrade());
  }
}
