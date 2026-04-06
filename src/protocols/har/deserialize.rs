//! HAR JSON Deserialization (manual parser)

use super::types::*;
use std::collections::HashMap;

/// Simple JSON parser for HAR deserialization
pub struct JsonParser<'a> {
  input: &'a str,
  pos: usize,
}

impl<'a> JsonParser<'a> {
  pub fn new(input: &'a str) -> Self {
    Self { input, pos: 0 }
  }

  fn skip_whitespace(&mut self) {
    while self.pos < self.input.len() {
      let c = self.input.as_bytes()[self.pos];
      if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
        self.pos += 1;
      } else {
        break;
      }
    }
  }

  fn peek(&self) -> Option<char> {
    self.input[self.pos..].chars().next()
  }

  fn consume(&mut self, expected: char) -> Result<(), String> {
    self.skip_whitespace();
    if self.peek() == Some(expected) {
      self.pos += expected.len_utf8();
      Ok(())
    } else {
      Err(format!("Expected '{}' at position {}", expected, self.pos))
    }
  }

  fn parse_string(&mut self) -> Result<String, String> {
    self.skip_whitespace();
    self.consume('"')?;

    let mut result = String::new();
    let mut escaped = false;

    while self.pos < self.input.len() {
      let c = self.input[self.pos..].chars().next().unwrap();
      self.pos += c.len_utf8();

      if escaped {
        match c {
          '"' => result.push('"'),
          '\\' => result.push('\\'),
          'n' => result.push('\n'),
          'r' => result.push('\r'),
          't' => result.push('\t'),
          'u' => {
            if self.pos + 4 <= self.input.len() {
              if let Ok(code) = u32::from_str_radix(&self.input[self.pos..self.pos + 4], 16) {
                if let Some(ch) = char::from_u32(code) {
                  result.push(ch);
                }
              }
              self.pos += 4;
            }
          }
          _ => result.push(c),
        }
        escaped = false;
      } else if c == '\\' {
        escaped = true;
      } else if c == '"' {
        return Ok(result);
      } else {
        result.push(c);
      }
    }

    Err("Unterminated string".to_string())
  }

  fn parse_number(&mut self) -> Result<f64, String> {
    self.skip_whitespace();
    let start = self.pos;

    while self.pos < self.input.len() {
      let c = self.input.as_bytes()[self.pos];
      if c == b'-' || c == b'+' || c == b'.' || c == b'e' || c == b'E' || c.is_ascii_digit() {
        self.pos += 1;
      } else {
        break;
      }
    }

    self.input[start..self.pos]
      .parse()
      .map_err(|_| format!("Invalid number at position {}", start))
  }

  fn parse_bool(&mut self) -> Result<bool, String> {
    self.skip_whitespace();
    if self.input[self.pos..].starts_with("true") {
      self.pos += 4;
      Ok(true)
    } else if self.input[self.pos..].starts_with("false") {
      self.pos += 5;
      Ok(false)
    } else {
      Err(format!("Expected boolean at position {}", self.pos))
    }
  }

  fn parse_null(&mut self) -> Result<(), String> {
    self.skip_whitespace();
    if self.input[self.pos..].starts_with("null") {
      self.pos += 4;
      Ok(())
    } else {
      Err(format!("Expected null at position {}", self.pos))
    }
  }

  fn parse_object(&mut self) -> Result<HashMap<String, JsonValue>, String> {
    self.skip_whitespace();
    self.consume('{')?;

    let mut map = HashMap::new();
    self.skip_whitespace();

    if self.peek() == Some('}') {
      self.pos += 1;
      return Ok(map);
    }

    loop {
      let key = self.parse_string()?;
      self.skip_whitespace();
      self.consume(':')?;
      let value = self.parse_value()?;
      map.insert(key, value);

      self.skip_whitespace();
      match self.peek() {
        Some(',') => {
          self.pos += 1;
          continue;
        }
        Some('}') => {
          self.pos += 1;
          break;
        }
        _ => return Err(format!("Expected ',' or '}}' at position {}", self.pos)),
      }
    }

    Ok(map)
  }

  fn parse_array(&mut self) -> Result<Vec<JsonValue>, String> {
    self.skip_whitespace();
    self.consume('[')?;

    let mut arr = Vec::new();
    self.skip_whitespace();

    if self.peek() == Some(']') {
      self.pos += 1;
      return Ok(arr);
    }

    loop {
      let value = self.parse_value()?;
      arr.push(value);

      self.skip_whitespace();
      match self.peek() {
        Some(',') => {
          self.pos += 1;
          continue;
        }
        Some(']') => {
          self.pos += 1;
          break;
        }
        _ => return Err(format!("Expected ',' or ']' at position {}", self.pos)),
      }
    }

    Ok(arr)
  }

  pub fn parse_value(&mut self) -> Result<JsonValue, String> {
    self.skip_whitespace();
    match self.peek() {
      Some('"') => Ok(JsonValue::String(self.parse_string()?)),
      Some('{') => Ok(JsonValue::Object(self.parse_object()?)),
      Some('[') => Ok(JsonValue::Array(self.parse_array()?)),
      Some('t') | Some('f') => Ok(JsonValue::Bool(self.parse_bool()?)),
      Some('n') => {
        self.parse_null()?;
        Ok(JsonValue::Null)
      }
      Some(c) if c == '-' || c.is_ascii_digit() => Ok(JsonValue::Number(self.parse_number()?)),
      _ => Err(format!("Unexpected character at position {}", self.pos)),
    }
  }
}

/// JSON value type for parsing
#[derive(Debug, Clone)]
pub enum JsonValue {
  Null,
  Bool(bool),
  Number(f64),
  String(String),
  Array(Vec<JsonValue>),
  Object(HashMap<String, JsonValue>),
}

impl JsonValue {
  pub fn as_str(&self) -> Option<&str> {
    match self {
      JsonValue::String(s) => Some(s),
      _ => None,
    }
  }

  pub fn as_f64(&self) -> Option<f64> {
    match self {
      JsonValue::Number(n) => Some(*n),
      _ => None,
    }
  }

  pub fn as_i64(&self) -> Option<i64> {
    match self {
      JsonValue::Number(n) => Some(*n as i64),
      _ => None,
    }
  }

  pub fn as_bool(&self) -> Option<bool> {
    match self {
      JsonValue::Bool(b) => Some(*b),
      _ => None,
    }
  }

  pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
    match self {
      JsonValue::Array(a) => Some(a),
      _ => None,
    }
  }

  pub fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
    match self {
      JsonValue::Object(o) => Some(o),
      _ => None,
    }
  }

  pub fn get(&self, key: &str) -> Option<&JsonValue> {
    match self {
      JsonValue::Object(o) => o.get(key),
      _ => None,
    }
  }
}

impl Har {
  pub fn from_json(json: &str) -> Result<Self, String> {
    let mut parser = JsonParser::new(json);
    let value = parser.parse_value()?;

    let obj = value.as_object().ok_or("Expected object at root")?;
    let log_value = obj.get("log").ok_or("Missing 'log' field")?;

    Ok(Har {
      log: HarLog::from_json_value(log_value)?,
    })
  }
}

impl HarLog {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for log")?;

    let version = obj
      .get("version")
      .and_then(|v| v.as_str())
      .unwrap_or("1.2")
      .to_string();

    let creator = obj
      .get("creator")
      .map(HarCreator::from_json_value)
      .transpose()?
      .unwrap_or_else(|| HarCreator {
        name: "unknown".to_string(),
        version: "0.0".to_string(),
        comment: None,
      });

    let browser = obj
      .get("browser")
      .map(HarBrowser::from_json_value)
      .transpose()?;

    let pages = obj
      .get("pages")
      .and_then(|v| v.as_array())
      .map(|arr| {
        arr
          .iter()
          .filter_map(|v| HarPage::from_json_value(v).ok())
          .collect()
      })
      .unwrap_or_default();

    let entries = obj
      .get("entries")
      .and_then(|v| v.as_array())
      .map(|arr| {
        arr
          .iter()
          .filter_map(|v| HarEntry::from_json_value(v).ok())
          .collect()
      })
      .unwrap_or_default();

    let comment = obj
      .get("comment")
      .and_then(|v| v.as_str())
      .map(String::from);

    Ok(HarLog {
      version,
      creator,
      browser,
      pages,
      entries,
      comment,
    })
  }
}

impl HarCreator {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for creator")?;
    Ok(HarCreator {
      name: obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      version: obj
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarBrowser {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for browser")?;
    Ok(HarBrowser {
      name: obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      version: obj
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarPage {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for page")?;
    Ok(HarPage {
      started_date_time: obj
        .get("startedDateTime")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      id: obj
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      title: obj
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      page_timings: obj
        .get("pageTimings")
        .map(HarPageTimings::from_json_value)
        .transpose()?
        .unwrap_or_else(|| HarPageTimings {
          on_content_load: None,
          on_load: None,
          comment: None,
        }),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarPageTimings {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for pageTimings")?;
    Ok(HarPageTimings {
      on_content_load: obj.get("onContentLoad").and_then(|v| v.as_f64()),
      on_load: obj.get("onLoad").and_then(|v| v.as_f64()),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarEntry {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for entry")?;

    Ok(HarEntry {
      pageref: obj
        .get("pageref")
        .and_then(|v| v.as_str())
        .map(String::from),
      started_date_time: obj
        .get("startedDateTime")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      time: obj.get("time").and_then(|v| v.as_f64()).unwrap_or(0.0),
      request: obj
        .get("request")
        .map(HarRequest::from_json_value)
        .transpose()?
        .ok_or("Missing request in entry")?,
      response: obj
        .get("response")
        .map(HarResponse::from_json_value)
        .transpose()?
        .ok_or("Missing response in entry")?,
      cache: obj
        .get("cache")
        .map(HarCache::from_json_value)
        .transpose()?
        .unwrap_or_else(|| HarCache {
          before_request: None,
          after_request: None,
          comment: None,
        }),
      timings: obj
        .get("timings")
        .map(HarTimings::from_json_value)
        .transpose()?
        .ok_or("Missing timings in entry")?,
      server_ip_address: obj
        .get("serverIPAddress")
        .and_then(|v| v.as_str())
        .map(String::from),
      connection: obj
        .get("connection")
        .and_then(|v| v.as_str())
        .map(String::from),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarRequest {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for request")?;

    Ok(HarRequest {
      method: obj
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_string(),
      url: obj
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      http_version: obj
        .get("httpVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("HTTP/1.1")
        .to_string(),
      cookies: obj
        .get("cookies")
        .and_then(|v| v.as_array())
        .map(|arr| {
          arr
            .iter()
            .filter_map(|v| HarCookie::from_json_value(v).ok())
            .collect()
        })
        .unwrap_or_default(),
      headers: obj
        .get("headers")
        .and_then(|v| v.as_array())
        .map(|arr| {
          arr
            .iter()
            .filter_map(|v| HarHeader::from_json_value(v).ok())
            .collect()
        })
        .unwrap_or_default(),
      query_string: obj
        .get("queryString")
        .and_then(|v| v.as_array())
        .map(|arr| {
          arr
            .iter()
            .filter_map(|v| HarQueryParam::from_json_value(v).ok())
            .collect()
        })
        .unwrap_or_default(),
      post_data: obj
        .get("postData")
        .map(HarPostData::from_json_value)
        .transpose()?,
      headers_size: obj
        .get("headersSize")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1),
      body_size: obj.get("bodySize").and_then(|v| v.as_i64()).unwrap_or(-1),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarResponse {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for response")?;

    Ok(HarResponse {
      status: obj
        .get("status")
        .and_then(|v| v.as_f64())
        .map(|n| n as u16)
        .unwrap_or(0),
      status_text: obj
        .get("statusText")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      http_version: obj
        .get("httpVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("HTTP/1.1")
        .to_string(),
      cookies: obj
        .get("cookies")
        .and_then(|v| v.as_array())
        .map(|arr| {
          arr
            .iter()
            .filter_map(|v| HarCookie::from_json_value(v).ok())
            .collect()
        })
        .unwrap_or_default(),
      headers: obj
        .get("headers")
        .and_then(|v| v.as_array())
        .map(|arr| {
          arr
            .iter()
            .filter_map(|v| HarHeader::from_json_value(v).ok())
            .collect()
        })
        .unwrap_or_default(),
      content: obj
        .get("content")
        .map(HarContent::from_json_value)
        .transpose()?
        .ok_or("Missing content in response")?,
      redirect_url: obj
        .get("redirectURL")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      headers_size: obj
        .get("headersSize")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1),
      body_size: obj.get("bodySize").and_then(|v| v.as_i64()).unwrap_or(-1),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarHeader {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for header")?;
    Ok(HarHeader {
      name: obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      value: obj
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarQueryParam {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for queryParam")?;
    Ok(HarQueryParam {
      name: obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      value: obj
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarCookie {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for cookie")?;
    Ok(HarCookie {
      name: obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      value: obj
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      path: obj.get("path").and_then(|v| v.as_str()).map(String::from),
      domain: obj.get("domain").and_then(|v| v.as_str()).map(String::from),
      expires: obj
        .get("expires")
        .and_then(|v| v.as_str())
        .map(String::from),
      http_only: obj.get("httpOnly").and_then(|v| v.as_bool()),
      secure: obj.get("secure").and_then(|v| v.as_bool()),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarPostData {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for postData")?;
    Ok(HarPostData {
      mime_type: obj
        .get("mimeType")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      params: obj
        .get("params")
        .and_then(|v| v.as_array())
        .map(|arr| {
          arr
            .iter()
            .filter_map(|v| HarPostDataParam::from_json_value(v).ok())
            .collect()
        })
        .unwrap_or_default(),
      text: obj
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarPostDataParam {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value
      .as_object()
      .ok_or("Expected object for postDataParam")?;
    Ok(HarPostDataParam {
      name: obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      value: obj.get("value").and_then(|v| v.as_str()).map(String::from),
      file_name: obj
        .get("fileName")
        .and_then(|v| v.as_str())
        .map(String::from),
      content_type: obj
        .get("contentType")
        .and_then(|v| v.as_str())
        .map(String::from),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarContent {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for content")?;
    Ok(HarContent {
      size: obj.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
      compression: obj.get("compression").and_then(|v| v.as_i64()),
      mime_type: obj
        .get("mimeType")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      text: obj.get("text").and_then(|v| v.as_str()).map(String::from),
      encoding: obj
        .get("encoding")
        .and_then(|v| v.as_str())
        .map(String::from),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarCache {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for cache")?;
    Ok(HarCache {
      before_request: obj
        .get("beforeRequest")
        .map(HarCacheEntry::from_json_value)
        .transpose()?,
      after_request: obj
        .get("afterRequest")
        .map(HarCacheEntry::from_json_value)
        .transpose()?,
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarCacheEntry {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for cacheEntry")?;
    Ok(HarCacheEntry {
      expires: obj
        .get("expires")
        .and_then(|v| v.as_str())
        .map(String::from),
      last_access: obj
        .get("lastAccess")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      e_tag: obj
        .get("eTag")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string(),
      hit_count: obj
        .get("hitCount")
        .and_then(|v| v.as_f64())
        .map(|n| n as i32)
        .unwrap_or(0),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}

impl HarTimings {
  pub fn from_json_value(value: &JsonValue) -> Result<Self, String> {
    let obj = value.as_object().ok_or("Expected object for timings")?;
    Ok(HarTimings {
      blocked: obj.get("blocked").and_then(|v| v.as_f64()).unwrap_or(-1.0),
      dns: obj.get("dns").and_then(|v| v.as_f64()).unwrap_or(-1.0),
      connect: obj.get("connect").and_then(|v| v.as_f64()).unwrap_or(-1.0),
      send: obj.get("send").and_then(|v| v.as_f64()).unwrap_or(0.0),
      wait: obj.get("wait").and_then(|v| v.as_f64()).unwrap_or(0.0),
      receive: obj.get("receive").and_then(|v| v.as_f64()).unwrap_or(0.0),
      ssl: obj.get("ssl").and_then(|v| v.as_f64()).unwrap_or(-1.0),
      comment: obj
        .get("comment")
        .and_then(|v| v.as_str())
        .map(String::from),
    })
  }
}
