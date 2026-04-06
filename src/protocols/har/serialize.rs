//! HAR JSON Serialization (manual, no serde)

use super::types::*;

/// Escape a string for JSON output
pub fn escape_json_string(s: &str) -> String {
  let mut result = String::with_capacity(s.len() + 16);
  for c in s.chars() {
    match c {
      '"' => result.push_str("\\\""),
      '\\' => result.push_str("\\\\"),
      '\n' => result.push_str("\\n"),
      '\r' => result.push_str("\\r"),
      '\t' => result.push_str("\\t"),
      c if c.is_control() => {
        result.push_str(&format!("\\u{:04x}", c as u32));
      }
      c => result.push(c),
    }
  }
  result
}

impl Har {
  pub fn to_json(&self) -> String {
    let mut json = String::with_capacity(4096);
    json.push_str("{\n");
    json.push_str("  \"log\": ");
    json.push_str(&self.log.to_json(2));
    json.push_str("\n}");
    json
  }

  pub fn to_json_compact(&self) -> String {
    format!("{{\"log\":{}}}", self.log.to_json_compact())
  }
}

impl HarLog {
  pub fn to_json(&self, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let pad2 = " ".repeat(indent + 2);
    let mut json = String::with_capacity(2048);

    json.push_str("{\n");
    json.push_str(&format!(
      "{}\"version\": \"{}\",\n",
      pad2,
      escape_json_string(&self.version)
    ));
    json.push_str(&format!(
      "{}\"creator\": {},\n",
      pad2,
      self.creator.to_json()
    ));

    if let Some(ref browser) = self.browser {
      json.push_str(&format!("{}\"browser\": {},\n", pad2, browser.to_json()));
    }

    json.push_str(&format!("{}\"pages\": [\n", pad2));
    for (i, page) in self.pages.iter().enumerate() {
      json.push_str(&format!(
        "{}{}",
        " ".repeat(indent + 4),
        page.to_json(indent + 4)
      ));
      if i < self.pages.len() - 1 {
        json.push(',');
      }
      json.push('\n');
    }
    json.push_str(&format!("{}],\n", pad2));

    json.push_str(&format!("{}\"entries\": [\n", pad2));
    for (i, entry) in self.entries.iter().enumerate() {
      json.push_str(&format!(
        "{}{}",
        " ".repeat(indent + 4),
        entry.to_json(indent + 4)
      ));
      if i < self.entries.len() - 1 {
        json.push(',');
      }
      json.push('\n');
    }
    json.push_str(&format!("{}]", pad2));

    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ",\n{}\"comment\": \"{}\"",
        pad2,
        escape_json_string(comment)
      ));
    }

    json.push_str(&format!("\n{}}}", pad));
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = String::with_capacity(1024);
    json.push_str(&format!(
      "{{\"version\":\"{}\",\"creator\":{},",
      escape_json_string(&self.version),
      self.creator.to_json_compact()
    ));

    if let Some(ref browser) = self.browser {
      json.push_str(&format!("\"browser\":{},", browser.to_json_compact()));
    }

    json.push_str("\"pages\":[");
    for (i, page) in self.pages.iter().enumerate() {
      json.push_str(&page.to_json_compact());
      if i < self.pages.len() - 1 {
        json.push(',');
      }
    }
    json.push_str("],\"entries\":[");
    for (i, entry) in self.entries.iter().enumerate() {
      json.push_str(&entry.to_json_compact());
      if i < self.entries.len() - 1 {
        json.push(',');
      }
    }
    json.push(']');

    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }

    json.push('}');
    json
  }
}

impl HarCreator {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"name\": \"{}\", \"version\": \"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.version)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"name\":\"{}\",\"version\":\"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.version)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarBrowser {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"name\": \"{}\", \"version\": \"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.version)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"name\":\"{}\",\"version\":\"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.version)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarPage {
  pub fn to_json(&self, _indent: usize) -> String {
    let mut json = format!(
      "{{\"startedDateTime\": \"{}\", \"id\": \"{}\", \"title\": \"{}\", \"pageTimings\": {}",
      escape_json_string(&self.started_date_time),
      escape_json_string(&self.id),
      escape_json_string(&self.title),
      self.page_timings.to_json()
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"startedDateTime\":\"{}\",\"id\":\"{}\",\"title\":\"{}\",\"pageTimings\":{}",
      escape_json_string(&self.started_date_time),
      escape_json_string(&self.id),
      escape_json_string(&self.title),
      self.page_timings.to_json_compact()
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarPageTimings {
  pub fn to_json(&self) -> String {
    let mut parts = Vec::new();
    if let Some(load) = self.on_content_load {
      parts.push(format!("\"onContentLoad\": {}", load));
    }
    if let Some(load) = self.on_load {
      parts.push(format!("\"onLoad\": {}", load));
    }
    if let Some(ref comment) = self.comment {
      parts.push(format!("\"comment\": \"{}\"", escape_json_string(comment)));
    }
    format!("{{{}}}", parts.join(", "))
  }

  pub fn to_json_compact(&self) -> String {
    let mut parts = Vec::new();
    if let Some(load) = self.on_content_load {
      parts.push(format!("\"onContentLoad\":{}", load));
    }
    if let Some(load) = self.on_load {
      parts.push(format!("\"onLoad\":{}", load));
    }
    if let Some(ref comment) = self.comment {
      parts.push(format!("\"comment\":\"{}\"", escape_json_string(comment)));
    }
    format!("{{{}}}", parts.join(","))
  }
}

impl HarEntry {
  pub fn to_json(&self, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let pad2 = " ".repeat(indent + 2);
    let mut json = String::with_capacity(1024);

    json.push_str("{\n");

    if let Some(ref pageref) = self.pageref {
      json.push_str(&format!(
        "{}\"pageref\": \"{}\",\n",
        pad2,
        escape_json_string(pageref)
      ));
    }

    json.push_str(&format!(
      "{}\"startedDateTime\": \"{}\",\n",
      pad2,
      escape_json_string(&self.started_date_time)
    ));
    json.push_str(&format!("{}\"time\": {},\n", pad2, self.time));
    json.push_str(&format!(
      "{}\"request\": {},\n",
      pad2,
      self.request.to_json(indent + 2)
    ));
    json.push_str(&format!(
      "{}\"response\": {},\n",
      pad2,
      self.response.to_json(indent + 2)
    ));
    json.push_str(&format!("{}\"cache\": {},\n", pad2, self.cache.to_json()));
    json.push_str(&format!("{}\"timings\": {}", pad2, self.timings.to_json()));

    if let Some(ref ip) = self.server_ip_address {
      json.push_str(&format!(
        ",\n{}\"serverIPAddress\": \"{}\"",
        pad2,
        escape_json_string(ip)
      ));
    }
    if let Some(ref conn) = self.connection {
      json.push_str(&format!(
        ",\n{}\"connection\": \"{}\"",
        pad2,
        escape_json_string(conn)
      ));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ",\n{}\"comment\": \"{}\"",
        pad2,
        escape_json_string(comment)
      ));
    }

    json.push_str(&format!("\n{}}}", pad));
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = String::with_capacity(512);
    json.push('{');

    if let Some(ref pageref) = self.pageref {
      json.push_str(&format!("\"pageref\":\"{}\",", escape_json_string(pageref)));
    }

    json.push_str(&format!(
            "\"startedDateTime\":\"{}\",\"time\":{},\"request\":{},\"response\":{},\"cache\":{},\"timings\":{}",
            escape_json_string(&self.started_date_time),
            self.time,
            self.request.to_json_compact(),
            self.response.to_json_compact(),
            self.cache.to_json_compact(),
            self.timings.to_json_compact()
        ));

    if let Some(ref ip) = self.server_ip_address {
      json.push_str(&format!(
        ",\"serverIPAddress\":\"{}\"",
        escape_json_string(ip)
      ));
    }
    if let Some(ref conn) = self.connection {
      json.push_str(&format!(",\"connection\":\"{}\"", escape_json_string(conn)));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }

    json.push('}');
    json
  }
}

impl HarRequest {
  pub fn to_json(&self, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let pad2 = " ".repeat(indent + 2);
    let mut json = String::with_capacity(512);

    json.push_str("{\n");
    json.push_str(&format!(
      "{}\"method\": \"{}\",\n",
      pad2,
      escape_json_string(&self.method)
    ));
    json.push_str(&format!(
      "{}\"url\": \"{}\",\n",
      pad2,
      escape_json_string(&self.url)
    ));
    json.push_str(&format!(
      "{}\"httpVersion\": \"{}\",\n",
      pad2,
      escape_json_string(&self.http_version)
    ));

    json.push_str(&format!("{}\"cookies\": [", pad2));
    for (i, cookie) in self.cookies.iter().enumerate() {
      json.push_str(&cookie.to_json());
      if i < self.cookies.len() - 1 {
        json.push_str(", ");
      }
    }
    json.push_str("],\n");

    json.push_str(&format!("{}\"headers\": [", pad2));
    for (i, header) in self.headers.iter().enumerate() {
      json.push_str(&header.to_json());
      if i < self.headers.len() - 1 {
        json.push_str(", ");
      }
    }
    json.push_str("],\n");

    json.push_str(&format!("{}\"queryString\": [", pad2));
    for (i, param) in self.query_string.iter().enumerate() {
      json.push_str(&param.to_json());
      if i < self.query_string.len() - 1 {
        json.push_str(", ");
      }
    }
    json.push_str("],\n");

    if let Some(ref post_data) = self.post_data {
      json.push_str(&format!("{}\"postData\": {},\n", pad2, post_data.to_json()));
    }

    json.push_str(&format!(
      "{}\"headersSize\": {},\n",
      pad2, self.headers_size
    ));
    json.push_str(&format!("{}\"bodySize\": {}", pad2, self.body_size));

    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ",\n{}\"comment\": \"{}\"",
        pad2,
        escape_json_string(comment)
      ));
    }

    json.push_str(&format!("\n{}}}", pad));
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = String::with_capacity(256);
    json.push_str(&format!(
      "{{\"method\":\"{}\",\"url\":\"{}\",\"httpVersion\":\"{}\",",
      escape_json_string(&self.method),
      escape_json_string(&self.url),
      escape_json_string(&self.http_version)
    ));

    json.push_str("\"cookies\":[");
    for (i, cookie) in self.cookies.iter().enumerate() {
      json.push_str(&cookie.to_json_compact());
      if i < self.cookies.len() - 1 {
        json.push(',');
      }
    }
    json.push_str("],\"headers\":[");
    for (i, header) in self.headers.iter().enumerate() {
      json.push_str(&header.to_json_compact());
      if i < self.headers.len() - 1 {
        json.push(',');
      }
    }
    json.push_str("],\"queryString\":[");
    for (i, param) in self.query_string.iter().enumerate() {
      json.push_str(&param.to_json_compact());
      if i < self.query_string.len() - 1 {
        json.push(',');
      }
    }
    json.push(']');

    if let Some(ref post_data) = self.post_data {
      json.push_str(&format!(",\"postData\":{}", post_data.to_json_compact()));
    }

    json.push_str(&format!(
      ",\"headersSize\":{},\"bodySize\":{}",
      self.headers_size, self.body_size
    ));

    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }

    json.push('}');
    json
  }
}

impl HarResponse {
  pub fn to_json(&self, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let pad2 = " ".repeat(indent + 2);
    let mut json = String::with_capacity(512);

    json.push_str("{\n");
    json.push_str(&format!("{}\"status\": {},\n", pad2, self.status));
    json.push_str(&format!(
      "{}\"statusText\": \"{}\",\n",
      pad2,
      escape_json_string(&self.status_text)
    ));
    json.push_str(&format!(
      "{}\"httpVersion\": \"{}\",\n",
      pad2,
      escape_json_string(&self.http_version)
    ));

    json.push_str(&format!("{}\"cookies\": [", pad2));
    for (i, cookie) in self.cookies.iter().enumerate() {
      json.push_str(&cookie.to_json());
      if i < self.cookies.len() - 1 {
        json.push_str(", ");
      }
    }
    json.push_str("],\n");

    json.push_str(&format!("{}\"headers\": [", pad2));
    for (i, header) in self.headers.iter().enumerate() {
      json.push_str(&header.to_json());
      if i < self.headers.len() - 1 {
        json.push_str(", ");
      }
    }
    json.push_str("],\n");

    json.push_str(&format!(
      "{}\"content\": {},\n",
      pad2,
      self.content.to_json()
    ));
    json.push_str(&format!(
      "{}\"redirectURL\": \"{}\",\n",
      pad2,
      escape_json_string(&self.redirect_url)
    ));
    json.push_str(&format!(
      "{}\"headersSize\": {},\n",
      pad2, self.headers_size
    ));
    json.push_str(&format!("{}\"bodySize\": {}", pad2, self.body_size));

    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ",\n{}\"comment\": \"{}\"",
        pad2,
        escape_json_string(comment)
      ));
    }

    json.push_str(&format!("\n{}}}", pad));
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = String::with_capacity(256);
    json.push_str(&format!(
      "{{\"status\":{},\"statusText\":\"{}\",\"httpVersion\":\"{}\",",
      self.status,
      escape_json_string(&self.status_text),
      escape_json_string(&self.http_version)
    ));

    json.push_str("\"cookies\":[");
    for (i, cookie) in self.cookies.iter().enumerate() {
      json.push_str(&cookie.to_json_compact());
      if i < self.cookies.len() - 1 {
        json.push(',');
      }
    }
    json.push_str("],\"headers\":[");
    for (i, header) in self.headers.iter().enumerate() {
      json.push_str(&header.to_json_compact());
      if i < self.headers.len() - 1 {
        json.push(',');
      }
    }
    json.push(']');

    json.push_str(&format!(
      ",\"content\":{},\"redirectURL\":\"{}\",\"headersSize\":{},\"bodySize\":{}",
      self.content.to_json_compact(),
      escape_json_string(&self.redirect_url),
      self.headers_size,
      self.body_size
    ));

    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }

    json.push('}');
    json
  }
}

impl HarHeader {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"name\": \"{}\", \"value\": \"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.value)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"name\":\"{}\",\"value\":\"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.value)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarQueryParam {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"name\": \"{}\", \"value\": \"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.value)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"name\":\"{}\",\"value\":\"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.value)
    );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarCookie {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"name\": \"{}\", \"value\": \"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.value)
    );
    if let Some(ref path) = self.path {
      json.push_str(&format!(", \"path\": \"{}\"", escape_json_string(path)));
    }
    if let Some(ref domain) = self.domain {
      json.push_str(&format!(", \"domain\": \"{}\"", escape_json_string(domain)));
    }
    if let Some(ref expires) = self.expires {
      json.push_str(&format!(
        ", \"expires\": \"{}\"",
        escape_json_string(expires)
      ));
    }
    if let Some(http_only) = self.http_only {
      json.push_str(&format!(", \"httpOnly\": {}", http_only));
    }
    if let Some(secure) = self.secure {
      json.push_str(&format!(", \"secure\": {}", secure));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"name\":\"{}\",\"value\":\"{}\"",
      escape_json_string(&self.name),
      escape_json_string(&self.value)
    );
    if let Some(ref path) = self.path {
      json.push_str(&format!(",\"path\":\"{}\"", escape_json_string(path)));
    }
    if let Some(ref domain) = self.domain {
      json.push_str(&format!(",\"domain\":\"{}\"", escape_json_string(domain)));
    }
    if let Some(ref expires) = self.expires {
      json.push_str(&format!(",\"expires\":\"{}\"", escape_json_string(expires)));
    }
    if let Some(http_only) = self.http_only {
      json.push_str(&format!(",\"httpOnly\":{}", http_only));
    }
    if let Some(secure) = self.secure {
      json.push_str(&format!(",\"secure\":{}", secure));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarPostData {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"mimeType\": \"{}\", \"params\": [",
      escape_json_string(&self.mime_type)
    );
    for (i, param) in self.params.iter().enumerate() {
      json.push_str(&param.to_json());
      if i < self.params.len() - 1 {
        json.push_str(", ");
      }
    }
    json.push_str(&format!(
      "], \"text\": \"{}\"",
      escape_json_string(&self.text)
    ));
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"mimeType\":\"{}\",\"params\":[",
      escape_json_string(&self.mime_type)
    );
    for (i, param) in self.params.iter().enumerate() {
      json.push_str(&param.to_json_compact());
      if i < self.params.len() - 1 {
        json.push(',');
      }
    }
    json.push_str(&format!(
      "],\"text\":\"{}\"",
      escape_json_string(&self.text)
    ));
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarPostDataParam {
  pub fn to_json(&self) -> String {
    let mut json = format!("{{\"name\": \"{}\"", escape_json_string(&self.name));
    if let Some(ref value) = self.value {
      json.push_str(&format!(", \"value\": \"{}\"", escape_json_string(value)));
    }
    if let Some(ref file_name) = self.file_name {
      json.push_str(&format!(
        ", \"fileName\": \"{}\"",
        escape_json_string(file_name)
      ));
    }
    if let Some(ref content_type) = self.content_type {
      json.push_str(&format!(
        ", \"contentType\": \"{}\"",
        escape_json_string(content_type)
      ));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!("{{\"name\":\"{}\"", escape_json_string(&self.name));
    if let Some(ref value) = self.value {
      json.push_str(&format!(",\"value\":\"{}\"", escape_json_string(value)));
    }
    if let Some(ref file_name) = self.file_name {
      json.push_str(&format!(
        ",\"fileName\":\"{}\"",
        escape_json_string(file_name)
      ));
    }
    if let Some(ref content_type) = self.content_type {
      json.push_str(&format!(
        ",\"contentType\":\"{}\"",
        escape_json_string(content_type)
      ));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarContent {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"size\": {}, \"mimeType\": \"{}\"",
      self.size,
      escape_json_string(&self.mime_type)
    );
    if let Some(compression) = self.compression {
      json.push_str(&format!(", \"compression\": {}", compression));
    }
    if let Some(ref text) = self.text {
      json.push_str(&format!(", \"text\": \"{}\"", escape_json_string(text)));
    }
    if let Some(ref encoding) = self.encoding {
      json.push_str(&format!(
        ", \"encoding\": \"{}\"",
        escape_json_string(encoding)
      ));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"size\":{},\"mimeType\":\"{}\"",
      self.size,
      escape_json_string(&self.mime_type)
    );
    if let Some(compression) = self.compression {
      json.push_str(&format!(",\"compression\":{}", compression));
    }
    if let Some(ref text) = self.text {
      json.push_str(&format!(",\"text\":\"{}\"", escape_json_string(text)));
    }
    if let Some(ref encoding) = self.encoding {
      json.push_str(&format!(
        ",\"encoding\":\"{}\"",
        escape_json_string(encoding)
      ));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarCache {
  pub fn to_json(&self) -> String {
    let mut parts = Vec::new();
    if let Some(ref before) = self.before_request {
      parts.push(format!("\"beforeRequest\": {}", before.to_json()));
    }
    if let Some(ref after) = self.after_request {
      parts.push(format!("\"afterRequest\": {}", after.to_json()));
    }
    if let Some(ref comment) = self.comment {
      parts.push(format!("\"comment\": \"{}\"", escape_json_string(comment)));
    }
    format!("{{{}}}", parts.join(", "))
  }

  pub fn to_json_compact(&self) -> String {
    let mut parts = Vec::new();
    if let Some(ref before) = self.before_request {
      parts.push(format!("\"beforeRequest\":{}", before.to_json_compact()));
    }
    if let Some(ref after) = self.after_request {
      parts.push(format!("\"afterRequest\":{}", after.to_json_compact()));
    }
    if let Some(ref comment) = self.comment {
      parts.push(format!("\"comment\":\"{}\"", escape_json_string(comment)));
    }
    format!("{{{}}}", parts.join(","))
  }
}

impl HarCacheEntry {
  pub fn to_json(&self) -> String {
    let mut json = format!(
      "{{\"lastAccess\": \"{}\", \"eTag\": \"{}\", \"hitCount\": {}",
      escape_json_string(&self.last_access),
      escape_json_string(&self.e_tag),
      self.hit_count
    );
    if let Some(ref expires) = self.expires {
      json.push_str(&format!(
        ", \"expires\": \"{}\"",
        escape_json_string(expires)
      ));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
      "{{\"lastAccess\":\"{}\",\"eTag\":\"{}\",\"hitCount\":{}",
      escape_json_string(&self.last_access),
      escape_json_string(&self.e_tag),
      self.hit_count
    );
    if let Some(ref expires) = self.expires {
      json.push_str(&format!(",\"expires\":\"{}\"", escape_json_string(expires)));
    }
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}

impl HarTimings {
  pub fn to_json(&self) -> String {
    let mut json = format!(
            "{{\"blocked\": {}, \"dns\": {}, \"connect\": {}, \"send\": {}, \"wait\": {}, \"receive\": {}, \"ssl\": {}",
            self.blocked, self.dns, self.connect, self.send, self.wait, self.receive, self.ssl
        );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(
        ", \"comment\": \"{}\"",
        escape_json_string(comment)
      ));
    }
    json.push('}');
    json
  }

  pub fn to_json_compact(&self) -> String {
    let mut json = format!(
            "{{\"blocked\":{},\"dns\":{},\"connect\":{},\"send\":{},\"wait\":{},\"receive\":{},\"ssl\":{}",
            self.blocked, self.dns, self.connect, self.send, self.wait, self.receive, self.ssl
        );
    if let Some(ref comment) = self.comment {
      json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
    }
    json.push('}');
    json
  }
}
