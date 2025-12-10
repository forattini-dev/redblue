/// HAR (HTTP Archive) 1.2 Implementation
/// Spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html
///
/// Provides recording and replay of HTTP transactions
/// with full timing information for analysis.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// HAR 1.2 top-level container
#[derive(Debug, Clone)]
pub struct Har {
    pub log: HarLog,
}

/// HAR Log - contains all entries and metadata
#[derive(Debug, Clone)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    pub browser: Option<HarBrowser>,
    pub pages: Vec<HarPage>,
    pub entries: Vec<HarEntry>,
    pub comment: Option<String>,
}

/// Creator tool information
#[derive(Debug, Clone)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
}

/// Browser information (optional)
#[derive(Debug, Clone)]
pub struct HarBrowser {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
}

/// Page information for grouping entries
#[derive(Debug, Clone)]
pub struct HarPage {
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    pub page_timings: HarPageTimings,
    pub comment: Option<String>,
}

/// Page timing information
#[derive(Debug, Clone)]
pub struct HarPageTimings {
    pub on_content_load: Option<f64>,
    pub on_load: Option<f64>,
    pub comment: Option<String>,
}

/// Individual HTTP transaction entry
#[derive(Debug, Clone)]
pub struct HarEntry {
    pub pageref: Option<String>,
    pub started_date_time: String,
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    pub cache: HarCache,
    pub timings: HarTimings,
    pub server_ip_address: Option<String>,
    pub connection: Option<String>,
    pub comment: Option<String>,
}

/// HTTP Request details
#[derive(Debug, Clone)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub cookies: Vec<HarCookie>,
    pub headers: Vec<HarHeader>,
    pub query_string: Vec<HarQueryParam>,
    pub post_data: Option<HarPostData>,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
}

/// HTTP Response details
#[derive(Debug, Clone)]
pub struct HarResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub cookies: Vec<HarCookie>,
    pub headers: Vec<HarHeader>,
    pub content: HarContent,
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
}

/// HTTP Header
#[derive(Debug, Clone)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
}

/// URL Query Parameter
#[derive(Debug, Clone)]
pub struct HarQueryParam {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
}

/// HTTP Cookie
#[derive(Debug, Clone)]
pub struct HarCookie {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub expires: Option<String>,
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub comment: Option<String>,
}

/// POST request data
#[derive(Debug, Clone)]
pub struct HarPostData {
    pub mime_type: String,
    pub params: Vec<HarPostDataParam>,
    pub text: String,
    pub comment: Option<String>,
}

/// POST data parameter
#[derive(Debug, Clone)]
pub struct HarPostDataParam {
    pub name: String,
    pub value: Option<String>,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub comment: Option<String>,
}

/// Response content
#[derive(Debug, Clone)]
pub struct HarContent {
    pub size: i64,
    pub compression: Option<i64>,
    pub mime_type: String,
    pub text: Option<String>,
    pub encoding: Option<String>,
    pub comment: Option<String>,
}

/// Cache information
#[derive(Debug, Clone)]
pub struct HarCache {
    pub before_request: Option<HarCacheEntry>,
    pub after_request: Option<HarCacheEntry>,
    pub comment: Option<String>,
}

/// Cache entry state
#[derive(Debug, Clone)]
pub struct HarCacheEntry {
    pub expires: Option<String>,
    pub last_access: String,
    pub e_tag: String,
    pub hit_count: i32,
    pub comment: Option<String>,
}

/// Detailed timing breakdown (all values in ms, -1 if not applicable)
#[derive(Debug, Clone)]
pub struct HarTimings {
    pub blocked: f64,
    pub dns: f64,
    pub connect: f64,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    pub ssl: f64,
    pub comment: Option<String>,
}

// ============================================================================
// JSON Serialization (manual, no serde)
// ============================================================================

fn escape_json_string(s: &str) -> String {
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
    fn to_json(&self, indent: usize) -> String {
        let pad = " ".repeat(indent);
        let pad2 = " ".repeat(indent + 2);
        let mut json = String::with_capacity(2048);

        json.push_str("{\n");
        json.push_str(&format!("{}\"version\": \"{}\",\n", pad2, escape_json_string(&self.version)));
        json.push_str(&format!("{}\"creator\": {},\n", pad2, self.creator.to_json()));

        if let Some(ref browser) = self.browser {
            json.push_str(&format!("{}\"browser\": {},\n", pad2, browser.to_json()));
        }

        json.push_str(&format!("{}\"pages\": [\n", pad2));
        for (i, page) in self.pages.iter().enumerate() {
            json.push_str(&format!("{}{}", " ".repeat(indent + 4), page.to_json(indent + 4)));
            if i < self.pages.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str(&format!("{}],\n", pad2));

        json.push_str(&format!("{}\"entries\": [\n", pad2));
        for (i, entry) in self.entries.iter().enumerate() {
            json.push_str(&format!("{}{}", " ".repeat(indent + 4), entry.to_json(indent + 4)));
            if i < self.entries.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str(&format!("{}]", pad2));

        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\n{}\"comment\": \"{}\"", pad2, escape_json_string(comment)));
        }

        json.push_str(&format!("\n{}}}", pad));
        json
    }

    fn to_json_compact(&self) -> String {
        let mut json = String::with_capacity(1024);
        json.push_str(&format!("{{\"version\":\"{}\",\"creator\":{},",
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
    fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"name\": \"{}\", \"version\": \"{}\"",
            escape_json_string(&self.name),
            escape_json_string(&self.version)
        );
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"name\": \"{}\", \"version\": \"{}\"",
            escape_json_string(&self.name),
            escape_json_string(&self.version)
        );
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self, _indent: usize) -> String {
        let mut json = format!(
            "{{\"startedDateTime\": \"{}\", \"id\": \"{}\", \"title\": \"{}\", \"pageTimings\": {}",
            escape_json_string(&self.started_date_time),
            escape_json_string(&self.id),
            escape_json_string(&self.title),
            self.page_timings.to_json()
        );
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
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

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self, indent: usize) -> String {
        let pad = " ".repeat(indent);
        let pad2 = " ".repeat(indent + 2);
        let mut json = String::with_capacity(1024);

        json.push_str("{\n");

        if let Some(ref pageref) = self.pageref {
            json.push_str(&format!("{}\"pageref\": \"{}\",\n", pad2, escape_json_string(pageref)));
        }

        json.push_str(&format!("{}\"startedDateTime\": \"{}\",\n", pad2, escape_json_string(&self.started_date_time)));
        json.push_str(&format!("{}\"time\": {},\n", pad2, self.time));
        json.push_str(&format!("{}\"request\": {},\n", pad2, self.request.to_json(indent + 2)));
        json.push_str(&format!("{}\"response\": {},\n", pad2, self.response.to_json(indent + 2)));
        json.push_str(&format!("{}\"cache\": {},\n", pad2, self.cache.to_json()));
        json.push_str(&format!("{}\"timings\": {}", pad2, self.timings.to_json()));

        if let Some(ref ip) = self.server_ip_address {
            json.push_str(&format!(",\n{}\"serverIPAddress\": \"{}\"", pad2, escape_json_string(ip)));
        }
        if let Some(ref conn) = self.connection {
            json.push_str(&format!(",\n{}\"connection\": \"{}\"", pad2, escape_json_string(conn)));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\n{}\"comment\": \"{}\"", pad2, escape_json_string(comment)));
        }

        json.push_str(&format!("\n{}}}", pad));
        json
    }

    fn to_json_compact(&self) -> String {
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
            json.push_str(&format!(",\"serverIPAddress\":\"{}\"", escape_json_string(ip)));
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
    fn to_json(&self, indent: usize) -> String {
        let pad = " ".repeat(indent);
        let pad2 = " ".repeat(indent + 2);
        let mut json = String::with_capacity(512);

        json.push_str("{\n");
        json.push_str(&format!("{}\"method\": \"{}\",\n", pad2, escape_json_string(&self.method)));
        json.push_str(&format!("{}\"url\": \"{}\",\n", pad2, escape_json_string(&self.url)));
        json.push_str(&format!("{}\"httpVersion\": \"{}\",\n", pad2, escape_json_string(&self.http_version)));

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

        json.push_str(&format!("{}\"headersSize\": {},\n", pad2, self.headers_size));
        json.push_str(&format!("{}\"bodySize\": {}", pad2, self.body_size));

        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\n{}\"comment\": \"{}\"", pad2, escape_json_string(comment)));
        }

        json.push_str(&format!("\n{}}}", pad));
        json
    }

    fn to_json_compact(&self) -> String {
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

        json.push_str(&format!(",\"headersSize\":{},\"bodySize\":{}", self.headers_size, self.body_size));

        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
        }

        json.push('}');
        json
    }
}

impl HarResponse {
    fn to_json(&self, indent: usize) -> String {
        let pad = " ".repeat(indent);
        let pad2 = " ".repeat(indent + 2);
        let mut json = String::with_capacity(512);

        json.push_str("{\n");
        json.push_str(&format!("{}\"status\": {},\n", pad2, self.status));
        json.push_str(&format!("{}\"statusText\": \"{}\",\n", pad2, escape_json_string(&self.status_text)));
        json.push_str(&format!("{}\"httpVersion\": \"{}\",\n", pad2, escape_json_string(&self.http_version)));

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

        json.push_str(&format!("{}\"content\": {},\n", pad2, self.content.to_json()));
        json.push_str(&format!("{}\"redirectURL\": \"{}\",\n", pad2, escape_json_string(&self.redirect_url)));
        json.push_str(&format!("{}\"headersSize\": {},\n", pad2, self.headers_size));
        json.push_str(&format!("{}\"bodySize\": {}", pad2, self.body_size));

        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\n{}\"comment\": \"{}\"", pad2, escape_json_string(comment)));
        }

        json.push_str(&format!("\n{}}}", pad));
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"name\": \"{}\", \"value\": \"{}\"",
            escape_json_string(&self.name),
            escape_json_string(&self.value)
        );
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"name\": \"{}\", \"value\": \"{}\"",
            escape_json_string(&self.name),
            escape_json_string(&self.value)
        );
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
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
            json.push_str(&format!(", \"expires\": \"{}\"", escape_json_string(expires)));
        }
        if let Some(http_only) = self.http_only {
            json.push_str(&format!(", \"httpOnly\": {}", http_only));
        }
        if let Some(secure) = self.secure {
            json.push_str(&format!(", \"secure\": {}", secure));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
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
        json.push_str(&format!("], \"text\": \"{}\"", escape_json_string(&self.text)));
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
        json.push_str(&format!("],\"text\":\"{}\"", escape_json_string(&self.text)));
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }
}

impl HarPostDataParam {
    fn to_json(&self) -> String {
        let mut json = format!("{{\"name\": \"{}\"", escape_json_string(&self.name));
        if let Some(ref value) = self.value {
            json.push_str(&format!(", \"value\": \"{}\"", escape_json_string(value)));
        }
        if let Some(ref file_name) = self.file_name {
            json.push_str(&format!(", \"fileName\": \"{}\"", escape_json_string(file_name)));
        }
        if let Some(ref content_type) = self.content_type {
            json.push_str(&format!(", \"contentType\": \"{}\"", escape_json_string(content_type)));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
        let mut json = format!("{{\"name\":\"{}\"", escape_json_string(&self.name));
        if let Some(ref value) = self.value {
            json.push_str(&format!(",\"value\":\"{}\"", escape_json_string(value)));
        }
        if let Some(ref file_name) = self.file_name {
            json.push_str(&format!(",\"fileName\":\"{}\"", escape_json_string(file_name)));
        }
        if let Some(ref content_type) = self.content_type {
            json.push_str(&format!(",\"contentType\":\"{}\"", escape_json_string(content_type)));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }
}

impl HarContent {
    fn to_json(&self) -> String {
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
            json.push_str(&format!(", \"encoding\": \"{}\"", escape_json_string(encoding)));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
            json.push_str(&format!(",\"encoding\":\"{}\"", escape_json_string(encoding)));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(",\"comment\":\"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }
}

impl HarCache {
    fn to_json(&self) -> String {
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

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"lastAccess\": \"{}\", \"eTag\": \"{}\", \"hitCount\": {}",
            escape_json_string(&self.last_access),
            escape_json_string(&self.e_tag),
            self.hit_count
        );
        if let Some(ref expires) = self.expires {
            json.push_str(&format!(", \"expires\": \"{}\"", escape_json_string(expires)));
        }
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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
    fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"blocked\": {}, \"dns\": {}, \"connect\": {}, \"send\": {}, \"wait\": {}, \"receive\": {}, \"ssl\": {}",
            self.blocked, self.dns, self.connect, self.send, self.wait, self.receive, self.ssl
        );
        if let Some(ref comment) = self.comment {
            json.push_str(&format!(", \"comment\": \"{}\"", escape_json_string(comment)));
        }
        json.push('}');
        json
    }

    fn to_json_compact(&self) -> String {
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

// ============================================================================
// JSON Deserialization (manual parser)
// ============================================================================

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
                            if let Ok(code) = u32::from_str_radix(&self.input[self.pos..self.pos+4], 16) {
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

    fn parse_value(&mut self) -> Result<JsonValue, String> {
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
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for log")?;

        let version = obj.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1.2")
            .to_string();

        let creator = obj.get("creator")
            .map(|v| HarCreator::from_json_value(v))
            .transpose()?
            .unwrap_or_else(|| HarCreator {
                name: "unknown".to_string(),
                version: "0.0".to_string(),
                comment: None,
            });

        let browser = obj.get("browser")
            .map(|v| HarBrowser::from_json_value(v))
            .transpose()?;

        let pages = obj.get("pages")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| HarPage::from_json_value(v).ok()).collect())
            .unwrap_or_default();

        let entries = obj.get("entries")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| HarEntry::from_json_value(v).ok()).collect())
            .unwrap_or_default();

        let comment = obj.get("comment").and_then(|v| v.as_str()).map(String::from);

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
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for creator")?;
        Ok(HarCreator {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            version: obj.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarBrowser {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for browser")?;
        Ok(HarBrowser {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            version: obj.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarPage {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for page")?;
        Ok(HarPage {
            started_date_time: obj.get("startedDateTime").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            id: obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            title: obj.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            page_timings: obj.get("pageTimings")
                .map(|v| HarPageTimings::from_json_value(v))
                .transpose()?
                .unwrap_or_else(|| HarPageTimings {
                    on_content_load: None,
                    on_load: None,
                    comment: None,
                }),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarPageTimings {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for pageTimings")?;
        Ok(HarPageTimings {
            on_content_load: obj.get("onContentLoad").and_then(|v| v.as_f64()),
            on_load: obj.get("onLoad").and_then(|v| v.as_f64()),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarEntry {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for entry")?;

        Ok(HarEntry {
            pageref: obj.get("pageref").and_then(|v| v.as_str()).map(String::from),
            started_date_time: obj.get("startedDateTime").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            time: obj.get("time").and_then(|v| v.as_f64()).unwrap_or(0.0),
            request: obj.get("request")
                .map(|v| HarRequest::from_json_value(v))
                .transpose()?
                .ok_or("Missing request in entry")?,
            response: obj.get("response")
                .map(|v| HarResponse::from_json_value(v))
                .transpose()?
                .ok_or("Missing response in entry")?,
            cache: obj.get("cache")
                .map(|v| HarCache::from_json_value(v))
                .transpose()?
                .unwrap_or_else(|| HarCache {
                    before_request: None,
                    after_request: None,
                    comment: None,
                }),
            timings: obj.get("timings")
                .map(|v| HarTimings::from_json_value(v))
                .transpose()?
                .ok_or("Missing timings in entry")?,
            server_ip_address: obj.get("serverIPAddress").and_then(|v| v.as_str()).map(String::from),
            connection: obj.get("connection").and_then(|v| v.as_str()).map(String::from),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarRequest {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for request")?;

        Ok(HarRequest {
            method: obj.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string(),
            url: obj.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            http_version: obj.get("httpVersion").and_then(|v| v.as_str()).unwrap_or("HTTP/1.1").to_string(),
            cookies: obj.get("cookies")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| HarCookie::from_json_value(v).ok()).collect())
                .unwrap_or_default(),
            headers: obj.get("headers")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| HarHeader::from_json_value(v).ok()).collect())
                .unwrap_or_default(),
            query_string: obj.get("queryString")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| HarQueryParam::from_json_value(v).ok()).collect())
                .unwrap_or_default(),
            post_data: obj.get("postData")
                .map(|v| HarPostData::from_json_value(v))
                .transpose()?,
            headers_size: obj.get("headersSize").and_then(|v| v.as_i64()).unwrap_or(-1),
            body_size: obj.get("bodySize").and_then(|v| v.as_i64()).unwrap_or(-1),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarResponse {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for response")?;

        Ok(HarResponse {
            status: obj.get("status").and_then(|v| v.as_f64()).map(|n| n as u16).unwrap_or(0),
            status_text: obj.get("statusText").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            http_version: obj.get("httpVersion").and_then(|v| v.as_str()).unwrap_or("HTTP/1.1").to_string(),
            cookies: obj.get("cookies")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| HarCookie::from_json_value(v).ok()).collect())
                .unwrap_or_default(),
            headers: obj.get("headers")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| HarHeader::from_json_value(v).ok()).collect())
                .unwrap_or_default(),
            content: obj.get("content")
                .map(|v| HarContent::from_json_value(v))
                .transpose()?
                .ok_or("Missing content in response")?,
            redirect_url: obj.get("redirectURL").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            headers_size: obj.get("headersSize").and_then(|v| v.as_i64()).unwrap_or(-1),
            body_size: obj.get("bodySize").and_then(|v| v.as_i64()).unwrap_or(-1),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarHeader {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for header")?;
        Ok(HarHeader {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            value: obj.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarQueryParam {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for queryParam")?;
        Ok(HarQueryParam {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            value: obj.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarCookie {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for cookie")?;
        Ok(HarCookie {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            value: obj.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            path: obj.get("path").and_then(|v| v.as_str()).map(String::from),
            domain: obj.get("domain").and_then(|v| v.as_str()).map(String::from),
            expires: obj.get("expires").and_then(|v| v.as_str()).map(String::from),
            http_only: obj.get("httpOnly").and_then(|v| v.as_bool()),
            secure: obj.get("secure").and_then(|v| v.as_bool()),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarPostData {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for postData")?;
        Ok(HarPostData {
            mime_type: obj.get("mimeType").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            params: obj.get("params")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| HarPostDataParam::from_json_value(v).ok()).collect())
                .unwrap_or_default(),
            text: obj.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarPostDataParam {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for postDataParam")?;
        Ok(HarPostDataParam {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            value: obj.get("value").and_then(|v| v.as_str()).map(String::from),
            file_name: obj.get("fileName").and_then(|v| v.as_str()).map(String::from),
            content_type: obj.get("contentType").and_then(|v| v.as_str()).map(String::from),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarContent {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for content")?;
        Ok(HarContent {
            size: obj.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
            compression: obj.get("compression").and_then(|v| v.as_i64()),
            mime_type: obj.get("mimeType").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            text: obj.get("text").and_then(|v| v.as_str()).map(String::from),
            encoding: obj.get("encoding").and_then(|v| v.as_str()).map(String::from),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarCache {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for cache")?;
        Ok(HarCache {
            before_request: obj.get("beforeRequest")
                .map(|v| HarCacheEntry::from_json_value(v))
                .transpose()?,
            after_request: obj.get("afterRequest")
                .map(|v| HarCacheEntry::from_json_value(v))
                .transpose()?,
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarCacheEntry {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for cacheEntry")?;
        Ok(HarCacheEntry {
            expires: obj.get("expires").and_then(|v| v.as_str()).map(String::from),
            last_access: obj.get("lastAccess").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            e_tag: obj.get("eTag").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            hit_count: obj.get("hitCount").and_then(|v| v.as_f64()).map(|n| n as i32).unwrap_or(0),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

impl HarTimings {
    fn from_json_value(value: &JsonValue) -> Result<Self, String> {
        let obj = value.as_object().ok_or("Expected object for timings")?;
        Ok(HarTimings {
            blocked: obj.get("blocked").and_then(|v| v.as_f64()).unwrap_or(-1.0),
            dns: obj.get("dns").and_then(|v| v.as_f64()).unwrap_or(-1.0),
            connect: obj.get("connect").and_then(|v| v.as_f64()).unwrap_or(-1.0),
            send: obj.get("send").and_then(|v| v.as_f64()).unwrap_or(0.0),
            wait: obj.get("wait").and_then(|v| v.as_f64()).unwrap_or(0.0),
            receive: obj.get("receive").and_then(|v| v.as_f64()).unwrap_or(0.0),
            ssl: obj.get("ssl").and_then(|v| v.as_f64()).unwrap_or(-1.0),
            comment: obj.get("comment").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

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
// HAR Recorder - captures HTTP transactions
// ============================================================================

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

// ============================================================================
// Helper functions
// ============================================================================

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

fn days_to_ymd(days: u64) -> (u32, u32, u32) {
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

fn is_leap_year(year: i32) -> bool {
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

fn url_decode(s: &str) -> String {
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

// ============================================================================
// HTTP Client with HAR Recording
// ============================================================================

use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

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
                send: total_time_ms * 0.1, // Estimate
                wait: total_time_ms * 0.7,  // Estimate
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

/// Check if content type is text-based
fn is_text_content(mime_type: &str) -> bool {
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
                    version: "0.1.0".to_string(),
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
