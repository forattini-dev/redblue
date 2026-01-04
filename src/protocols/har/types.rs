//! HAR 1.2 Type Definitions
//! Spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html

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

/// Alias for POST data parameter (backwards compatibility)
pub type HarParam = HarPostDataParam;
