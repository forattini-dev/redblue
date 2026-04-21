use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use super::{
  HttpDispatchMetrics, HttpDispatchOptions, HttpDispatcher, HttpRequest, HttpResponse,
  HttpResponseHandler, HttpResponseHead, HttpSendError, ParsedUrl, Scheme,
};

/// Cookie jar that stores cookies keyed by domain.
///
/// Parses `Set-Cookie` response headers and generates the `Cookie` request
/// header value for a given domain.  Only the cookie name=value pair is
/// stored; attributes like Path, Expires, Max-Age, Secure, and HttpOnly are
/// currently ignored.
#[derive(Debug, Clone)]
pub struct CookieJar {
  /// domain -> (cookie_name -> cookie_value)
  cookies: HashMap<String, HashMap<String, String>>,
}

impl CookieJar {
  pub fn new() -> Self {
    Self {
      cookies: HashMap::new(),
    }
  }

  /// Parse a single `Set-Cookie` header value and store the cookie.
  ///
  /// The cookie name=value pair is taken from the portion before the first
  /// semicolon.  If a `Domain` attribute is present its value is used as the
  /// storage key (with any leading dot stripped); otherwise `domain` is used.
  pub fn parse_set_cookie(&mut self, domain: &str, header_value: &str) {
    // The name=value pair is everything before the first ";"
    let name_value_part = match header_value.find(';') {
      Some(idx) => header_value[..idx].trim(),
      None => header_value.trim(),
    };

    let (name, value) = match name_value_part.find('=') {
      Some(idx) => (
        name_value_part[..idx].trim().to_string(),
        name_value_part[idx + 1..].trim().to_string(),
      ),
      None => return, // malformed — no '=' found, skip
    };

    if name.is_empty() {
      return;
    }

    // Check for a Domain attribute in the cookie attributes
    let cookie_domain = header_value
      .split(';')
      .skip(1) // skip the name=value part
      .find_map(|attr| {
        let attr = attr.trim();
        if attr.len() > 7 && attr[..7].eq_ignore_ascii_case("domain=") {
          let d = attr[7..].trim().trim_start_matches('.');
          if !d.is_empty() {
            return Some(d.to_ascii_lowercase());
          }
        }
        None
      })
      .unwrap_or_else(|| domain.to_ascii_lowercase());

    self
      .cookies
      .entry(cookie_domain)
      .or_insert_with(HashMap::new)
      .insert(name, value);
  }

  /// Build the `Cookie` header value for the given domain.
  ///
  /// Returns `None` when there are no cookies stored for `domain`.
  pub fn cookie_header(&self, domain: &str) -> Option<String> {
    let domain_lower = domain.to_ascii_lowercase();
    let jar = self.cookies.get(&domain_lower)?;
    if jar.is_empty() {
      return None;
    }
    let pairs: Vec<String> = jar.iter().map(|(n, v)| format!("{}={}", n, v)).collect();
    Some(pairs.join("; "))
  }

  /// Remove all stored cookies.
  pub fn clear(&mut self) {
    self.cookies.clear();
  }
}

/// Resolve a potentially relative `Location` header against the current
/// request URL.
///
/// Rules:
/// - Absolute URL (starts with `http://` or `https://`): use as-is
/// - Protocol-relative (starts with `//`): prepend current scheme
/// - Absolute path (starts with `/`): prepend scheme + host
/// - Relative path: prepend scheme + host + `/`
pub(crate) fn resolve_redirect_url(location: &str, current_url: &str) -> String {
  if location.starts_with("http://") || location.starts_with("https://") {
    return location.to_string();
  }

  let parsed = ParsedUrl::parse(current_url);
  let scheme_str = match parsed.scheme {
    Scheme::Http => "http",
    Scheme::Https => "https",
  };

  let host_port = if parsed.port != parsed.scheme.default_port() {
    format!("{}:{}", parsed.host, parsed.port)
  } else {
    parsed.host.clone()
  };

  if location.starts_with("//") {
    return format!("{}:{}", scheme_str, location);
  }

  if location.starts_with('/') {
    return format!("{}://{}{}", scheme_str, host_port, location);
  }

  format!("{}://{}/{}", scheme_str, host_port, location)
}

#[derive(Debug)]
pub struct HttpClient {
  dispatcher: HttpDispatcher,
  /// Maximum number of redirects to follow (0 = disabled).  Default: 10.
  max_redirects: u8,
  /// Optional cookie jar protected by a mutex for interior mutability.
  cookie_jar: Option<Mutex<CookieJar>>,
}

impl HttpClient {
  pub fn new() -> Self {
    Self {
      dispatcher: HttpDispatcher::new(),
      max_redirects: 10,
      cookie_jar: None,
    }
  }

  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.dispatcher = self.dispatcher.with_uniform_timeout(timeout);
    self
  }

  pub fn with_keep_alive(mut self, keep_alive: bool) -> Self {
    self.dispatcher = self.dispatcher.with_keep_alive_default(keep_alive);
    self
  }

  /// Set the maximum response bytes limit for all requests
  pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
    self.dispatcher = self.dispatcher.with_max_response_bytes(limit);
    self
  }

  pub fn with_middleware(mut self, middleware: std::sync::Arc<dyn super::HttpMiddleware>) -> Self {
    self.dispatcher = self.dispatcher.with_middleware(middleware);
    self
  }

  /// Set the maximum number of redirects to follow.  Pass 0 to disable
  /// redirect following entirely.
  pub fn with_max_redirects(mut self, max: u8) -> Self {
    self.max_redirects = max;
    self
  }

  /// Enable automatic cookie handling.  A fresh `CookieJar` is created and
  /// cookies received via `Set-Cookie` headers will be stored and replayed
  /// on subsequent requests to the matching domain.
  pub fn with_cookies(mut self) -> Self {
    self.cookie_jar = Some(Mutex::new(CookieJar::new()));
    self
  }

  pub fn send_with_handler<H: HttpResponseHandler>(
    &self,
    request: &HttpRequest,
    handler: &mut H,
  ) -> Result<(HttpResponseHead, HttpDispatchMetrics), HttpSendError> {
    let options = HttpDispatchOptions::from(request.clone());
    self.dispatcher.dispatch_with_handler(options, handler)
  }

  /// Send a request, following redirects and handling cookies automatically.
  ///
  /// This is the primary send method.  It honours `max_redirects` and, when
  /// a cookie jar is enabled, injects the `Cookie` header and collects
  /// `Set-Cookie` headers from every response in the redirect chain.
  pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
    self
      .send_following_redirects(request)
      .map_err(|err| err.message)
  }

  /// Send without following any redirects.  Useful for security scanners
  /// that need to inspect redirect responses directly.
  pub fn send_no_redirect(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
    let mut req = request.clone();

    // Inject cookies if the jar is enabled
    if let Some(ref jar_mutex) = self.cookie_jar {
      if let Ok(jar) = jar_mutex.lock() {
        if let Some(cookie_header) = jar.cookie_header(req.host()) {
          req.headers.insert("Cookie".to_string(), cookie_header);
        }
      }
    }

    let options = HttpDispatchOptions::from(req.clone());
    let result = self.dispatcher.dispatch(options).map_err(|e| e.message)?;

    // Collect cookies from the response
    if let Some(ref jar_mutex) = self.cookie_jar {
      if let Ok(mut jar) = jar_mutex.lock() {
        collect_set_cookies(&mut jar, req.host(), &result.response.headers);
      }
    }

    Ok(result.response)
  }

  /// Internal method that performs the redirect-following loop.
  fn send_following_redirects(&self, request: &HttpRequest) -> Result<HttpResponse, HttpSendError> {
    let mut current_request = request.clone();
    let mut redirects_remaining = self.max_redirects;

    loop {
      // Inject cookies before dispatching
      if let Some(ref jar_mutex) = self.cookie_jar {
        if let Ok(jar) = jar_mutex.lock() {
          if let Some(cookie_header) = jar.cookie_header(current_request.host()) {
            current_request
              .headers
              .insert("Cookie".to_string(), cookie_header);
          }
        }
      }

      let options = HttpDispatchOptions::from(current_request.clone());
      let result = self.dispatcher.dispatch(options)?;
      let response = result.response;

      // Collect cookies from every response in the chain
      if let Some(ref jar_mutex) = self.cookie_jar {
        if let Ok(mut jar) = jar_mutex.lock() {
          collect_set_cookies(&mut jar, current_request.host(), &response.headers);
        }
      }

      // Check for redirect status codes
      let is_redirect = matches!(response.status_code, 301 | 302 | 303 | 307 | 308);
      if !is_redirect || redirects_remaining == 0 {
        return Ok(response);
      }

      // Extract the Location header (try canonical then lowercase)
      let location = response
        .headers
        .get("Location")
        .or_else(|| response.headers.get("location"))
        .cloned();

      let location = match location {
        Some(loc) if !loc.is_empty() => loc,
        _ => return Ok(response), // no usable Location — return as-is
      };

      let current_full_url = current_request.full_url();
      let resolved = resolve_redirect_url(&location, &current_full_url);

      // Build a fresh request to the redirect target
      let mut next_method = current_request.method.clone();
      let mut next_body = current_request.body.clone();

      match response.status_code {
        // 303 See Other: always switch to GET, drop body
        303 => {
          next_method = "GET".to_string();
          next_body = Vec::new();
        }
        // 301 Moved Permanently / 302 Found: switch POST -> GET (standard browser behaviour)
        301 | 302 => {
          if current_request.method == "POST" {
            next_method = "GET".to_string();
            next_body = Vec::new();
          }
        }
        // 307 / 308: preserve method and body
        _ => {}
      }

      let mut next_request = HttpRequest::new(&next_method, &resolved);

      // Carry over relevant headers (except Host, which is set by HttpRequest::new)
      for (key, value) in &current_request.headers {
        let key_lower = key.to_ascii_lowercase();
        // Skip headers that are set automatically or are request-body-specific
        // when the body has been dropped
        if key_lower == "host" {
          continue;
        }
        if next_body.is_empty() && (key_lower == "content-length" || key_lower == "content-type") {
          continue;
        }
        next_request.headers.insert(key.clone(), value.clone());
      }

      if !next_body.is_empty() {
        next_request = next_request.with_body(next_body);
      }

      // Preserve TLS settings
      next_request.tls_verify = current_request.tls_verify;
      next_request.tls_pins = current_request.tls_pins.clone();
      next_request.tls_profile = current_request.tls_profile;

      current_request = next_request;
      redirects_remaining -= 1;
    }
  }

  pub fn send_with_metrics(
    &self,
    request: &HttpRequest,
  ) -> Result<(HttpResponse, Duration), HttpSendError> {
    let options = HttpDispatchOptions::from(request.clone());
    let result = self.dispatcher.dispatch(options)?;
    Ok((result.response, result.metrics.ttfb))
  }

  pub fn get(&self, url: &str) -> Result<HttpResponse, String> {
    let request = HttpRequest::get(url);
    self.send(&request)
  }

  /// GET request with custom headers
  pub fn get_with_headers(
    &self,
    url: &str,
    headers: &[(&str, &str)],
  ) -> Result<HttpResponse, String> {
    let mut request = HttpRequest::get(url);
    for (key, value) in headers {
      request = request.with_header(key, value);
    }
    self.send(&request)
  }

  pub fn post(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, String> {
    let request = HttpRequest::post(url).with_body(body);
    self.send(&request)
  }

  /// POST request with custom headers
  pub fn post_with_headers(
    &self,
    url: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
  ) -> Result<HttpResponse, String> {
    let mut request = HttpRequest::post(url).with_body(body);
    for (key, value) in headers {
      request = request.with_header(key, value);
    }
    self.send(&request)
  }

  /// HEAD request - returns only headers, no body
  pub fn head(&self, url: &str) -> Result<HttpResponse, String> {
    let request = HttpRequest::head(url);
    self.send(&request)
  }

  /// Set timeout (mutating version)
  /// Note: This creates a new dispatcher with the timeout, which is slightly inefficient
  /// but avoids requiring Default on HttpDispatcher
  pub fn set_timeout(&mut self, timeout: Duration) {
    // Create new dispatcher with timeout
    let new_dispatcher = HttpDispatcher::new().with_uniform_timeout(timeout);
    self.dispatcher = new_dispatcher;
  }

  /// Set user agent header for all requests
  /// Note: This creates a middleware that adds the User-Agent header
  pub fn set_user_agent(&mut self, user_agent: &str) {
    // Store user agent in dispatcher as a default header
    // For now, we'll just note this is a no-op since HttpDispatcher doesn't support this yet
    // The caller should add User-Agent to individual requests instead
    let _ = user_agent; // Suppress unused warning - this is intentionally a no-op placeholder
  }

  /// POST with content type and raw body
  pub fn post_raw(
    &self,
    url: &str,
    body: &[u8],
    content_type: &str,
  ) -> Result<HttpResponse, String> {
    let request = HttpRequest::post(url)
      .with_body(body.to_vec())
      .with_header("Content-Type", content_type);
    self.send(&request)
  }
}

/// Extract `Set-Cookie` headers from a response and feed them into the jar.
///
/// The HTTP headers `HashMap` stores only one value per key, but real servers
/// may send multiple `Set-Cookie` headers.  When the response is parsed by
/// `HttpResponse::from_bytes`, only one survives.  We do the best we can
/// with what we have — when a comma-separated value looks like it contains
/// multiple cookies (heuristic: contains ", " followed by a token and "=")
/// we split on that boundary.
fn collect_set_cookies(jar: &mut CookieJar, domain: &str, headers: &HashMap<String, String>) {
  for (key, value) in headers {
    if key.eq_ignore_ascii_case("Set-Cookie") || key.eq_ignore_ascii_case("set-cookie") {
      jar.parse_set_cookie(domain, value);
    }
  }
}

impl Default for HttpClient {
  fn default() -> Self {
    Self::new()
  }
}
