/// HTTPS support backed by the in-tree TLS 1.2 implementation.
use std::time::Duration;

use super::{
    http::{HttpRequest, HttpResponse},
    tls12::Tls12Client,
};

/// HTTPS connection wrapper
pub struct HttpsConnection {
    host: String,
    port: u16,
    timeout: Duration,
}

impl HttpsConnection {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn request(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        let mut client = Tls12Client::connect_with_timeout(&self.host, self.port, self.timeout)?;
        client.verify_peer_certificate()?;

        let request_bytes = request.to_bytes();
        client
            .send_application_data(&request_bytes)
            .map_err(|e| format!("Failed to send HTTPS request: {}", e))?;

        let mut response_data = Vec::new();
        loop {
            match client.receive_application_data() {
                Ok(Some(chunk)) => response_data.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => return Err(format!("Failed to read HTTPS response: {}", e)),
            }
        }

        if response_data.is_empty() {
            return Err("Empty HTTPS response".to_string());
        }

        HttpResponse::from_bytes(&response_data)
    }
}
