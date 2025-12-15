use crate::crypto::encoding::base64;
use crate::protocols::http::{HttpClient, HttpRequest};

pub struct HttpAuthTester {
    client: HttpClient,
}

impl HttpAuthTester {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    pub fn test_basic(&mut self, url: &str, user: &str, pass: &str) -> bool {
        let mut req = HttpRequest::get(url);
        let creds = format!("{}:{}", user, pass);
        let encoded = base64::base64_encode(creds.as_bytes());
        req.headers
            .insert("Authorization".to_string(), format!("Basic {}", encoded));

        if let Ok(resp) = self.client.send(&req) {
            return resp.status_code >= 200 && resp.status_code < 300; // Assuming success is 2xx. 401 is fail.
        }
        false
    }

    // Digest auth is more complex (nonce handling), skipping for minimal impl
}
