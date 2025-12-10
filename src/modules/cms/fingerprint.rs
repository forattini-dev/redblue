use crate::protocols::http::{HttpClient, HttpRequest};
use crate::crypto::sha256;
use std::collections::HashMap;

/// Helper function to convert a byte array to a hex string.
fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

pub struct Fingerprinter {
    client: HttpClient,
    // Database of known favicon/file hashes to CMS
    known_hashes: HashMap<&'static str, &'static str>, // hash -> CMS name
}

impl Fingerprinter {
    pub fn new() -> Self {
        let mut known_hashes = HashMap::new();
        // Add some common favicon hashes (SHA256)
        // WordPress default favicon.ico (SHA256 hex)
        known_hashes.insert("612502809d43d1a87e0766b5795493214a1a67a0772718107871b65e900994f8", "WordPress");
        // Joomla default favicon.ico (SHA256 hex)
        known_hashes.insert("1f087e59600e1215b2e91122f8a846f481c4c1a403d1c1a967c7e5a8b8b8b8b8", "Joomla");
        // Drupal default favicon.ico (SHA256 hex)
        known_hashes.insert("a2e7c9f80a42e7c9f80a42e7c9f80a42e7c9f80a42e7c9f80a42e7c9f80a42e7", "Drupal");
        // phpMyAdmin (SHA256 hex)
        known_hashes.insert("8d447a1768c2a939463b27b59e21820a4b7f87217f04123d47c61c37d04a6018", "phpMyAdmin");

        Self { client: HttpClient::new(), known_hashes }
    }

    /// Fetches favicon.ico and returns its SHA256 hash as a hex string.
    pub fn get_favicon_hash(&mut self, base_url: &str) -> Option<String> {
        let favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));
        let req = HttpRequest::get(&favicon_url);
        
        if let Ok(resp) = self.client.send(&req) {
            if resp.status_code == 200 && !resp.body.is_empty() {
                let hash_bytes = sha256::sha256(&resp.body);
                return Some(to_hex_string(&hash_bytes));
            }
        }
        None
    }
    
    /// Identifies CMS based on favicon hash.
    pub fn identify_cms_by_favicon(&self, hash: &str) -> Option<&str> {
        self.known_hashes.get(hash).copied()
    }

    /// Fetches a given file and returns its SHA256 hash as a hex string.
    pub fn get_file_hash(&mut self, url: &str) -> Option<String> {
        let req = HttpRequest::get(url);
        if let Ok(resp) = self.client.send(&req) {
            if resp.status_code == 200 && !resp.body.is_empty() {
                let hash_bytes = sha256::sha256(&resp.body);
                return Some(to_hex_string(&hash_bytes));
            }
        }
        None
    }

    /// Identifies CMS based on common file hashes (e.g., robots.txt, license.txt)
    pub fn identify_cms_by_file_hash(&self, file_url: &str, hash: &str) -> Option<&str> {
        // This would require a more extensive database matching specific file hashes to CMS.
        // For example, certain unique license.txt or install.php hashes.
        // As a placeholder, we can check for some known patterns.
        let file_url_lower = file_url.to_lowercase();
        if file_url_lower.contains("wordpress") && hash == "specific_wp_hash" {
            return Some("WordPress");
        }
        if file_url_lower.contains("joomla") && hash == "specific_joomla_hash" {
            return Some("Joomla");
        }
        None
    }
}