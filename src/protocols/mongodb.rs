/// MongoDB Wire Protocol Implementation
///
/// Implements MongoDB wire protocol for:
/// - Server version detection
/// - Authentication testing
/// - No-auth detection
/// - Database enumeration
/// - Basic BSON handling
///
/// Reference: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// MongoDB opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum OpCode {
    Reply = 1,
    Update = 2001,
    Insert = 2002,
    Query = 2004,
    GetMore = 2005,
    Delete = 2006,
    KillCursors = 2007,
    Msg = 2013, // OP_MSG (MongoDB 3.6+)
}

/// MongoDB server information
#[derive(Debug, Clone)]
pub struct MongoServerInfo {
    pub version: String,
    pub git_version: String,
    pub ok: bool,
}

/// MongoDB client
pub struct MongoClient {
    stream: TcpStream,
    request_id: i32,
}

impl MongoClient {
    /// Connect to MongoDB server
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        let address = format!("{}:{}", host, port);

        let stream = TcpStream::connect(&address)
            .map_err(|e| format!("Failed to connect to {}: {}", address, e))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        Ok(Self {
            stream,
            request_id: 1,
        })
    }

    /// Get server build info (version detection)
    pub fn build_info(&mut self) -> Result<MongoServerInfo, String> {
        // Send buildInfo command using OP_QUERY
        let query = self.build_query("admin.$cmd", 0, 0, &build_info_bson())?;

        self.stream
            .write_all(&query)
            .map_err(|e| format!("Failed to send query: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        self.request_id += 1;

        // Read response
        let response = self.read_response()?;
        self.parse_build_info(&response)
    }

    /// Test if MongoDB allows connection without auth
    pub fn test_no_auth(&mut self) -> Result<bool, String> {
        match self.build_info() {
            Ok(info) => Ok(info.ok),
            Err(_) => Ok(false),
        }
    }

    /// Build OP_QUERY message
    fn build_query(
        &self,
        collection: &str,
        skip: i32,
        limit: i32,
        query_doc: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut message = Vec::new();

        // Message header
        let header_len = 16; // Standard MongoDB message header
        let message_len = header_len + 4 + collection.len() + 1 + 4 + 4 + query_doc.len();

        // Message length (4 bytes, little-endian)
        message.extend_from_slice(&(message_len as i32).to_le_bytes());

        // Request ID (4 bytes)
        message.extend_from_slice(&self.request_id.to_le_bytes());

        // Response to (4 bytes) - 0 for new queries
        message.extend_from_slice(&0i32.to_le_bytes());

        // OpCode (4 bytes) - OP_QUERY = 2004
        message.extend_from_slice(&(OpCode::Query as i32).to_le_bytes());

        // OP_QUERY specific fields
        // Flags (4 bytes) - 0 for default
        message.extend_from_slice(&0i32.to_le_bytes());

        // Collection name (null-terminated string)
        message.extend_from_slice(collection.as_bytes());
        message.push(0); // Null terminator

        // Number to skip (4 bytes)
        message.extend_from_slice(&skip.to_le_bytes());

        // Number to return (4 bytes)
        message.extend_from_slice(&limit.to_le_bytes());

        // Query document (BSON)
        message.extend_from_slice(query_doc);

        Ok(message)
    }

    /// Read response from MongoDB
    fn read_response(&mut self) -> Result<Vec<u8>, String> {
        // Read message header (16 bytes)
        let mut header = [0u8; 16];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read header: {}", e))?;

        // Parse message length (first 4 bytes)
        let message_len = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;

        if message_len < 16 || message_len > 48_000_000 {
            return Err(format!("Invalid message length: {}", message_len));
        }

        // Read the rest of the message
        let body_len = message_len - 16;
        let mut body = vec![0u8; body_len];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| format!("Failed to read body: {}", e))?;

        Ok(body)
    }

    /// Parse buildInfo response
    fn parse_build_info(&self, response: &[u8]) -> Result<MongoServerInfo, String> {
        if response.len() < 20 {
            return Err("Response too short".to_string());
        }

        // Skip OP_REPLY header (20 bytes)
        let doc_start = 20;
        if doc_start >= response.len() {
            return Err("Invalid response format".to_string());
        }

        let doc = &response[doc_start..];

        // Parse BSON document (simplified)
        let version = extract_bson_string(doc, "version").unwrap_or_else(|| "unknown".to_string());
        let git_version =
            extract_bson_string(doc, "gitVersion").unwrap_or_else(|| "unknown".to_string());

        Ok(MongoServerInfo {
            version,
            git_version,
            ok: true,
        })
    }

    /// List databases
    pub fn list_databases(&mut self) -> Result<Vec<String>, String> {
        let query = self.build_query("admin.$cmd", 0, 0, &list_databases_bson())?;

        self.stream
            .write_all(&query)
            .map_err(|e| format!("Failed to send query: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        self.request_id += 1;

        let response = self.read_response()?;
        self.parse_databases(&response)
    }

    /// Parse database list response
    fn parse_databases(&self, response: &[u8]) -> Result<Vec<String>, String> {
        if response.len() < 20 {
            return Err("Response too short".to_string());
        }

        let doc_start = 20;
        if doc_start >= response.len() {
            return Err("Invalid response format".to_string());
        }

        let doc = &response[doc_start..];

        // Extract database names (simplified parsing)
        let mut databases = Vec::new();

        // Look for "name" fields in the BSON document
        let mut pos = 0;
        while pos + 10 < doc.len() {
            if let Some(name_pos) = find_subsequence(&doc[pos..], b"name\x00") {
                let actual_pos = pos + name_pos + 5; // Skip "name\0"
                if actual_pos + 2 < doc.len() && doc[actual_pos] == 0x02 {
                    // String type
                    if let Some(db_name) = read_bson_string(&doc[actual_pos..]) {
                        databases.push(db_name);
                    }
                }
                pos = actual_pos + 1;
            } else {
                break;
            }
        }

        Ok(databases)
    }
}

/// Build buildInfo command BSON document
fn build_info_bson() -> Vec<u8> {
    // Simple BSON document: { buildInfo: 1 }
    let mut doc = Vec::new();

    // Document length (placeholder)
    let doc_len: i32 = 4 + 1 + 9 + 1 + 4 + 1; // length + type + "buildInfo\0" + type + value + terminator
    doc.extend_from_slice(&doc_len.to_le_bytes());

    // Element: int32 "buildInfo" = 1
    doc.push(0x10); // int32 type
    doc.extend_from_slice(b"buildInfo\x00");
    doc.extend_from_slice(&1i32.to_le_bytes());

    // Document terminator
    doc.push(0x00);

    doc
}

/// Build listDatabases command BSON document
fn list_databases_bson() -> Vec<u8> {
    // Simple BSON document: { listDatabases: 1 }
    let mut doc = Vec::new();

    let doc_len: i32 = 4 + 1 + 13 + 1 + 4 + 1;
    doc.extend_from_slice(&doc_len.to_le_bytes());

    doc.push(0x10); // int32 type
    doc.extend_from_slice(b"listDatabases\x00");
    doc.extend_from_slice(&1i32.to_le_bytes());

    doc.push(0x00);

    doc
}

/// Extract string value from BSON document by key
fn extract_bson_string(doc: &[u8], key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    let mut pos = 4; // Skip document length

    while pos < doc.len() {
        if pos + 1 >= doc.len() {
            break;
        }

        let element_type = doc[pos];
        if element_type == 0x00 {
            break; // End of document
        }

        pos += 1;

        // Read field name
        let name_start = pos;
        while pos < doc.len() && doc[pos] != 0 {
            pos += 1;
        }

        if pos >= doc.len() {
            break;
        }

        let field_name = &doc[name_start..pos];
        pos += 1; // Skip null terminator

        // Check if this is our key
        if field_name == key_bytes && element_type == 0x02 {
            // String type
            return read_bson_string(&doc[pos - 1..]);
        }

        // Skip value based on type
        pos = skip_bson_value(doc, pos, element_type)?;
    }

    None
}

/// Read BSON string value
fn read_bson_string(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // String length (4 bytes, includes null terminator)
    let str_len = i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if str_len < 1 || data.len() < 4 + str_len {
        return None;
    }

    // Extract string (excluding null terminator)
    let str_bytes = &data[4..4 + str_len - 1];
    String::from_utf8(str_bytes.to_vec()).ok()
}

/// Skip BSON value based on type
fn skip_bson_value(doc: &[u8], pos: usize, element_type: u8) -> Option<usize> {
    match element_type {
        0x01 => Some(pos + 8), // double (8 bytes)
        0x02 => {
            // string
            if pos + 4 > doc.len() {
                return None;
            }
            let str_len =
                i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]]) as usize;
            Some(pos + 4 + str_len)
        }
        0x03 | 0x04 => {
            // document or array
            if pos + 4 > doc.len() {
                return None;
            }
            let doc_len =
                i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]]) as usize;
            Some(pos + doc_len)
        }
        0x08 => Some(pos + 1), // boolean (1 byte)
        0x09 => Some(pos + 8), // UTC datetime (8 bytes)
        0x10 => Some(pos + 4), // int32 (4 bytes)
        0x12 => Some(pos + 8), // int64 (8 bytes)
        _ => Some(pos + 1),    // Unknown type, skip 1 byte
    }
}

/// Find subsequence in slice
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Test MongoDB connection without authentication
pub fn test_mongodb_no_auth(host: &str, port: u16) -> Result<bool, String> {
    let mut client = MongoClient::connect(host, port)?;
    client.test_no_auth()
}

/// Get MongoDB server version
pub fn get_mongodb_version(host: &str, port: u16) -> Result<String, String> {
    let mut client = MongoClient::connect(host, port)?;
    let info = client.build_info()?;
    Ok(format!("{} ({})", info.version, info.git_version))
}

/// List MongoDB databases
pub fn list_mongo_databases(host: &str, port: u16) -> Result<Vec<String>, String> {
    let mut client = MongoClient::connect(host, port)?;
    client.list_databases()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_info_bson() {
        let bson = build_info_bson();
        assert!(bson.len() > 0);
        assert_eq!(bson[0], bson.len() as u8); // First 4 bytes should be length
        assert_eq!(bson[bson.len() - 1], 0x00); // Last byte should be terminator
    }

    #[test]
    fn test_list_databases_bson() {
        let bson = list_databases_bson();
        assert!(bson.len() > 0);
        assert_eq!(bson[bson.len() - 1], 0x00);
    }

    #[test]
    fn test_opcodes() {
        assert_eq!(OpCode::Query as i32, 2004);
        assert_eq!(OpCode::Reply as i32, 1);
        assert_eq!(OpCode::Msg as i32, 2013);
    }

    #[test]
    fn test_find_subsequence() {
        let haystack = b"hello world name test";
        assert_eq!(find_subsequence(haystack, b"name"), Some(12));
        assert_eq!(find_subsequence(haystack, b"xyz"), None);
    }
}

// ====================================================================================
// INTELLIGENCE GATHERING - Enhanced MongoDB Fingerprinting
// ====================================================================================

/// MongoDB intelligence profile combining timing, version, and security analysis
#[derive(Debug, Clone)]
pub struct MongoIntelligence {
    pub server_info: MongoServerInfo,
    pub connection_time_ms: u64,
    pub response_time_ms: u64,
    pub no_auth_enabled: bool,
    pub security_score: u8, // 0-100, lower is worse
    pub detected_issues: Vec<String>,
}

/// Gather comprehensive intelligence from MongoDB server
///
/// This combines:
/// - Timing analysis (connection + response)
/// - Version detection
/// - No-auth vulnerability check
/// - Security configuration analysis
pub fn gather_mongo_intelligence(host: &str, port: u16) -> Result<MongoIntelligence, String> {
    // Measure connection timing
    let conn_start = Instant::now();
    let mut client = MongoClient::connect(host, port)?;
    let connection_time_ms = conn_start.elapsed().as_millis() as u64;

    // Measure response timing for buildInfo
    let response_start = Instant::now();
    let server_info = client.build_info()?;
    let response_time_ms = response_start.elapsed().as_millis() as u64;

    // Check for no-auth vulnerability
    let no_auth_enabled = client.test_no_auth().unwrap_or(false);

    // Analyze security posture
    let mut security_score = 100u8;
    let mut detected_issues = Vec::new();

    // Critical: No authentication
    if no_auth_enabled {
        security_score = security_score.saturating_sub(60);
        detected_issues.push("CRITICAL: No authentication required".to_string());
    }

    // Version analysis - old versions are security risks
    if server_info.version.starts_with("2.") || server_info.version.starts_with("3.") {
        security_score = security_score.saturating_sub(20);
        detected_issues.push(format!(
            "WARNING: Outdated MongoDB version {} (security risk)",
            server_info.version
        ));
    }

    // Fast response time might indicate localhost or local network
    if response_time_ms < 10 {
        detected_issues.push("INFO: Very fast response (< 10ms) - likely local/LAN".to_string());
    }

    Ok(MongoIntelligence {
        server_info,
        connection_time_ms,
        response_time_ms,
        no_auth_enabled,
        security_score,
        detected_issues,
    })
}

impl MongoIntelligence {
    /// Get human-readable security assessment
    pub fn security_assessment(&self) -> &'static str {
        match self.security_score {
            0..=20 => "CRITICAL - Immediate action required",
            21..=40 => "HIGH RISK - Significant vulnerabilities",
            41..=60 => "MEDIUM RISK - Security improvements needed",
            61..=80 => "LOW RISK - Minor security concerns",
            81..=100 => "SECURE - Good security posture",
            _ => "UNKNOWN",
        }
    }

    /// Generate detailed intelligence report
    pub fn report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!(
            "MongoDB Intelligence Report\n\
             ==========================\n\n\
             Version: {} ({})\n\
             Connection Time: {}ms\n\
             Response Time: {}ms\n\
             No Auth Enabled: {}\n\n\
             Security Score: {}/100 ({})\n\n",
            self.server_info.version,
            self.server_info.git_version,
            self.connection_time_ms,
            self.response_time_ms,
            self.no_auth_enabled,
            self.security_score,
            self.security_assessment()
        ));

        if !self.detected_issues.is_empty() {
            report.push_str("Detected Issues:\n");
            for (i, issue) in self.detected_issues.iter().enumerate() {
                report.push_str(&format!("  {}. {}\n", i + 1, issue));
            }
        }

        report
    }
}

#[cfg(test)]
mod intelligence_tests {
    use super::*;

    #[test]
    fn test_security_assessment() {
        let intel = MongoIntelligence {
            server_info: MongoServerInfo {
                version: "4.4.0".to_string(),
                git_version: "abc123".to_string(),
                ok: true,
            },
            connection_time_ms: 5,
            response_time_ms: 15,
            no_auth_enabled: true,
            security_score: 30,
            detected_issues: vec!["CRITICAL: No auth".to_string()],
        };

        assert_eq!(
            intel.security_assessment(),
            "HIGH RISK - Significant vulnerabilities"
        );
    }

    #[test]
    fn test_intelligence_report() {
        let intel = MongoIntelligence {
            server_info: MongoServerInfo {
                version: "5.0.0".to_string(),
                git_version: "xyz789".to_string(),
                ok: true,
            },
            connection_time_ms: 8,
            response_time_ms: 12,
            no_auth_enabled: false,
            security_score: 85,
            detected_issues: vec![],
        };

        let report = intel.report();
        assert!(report.contains("MongoDB Intelligence Report"));
        assert!(report.contains("5.0.0"));
        assert!(report.contains("85/100"));
    }
}
