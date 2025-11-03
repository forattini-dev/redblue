/// SSH Protocol Implementation (RFC 4253 - Limited)
///
/// Implements SSH version identification and banner grabbing
/// - SSH version string exchange
/// - Server banner detection
/// - Algorithm negotiation detection
///
/// **Note**: This is a LIMITED implementation for reconnaissance only.
/// Full SSH authentication and encryption is extremely complex.
///
/// Reference: https://tools.ietf.org/html/rfc4253
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// SSH version constants
pub const SSH_VERSION_2: &str = "SSH-2.0";
pub const SSH_VERSION_1: &str = "SSH-1.99"; // Backward compatible

/// SSH banner information
#[derive(Debug, Clone)]
pub struct SshBanner {
    pub protocol_version: String,
    pub software_version: String,
    pub comments: Option<String>,
    pub raw_banner: String,
}

impl SshBanner {
    /// Parse SSH banner string
    /// Format: SSH-protoversion-softwareversion SP comments CR LF
    pub fn parse(banner: &str) -> Result<Self, String> {
        let clean_banner = banner.trim();

        if !clean_banner.starts_with("SSH-") {
            return Err(format!("Invalid SSH banner: {}", banner));
        }

        let parts: Vec<&str> = clean_banner.splitn(3, '-').collect();
        if parts.len() < 3 {
            return Err("Invalid SSH banner format".to_string());
        }

        let protocol_version = format!("{}-{}", parts[0], parts[1]);

        // Software version may contain comments
        let soft_and_comments: Vec<&str> = parts[2].splitn(2, ' ').collect();
        let software_version = soft_and_comments[0].to_string();
        let comments = soft_and_comments.get(1).map(|s| s.to_string());

        Ok(Self {
            protocol_version,
            software_version,
            comments,
            raw_banner: clean_banner.to_string(),
        })
    }

    /// Get server type from software version
    pub fn server_type(&self) -> &str {
        let lower = self.software_version.to_lowercase();

        if lower.contains("openssh") {
            "OpenSSH"
        } else if lower.contains("dropbear") {
            "Dropbear"
        } else if lower.contains("libssh") {
            "libssh"
        } else if lower.contains("putty") {
            "PuTTY"
        } else if lower.contains("paramiko") {
            "Paramiko"
        } else if lower.contains("maverick") {
            "Maverick"
        } else if lower.contains("cisco") {
            "Cisco"
        } else if lower.contains("fortinet") {
            "FortiOS"
        } else {
            "Unknown"
        }
    }

    /// Check if server supports SSH-2
    pub fn supports_ssh2(&self) -> bool {
        self.protocol_version.contains("2.0") || self.protocol_version.contains("1.99")
    }
}

/// SSH client for banner grabbing
pub struct SshClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl SshClient {
    /// Connect to SSH server and grab banner
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

        let reader_stream = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;

        let reader = BufReader::new(reader_stream);

        Ok(Self { stream, reader })
    }

    /// Read server banner
    pub fn read_banner(&mut self) -> Result<SshBanner, String> {
        let mut banner_line = String::new();

        self.reader
            .read_line(&mut banner_line)
            .map_err(|e| format!("Failed to read banner: {}", e))?;

        if banner_line.is_empty() {
            return Err("Connection closed by server".to_string());
        }

        SshBanner::parse(&banner_line)
    }

    /// Send client version and read server banner
    pub fn handshake(&mut self, client_version: &str) -> Result<SshBanner, String> {
        // Read server banner first
        let server_banner = self.read_banner()?;

        // Send our client version
        let our_banner = format!("{}\r\n", client_version);
        self.stream
            .write_all(our_banner.as_bytes())
            .map_err(|e| format!("Failed to send banner: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(server_banner)
    }

    /// Grab banner without sending client version
    pub fn grab_banner(host: &str, port: u16) -> Result<SshBanner, String> {
        let mut client = Self::connect(host, port)?;
        client.read_banner()
    }
}

/// Get default SSH client identification string
pub fn default_client_banner() -> String {
    "SSH-2.0-RedBlue_1.0".to_string()
}

/// Quick SSH banner grab
pub fn ssh_banner(host: &str, port: u16) -> Result<SshBanner, String> {
    SshClient::grab_banner(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openssh_banner() {
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let parsed = SshBanner::parse(banner).unwrap();

        assert_eq!(parsed.protocol_version, "SSH-2.0");
        assert!(parsed.software_version.contains("OpenSSH"));
        assert_eq!(parsed.server_type(), "OpenSSH");
        assert!(parsed.supports_ssh2());
    }

    #[test]
    fn test_parse_dropbear_banner() {
        let banner = "SSH-2.0-dropbear_2020.81";
        let parsed = SshBanner::parse(banner).unwrap();

        assert_eq!(parsed.protocol_version, "SSH-2.0");
        assert!(parsed.software_version.contains("dropbear"));
        assert_eq!(parsed.server_type(), "Dropbear");
    }

    #[test]
    fn test_parse_banner_with_comments() {
        let banner = "SSH-2.0-OpenSSH_7.4 This is a comment";
        let parsed = SshBanner::parse(banner).unwrap();

        assert_eq!(parsed.protocol_version, "SSH-2.0");
        assert!(parsed.software_version.contains("OpenSSH"));
        assert_eq!(parsed.comments, Some("This is a comment".to_string()));
    }

    #[test]
    fn test_invalid_banner() {
        let banner = "HTTP/1.1 200 OK";
        let result = SshBanner::parse(banner);

        assert!(result.is_err());
    }

    #[test]
    fn test_ssh1_banner() {
        let banner = "SSH-1.99-OpenSSH_3.9";
        let parsed = SshBanner::parse(banner).unwrap();

        assert!(parsed.supports_ssh2()); // 1.99 means SSH-2 compatible
    }
}
