/// WHOIS Protocol Implementation (RFC 3912)
/// TCP port 43
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct WhoisClient {
    timeout: Duration,
}

impl WhoisClient {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Query WHOIS for a domain
    pub fn query(&self, domain: &str) -> Result<WhoisResult, String> {
        let server = Self::get_whois_server(domain);

        let mut stream = TcpStream::connect(format!("{}:43", server))
            .map_err(|e| format!("Failed to connect to WHOIS server: {}", e))?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Send query
        let query = format!("{}\r\n", domain);
        stream
            .write_all(query.as_bytes())
            .map_err(|e| format!("Failed to send query: {}", e))?;

        // Read response
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        Ok(Self::parse_response(&response))
    }

    /// Get appropriate WHOIS server based on TLD
    fn get_whois_server(domain: &str) -> String {
        let tld = domain.split('.').last().unwrap_or("");

        match tld {
            "com" | "net" => "whois.verisign-grs.com",
            "org" => "whois.pir.org",
            "io" => "whois.nic.io",
            "ai" => "whois.nic.ai",
            "dev" => "whois.nic.google",
            "app" => "whois.nic.google",
            "br" => "whois.registro.br",
            "uk" => "whois.nic.uk",
            "de" => "whois.denic.de",
            "fr" => "whois.nic.fr",
            "jp" => "whois.jprs.jp",
            "cn" => "whois.cnnic.cn",
            "ru" => "whois.tcinet.ru",
            _ => "whois.iana.org",
        }
        .to_string()
    }

    fn parse_response(response: &str) -> WhoisResult {
        let mut result = WhoisResult {
            raw: response.to_string(),
            registrar: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            name_servers: Vec::new(),
            status: Vec::new(),
            registrant_org: None,
            registrant_country: None,
        };

        for line in response.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
                continue;
            }

            let lower = line.to_lowercase();

            // Registrar
            if (lower.starts_with("registrar:") || lower.starts_with("sponsoring registrar:"))
                && result.registrar.is_none()
            {
                result.registrar = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }

            // Dates
            if (lower.contains("creation date") || lower.contains("created"))
                && result.creation_date.is_none()
            {
                result.creation_date = Some(
                    line.split(':')
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(":")
                        .trim()
                        .to_string(),
                );
            }

            if (lower.contains("expir") || lower.contains("registry expiry"))
                && result.expiration_date.is_none()
            {
                result.expiration_date = Some(
                    line.split(':')
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(":")
                        .trim()
                        .to_string(),
                );
            }

            if (lower.contains("updated date") || lower.contains("last updated"))
                && result.updated_date.is_none()
            {
                result.updated_date = Some(
                    line.split(':')
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(":")
                        .trim()
                        .to_string(),
                );
            }

            // Name servers
            if lower.starts_with("name server:") || lower.starts_with("nserver:") {
                let ns = line.split(':').nth(1).unwrap_or("").trim().to_string();
                if !ns.is_empty() {
                    result.name_servers.push(ns);
                }
            }

            // Status
            if lower.starts_with("domain status:") || lower.starts_with("status:") {
                let status = line.split(':').nth(1).unwrap_or("").trim().to_string();
                if !status.is_empty() && !result.status.contains(&status) {
                    result.status.push(status);
                }
            }

            // Registrant info
            if (lower.starts_with("registrant organization:") || lower.starts_with("org:"))
                && result.registrant_org.is_none()
            {
                result.registrant_org =
                    Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }

            if (lower.starts_with("registrant country:") || lower.starts_with("country:"))
                && result.registrant_country.is_none()
            {
                result.registrant_country =
                    Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
        }

        result
    }
}

impl Default for WhoisClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct WhoisResult {
    pub raw: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub registrant_org: Option<String>,
    pub registrant_country: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_whois_server() {
        assert_eq!(
            WhoisClient::get_whois_server("example.com"),
            "whois.verisign-grs.com"
        );
        assert_eq!(
            WhoisClient::get_whois_server("example.org"),
            "whois.pir.org"
        );
        assert_eq!(WhoisClient::get_whois_server("example.io"), "whois.nic.io");
    }
}
