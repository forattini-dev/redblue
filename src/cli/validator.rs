/// Input validation with helpful error messages
use std::net::IpAddr;

use crate::config;
use crate::protocols::dns::{DnsClient, DnsRecordType};

pub struct Validator;

impl Validator {
    pub fn validate_ip(input: &str) -> Result<IpAddr, String> {
        input.parse::<IpAddr>().map_err(|_| {
            format!(
                "Invalid IP address: '{}'\n\
                \n\
                Expected formats:\n\
                  • IPv4: 192.168.1.1\n\
                  • IPv6: 2001:db8::1\n\
                \n\
                Did you mean to use a domain name? Try:\n\
                  rb dns resolve {}",
                input, input
            )
        })
    }

    pub fn resolve_host(input: &str) -> Result<IpAddr, String> {
        if let Ok(addr) = input.parse::<IpAddr>() {
            return Ok(addr);
        }

        let domain = Self::validate_domain(input)?;
        let cfg = config::get();
        let resolver_addr = cfg.network.dns_resolver.as_str();
        let resolver_timeout = cfg.network.dns_timeout_ms;
        let resolver = DnsClient::new(resolver_addr).with_timeout(resolver_timeout);

        if let Ok(answers) = resolver.query(&domain, DnsRecordType::A) {
            if let Some(ip) = answers.iter().find_map(|a| a.as_ip()) {
                return ip.parse::<IpAddr>().map_err(|_| {
                    format!("Resolved '{}' to invalid IPv4 address '{}'.", domain, ip)
                });
            }
        }

        if let Ok(answers) = resolver.query(&domain, DnsRecordType::AAAA) {
            if let Some(ip) = answers.iter().find_map(|a| a.as_ip()) {
                return ip.parse::<IpAddr>().map_err(|_| {
                    format!("Resolved '{}' to invalid IPv6 address '{}'.", domain, ip)
                });
            }
        }

        Err(format!(
            "Could not resolve '{}'.\n\
            Try running: rb dns record lookup {} --type A",
            domain, domain
        ))
    }

    pub fn validate_domain(input: &str) -> Result<String, String> {
        if input.is_empty() {
            return Err("Domain cannot be empty".to_string());
        }

        if input.contains(' ') {
            return Err(format!("Invalid domain: '{}' (contains spaces)", input));
        }

        if input.starts_with('-') || input.ends_with('-') {
            return Err(format!(
                "Invalid domain: '{}' (cannot start or end with hyphen)",
                input
            ));
        }

        Ok(input.to_string())
    }

    pub fn validate_host(input: &str) -> Result<(), String> {
        if input.parse::<IpAddr>().is_ok() {
            return Ok(());
        }
        Self::validate_domain(input).map(|_| ())
    }

    pub fn validate_port(input: &str) -> Result<u16, String> {
        input.parse::<u16>().map_err(|_| {
            format!(
                "Invalid port: '{}'\n\
                \n\
                Port must be a number between 1 and 65535\n\
                \n\
                Examples:\n\
                  • Single port: 80\n\
                  • Common ports: Use 'common' instead",
                input
            )
        })
    }

    pub fn validate_port_range(start: u16, end: u16) -> Result<(), String> {
        if start > end {
            return Err(format!(
                "Invalid port range: {}-{}\n\
                \n\
                Start port ({}) must be less than or equal to end port ({})",
                start, end, start, end
            ));
        }

        if start == 0 {
            return Err("Port range cannot start at 0 (minimum is 1)".to_string());
        }

        Ok(())
    }

    pub fn validate_url(input: &str) -> Result<String, String> {
        if !input.starts_with("http://") && !input.starts_with("https://") {
            return Err(format!(
                "Invalid URL: '{}'\n\
                \n\
                URL must start with http:// or https://\n\
                \n\
                Did you mean:\n\
                  • http://{}\n\
                  • https://{}",
                input, input, input
            ));
        }

        Ok(input.to_string())
    }

    #[allow(dead_code)]
    pub fn validate_positive_number(input: &str, name: &str) -> Result<usize, String> {
        input.parse::<usize>().map_err(|_| {
            format!(
                "Invalid {}: '{}'\n\
                \n\
                {} must be a positive number",
                name, input, name
            )
        })
    }

    pub fn suggest_command(input: &str, available: &[&str]) -> String {
        let suggestions = available
            .iter()
            .filter(|cmd| cmd.starts_with(input) || levenshtein(input, cmd) <= 2)
            .take(3)
            .collect::<Vec<_>>();

        if suggestions.is_empty() {
            return String::new();
        }

        let mut result = String::from("\nDid you mean one of these?\n");
        for suggestion in suggestions {
            result.push_str(&format!("  • {}\n", suggestion));
        }
        result
    }
}

// Simple Levenshtein distance for suggestions
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0; b_len + 1];

    for (i, a_char) in a.chars().enumerate() {
        curr_row[0] = i + 1;

        for (j, b_char) in b.chars().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            curr_row[j + 1] = (curr_row[j] + 1)
                .min(prev_row[j + 1] + 1)
                .min(prev_row[j] + cost);
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip() {
        assert!(Validator::validate_ip("127.0.0.1").is_ok());
        assert!(Validator::validate_ip("invalid").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(Validator::validate_port("80").is_ok());
        assert!(Validator::validate_port("70000").is_err());
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("scan", "scan"), 0);
        assert_eq!(levenshtein("scan", "scna"), 2);
        assert_eq!(levenshtein("dns", "dns"), 0);
    }
}
