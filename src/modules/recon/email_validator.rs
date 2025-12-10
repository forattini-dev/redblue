use crate::protocols::dns::DnsClient;
use crate::protocols::smtp::SmtpClient;
use std::time::Duration;

pub struct EmailValidator {
    domain: String,
    dns_client: DnsClient,
    smtp_timeout: Duration,
}

impl EmailValidator {
    pub fn new(domain: &str) -> Self {
        let cfg = crate::config::get();
        Self {
            domain: domain.to_string(),
            dns_client: DnsClient::new(&cfg.network.dns_resolver)
                .with_timeout(cfg.network.dns_timeout_ms),
            smtp_timeout: Duration::from_secs(5),
        }
    }

    pub fn with_smtp_timeout(mut self, secs: u64) -> Self {
        self.smtp_timeout = Duration::from_secs(secs);
        self
    }

    /// Validates an email address by:
    /// 1. Looking up MX records for the domain.
    /// 2. Attempting to connect to the highest priority mail server.
    /// 3. Performing an SMTP RCPT TO check.
    pub fn validate_email(&self, email: &str) -> Result<bool, String> {
        // 1. Extract domain from email
        let email_parts: Vec<&str> = email.split('@').collect();
        if email_parts.len() != 2 {
            return Err("Invalid email address format".to_string());
        }
        let domain_from_email = email_parts[1];

        // 2. Look up MX records for the domain
        let mx_records = self.dns_client.query(domain_from_email, crate::protocols::dns::DnsRecordType::MX)
            .map_err(|e| format!("MX lookup failed for {}: {}", domain_from_email, e))?;

        if mx_records.is_empty() {
            return Ok(false); // No MX records, no mail server
        }

        // MX records usually come with preference (lower is higher priority)
        // DnsAnswer has a 'priority' field for MX records, assuming it's available.
        // For simplicity, let's just connect to the first MX record.
        let mut mail_servers: Vec<(u16, String)> = mx_records.iter()
            .filter_map(|answer| answer.as_mx())
            .collect();
        mail_servers.sort_by_key(|(priority, _)| *priority); // Sort by priority

        for (_, mail_server_host) in mail_servers {
            let smtp_server_addr = format!("{}:25", mail_server_host); // Default SMTP port
            let smtp_client = SmtpClient::new(&smtp_server_addr).with_timeout(self.smtp_timeout);

            match smtp_client.verify_email(email) {
                Ok(exists) => {
                    if exists { return Ok(true); }
                },
                Err(e) => {
                    // Log error but try next server
                    eprintln!("Warning: SMTP verification failed for {}: {}", mail_server_host, e);
                }
            }
        }
        
        Ok(false) // No mail server confirmed existence
    }
}
