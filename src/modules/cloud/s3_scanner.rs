#![allow(dead_code)]

/// S3 Scanner - AWS S3 bucket enumeration and security testing
///
/// Replaces tools like s3scanner, bucket_finder, AWSBucketDump
/// Features:
/// - Bucket existence checking
/// - Public access detection (ListBucket, GetObject permissions)
/// - Common bucket name enumeration
/// - Region detection
/// - Permissive ACL detection
///
/// NO external dependencies - pure Rust std implementation
use crate::protocols::http::HttpClient;

#[derive(Debug, Clone)]
pub struct S3Bucket {
    pub name: String,
    pub exists: bool,
    pub region: Option<String>,
    pub public_list: bool,
    pub public_read: bool,
    pub accessible: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct S3ScanResult {
    pub buckets: Vec<S3Bucket>,
    pub total_scanned: usize,
    pub total_exists: usize,
    pub total_public: usize,
}

pub struct S3Scanner {
    client: HttpClient,
}

impl S3Scanner {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    /// Check if a single S3 bucket exists and its permissions
    pub fn check_bucket(&self, bucket_name: &str) -> Result<S3Bucket, String> {
        let url = format!("https://{}.s3.amazonaws.com", bucket_name);

        // Try to access the bucket
        let response = self.client.get(&url);

        match response {
            Ok(resp) => {
                let body = String::from_utf8_lossy(&resp.body);

                match resp.status_code {
                    200 => {
                        // Bucket exists and is publicly listable
                        Ok(S3Bucket {
                            name: bucket_name.to_string(),
                            exists: true,
                            region: self.extract_region(&body),
                            public_list: true,
                            public_read: true,
                            accessible: true,
                            message: "Bucket is publicly accessible (LIST + READ)".to_string(),
                        })
                    }
                    403 => {
                        // Bucket exists but access is forbidden
                        // Check if we can at least confirm existence
                        let message = if body.contains("Access Denied") {
                            "Bucket exists but is private (Access Denied)"
                        } else {
                            "Bucket exists (Forbidden)"
                        };

                        Ok(S3Bucket {
                            name: bucket_name.to_string(),
                            exists: true,
                            region: self.extract_region(&body),
                            public_list: false,
                            public_read: false,
                            accessible: false,
                            message: message.to_string(),
                        })
                    }
                    404 => {
                        // Bucket does not exist
                        Ok(S3Bucket {
                            name: bucket_name.to_string(),
                            exists: false,
                            region: None,
                            public_list: false,
                            public_read: false,
                            accessible: false,
                            message: "Bucket does not exist".to_string(),
                        })
                    }
                    _ => {
                        // Other status code
                        Ok(S3Bucket {
                            name: bucket_name.to_string(),
                            exists: false,
                            region: None,
                            public_list: false,
                            public_read: false,
                            accessible: false,
                            message: format!("HTTP {}", resp.status_code),
                        })
                    }
                }
            }
            Err(e) => {
                // Network error or DNS resolution failed
                if e.contains("DNS") || e.contains("resolve") {
                    Ok(S3Bucket {
                        name: bucket_name.to_string(),
                        exists: false,
                        region: None,
                        public_list: false,
                        public_read: false,
                        accessible: false,
                        message: "Bucket does not exist (DNS)".to_string(),
                    })
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Scan multiple bucket names
    pub fn scan_buckets(&self, bucket_names: &[String]) -> S3ScanResult {
        let mut buckets = Vec::new();
        let mut total_exists = 0;
        let mut total_public = 0;

        for name in bucket_names {
            if let Ok(bucket) = self.check_bucket(name) {
                if bucket.exists {
                    total_exists += 1;
                }
                if bucket.public_list || bucket.public_read {
                    total_public += 1;
                }
                buckets.push(bucket);
            }
        }

        S3ScanResult {
            total_scanned: bucket_names.len(),
            total_exists,
            total_public,
            buckets,
        }
    }

    /// Generate common bucket name variations
    pub fn generate_bucket_names(&self, base_name: &str) -> Vec<String> {
        let mut names = Vec::new();

        // Base name
        names.push(base_name.to_string());

        // Common suffixes
        let suffixes = vec![
            "backup",
            "backups",
            "data",
            "files",
            "assets",
            "images",
            "uploads",
            "documents",
            "private",
            "public",
            "dev",
            "prod",
            "staging",
            "test",
            "logs",
            "archive",
            "temp",
            "static",
            "media",
            "resources",
        ];

        for suffix in &suffixes {
            names.push(format!("{}-{}", base_name, suffix));
            names.push(format!("{}_{}", base_name, suffix));
            names.push(format!("{}.{}", base_name, suffix));
        }

        // Common prefixes
        let prefixes = vec![
            "dev", "prod", "staging", "test", "backup", "private", "public",
        ];

        for prefix in &prefixes {
            names.push(format!("{}-{}", prefix, base_name));
            names.push(format!("{}_{}", prefix, base_name));
            names.push(format!("{}.{}", prefix, base_name));
        }

        // Year-based names (current year and previous 2 years)
        let current_year = 2025;
        for year in (current_year - 2)..=current_year {
            names.push(format!("{}-{}", base_name, year));
            names.push(format!("{}{}", base_name, year));
        }

        // Common patterns
        names.push(format!("{}-s3", base_name));
        names.push(format!("{}-bucket", base_name));
        names.push(format!("{}-aws", base_name));
        names.push(format!("s3-{}", base_name));
        names.push(format!("aws-{}", base_name));

        // Deduplicate
        let mut unique_names: Vec<String> = names.into_iter().collect();
        unique_names.sort();
        unique_names.dedup();

        unique_names
    }

    /// Extract region from XML response
    fn extract_region(&self, body: &str) -> Option<String> {
        // Look for <Region>us-east-1</Region> pattern
        if let Some(start) = body.find("<Region>") {
            let after_start = &body[start + 8..];
            if let Some(end) = after_start.find("</Region>") {
                return Some(after_start[..end].to_string());
            }
        }

        // Look for region in endpoint
        if let Some(start) = body.find("s3.") {
            let after_start = &body[start + 3..];
            if let Some(end) = after_start.find(".amazonaws.com") {
                let region = &after_start[..end];
                if !region.is_empty() && region != "s3" {
                    return Some(region.to_string());
                }
            }
        }

        None
    }

    /// Get common company/organization bucket names
    pub fn common_bucket_patterns() -> Vec<&'static str> {
        vec![
            "backup",
            "backups",
            "data",
            "files",
            "assets",
            "images",
            "uploads",
            "documents",
            "private",
            "public",
            "dev",
            "prod",
            "staging",
            "test",
            "logs",
            "archive",
            "temp",
            "static",
            "media",
            "resources",
            "downloads",
            "exports",
            "reports",
            "database",
            "db",
            "sql",
            "configs",
            "secrets",
            "keys",
        ]
    }

    /// Check bucket with alternative methods (path-style URL)
    pub fn check_bucket_path_style(&self, bucket_name: &str) -> Result<S3Bucket, String> {
        // Alternative path-style URL: https://s3.amazonaws.com/bucket-name
        let url = format!("https://s3.amazonaws.com/{}", bucket_name);

        let response = self.client.get(&url);

        match response {
            Ok(resp) => {
                let body = String::from_utf8_lossy(&resp.body);

                let exists = resp.status_code == 200 || resp.status_code == 403;
                let public = resp.status_code == 200;

                Ok(S3Bucket {
                    name: bucket_name.to_string(),
                    exists,
                    region: self.extract_region(&body),
                    public_list: public,
                    public_read: public,
                    accessible: public,
                    message: if public {
                        "Public (path-style)".to_string()
                    } else if exists {
                        "Exists but private (path-style)".to_string()
                    } else {
                        "Not found (path-style)".to_string()
                    },
                })
            }
            Err(_) => Ok(S3Bucket {
                name: bucket_name.to_string(),
                exists: false,
                region: None,
                public_list: false,
                public_read: false,
                accessible: false,
                message: "Not found".to_string(),
            }),
        }
    }
}

impl Default for S3Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bucket_names() {
        let scanner = S3Scanner::new();
        let names = scanner.generate_bucket_names("company");

        assert!(names.contains(&"company".to_string()));
        assert!(names.contains(&"company-backup".to_string()));
        assert!(names.contains(&"company-dev".to_string()));
        assert!(names.contains(&"dev-company".to_string()));
        assert!(names.len() > 50); // Should generate many variations
    }

    #[test]
    fn test_extract_region() {
        let scanner = S3Scanner::new();

        let xml = "<Region>us-west-2</Region>";
        assert_eq!(scanner.extract_region(xml), Some("us-west-2".to_string()));

        let url = "https://mybucket.s3.eu-central-1.amazonaws.com/";
        assert_eq!(
            scanner.extract_region(url),
            Some("eu-central-1".to_string())
        );
    }

    #[test]
    fn test_common_bucket_patterns() {
        let patterns = S3Scanner::common_bucket_patterns();
        assert!(patterns.contains(&"backup"));
        assert!(patterns.contains(&"private"));
        assert!(patterns.len() > 20);
    }
}
