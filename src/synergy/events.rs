/// Event System for Cross-Module Communication
///
/// Provides pub/sub event bus for the synergy layer.
/// Events flow from producers (scanning modules) to consumers (correlation rules).
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Event types emitted by modules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// New entity discovered (host, port, service, etc.)
    Discovery,
    /// Existing entity enriched with new data
    Enrichment,
    /// Vulnerability found
    VulnFound,
    /// Credential found (password, token, key)
    CredentialFound,
    /// Access gained to a system
    AccessGained,
    /// Session established
    SessionEstablished,
    /// Lateral movement detected
    LateralMovement,
    /// Data exfiltrated (loot)
    DataExfiltrated,
    /// Task started
    TaskStarted,
    /// Task completed
    TaskCompleted,
    /// Error occurred
    Error,
    /// Custom event type
    Custom,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Discovery => write!(f, "DISCOVERY"),
            EventType::Enrichment => write!(f, "ENRICHMENT"),
            EventType::VulnFound => write!(f, "VULN_FOUND"),
            EventType::CredentialFound => write!(f, "CREDENTIAL_FOUND"),
            EventType::AccessGained => write!(f, "ACCESS_GAINED"),
            EventType::SessionEstablished => write!(f, "SESSION_ESTABLISHED"),
            EventType::LateralMovement => write!(f, "LATERAL_MOVEMENT"),
            EventType::DataExfiltrated => write!(f, "DATA_EXFILTRATED"),
            EventType::TaskStarted => write!(f, "TASK_STARTED"),
            EventType::TaskCompleted => write!(f, "TASK_COMPLETED"),
            EventType::Error => write!(f, "ERROR"),
            EventType::Custom => write!(f, "CUSTOM"),
        }
    }
}

/// Entity type for event targeting
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    Host,
    Port,
    Service,
    Credential,
    Vulnerability,
    Session,
    User,
    Domain,
    Certificate,
    Technology,
    Endpoint,
    Loot,
    Url,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityType::Host => write!(f, "Host"),
            EntityType::Port => write!(f, "Port"),
            EntityType::Service => write!(f, "Service"),
            EntityType::Credential => write!(f, "Credential"),
            EntityType::Vulnerability => write!(f, "Vulnerability"),
            EntityType::Session => write!(f, "Session"),
            EntityType::User => write!(f, "User"),
            EntityType::Domain => write!(f, "Domain"),
            EntityType::Certificate => write!(f, "Certificate"),
            EntityType::Technology => write!(f, "Technology"),
            EntityType::Endpoint => write!(f, "Endpoint"),
            EntityType::Loot => write!(f, "Loot"),
            EntityType::Url => write!(f, "Url"),
        }
    }
}

/// Entity reference with type and ID
#[derive(Debug, Clone)]
pub struct EntityRef {
    pub entity_type: EntityType,
    pub id: String,
    pub label: Option<String>,
}

impl EntityRef {
    pub fn host(id: impl Into<String>) -> Self {
        Self {
            entity_type: EntityType::Host,
            id: id.into(),
            label: None,
        }
    }

    pub fn service(id: impl Into<String>) -> Self {
        Self {
            entity_type: EntityType::Service,
            id: id.into(),
            label: None,
        }
    }

    pub fn credential(id: impl Into<String>) -> Self {
        Self {
            entity_type: EntityType::Credential,
            id: id.into(),
            label: None,
        }
    }

    pub fn vulnerability(id: impl Into<String>) -> Self {
        Self {
            entity_type: EntityType::Vulnerability,
            id: id.into(),
            label: None,
        }
    }

    pub fn url(id: impl Into<String>) -> Self {
        Self {
            entity_type: EntityType::Url,
            id: id.into(),
            label: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// MITRE ATT&CK technique reference
#[derive(Debug, Clone)]
pub struct MitreAttack {
    /// Technique ID (e.g., "T1046")
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Tactic (e.g., "Discovery")
    pub tactic: String,
    /// Sub-technique ID if applicable
    pub sub_technique: Option<String>,
}

impl MitreAttack {
    pub fn new(
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        tactic: impl Into<String>,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            tactic: tactic.into(),
            sub_technique: None,
        }
    }

    /// Create from just technique ID (name and tactic will be generic)
    pub fn from_id(technique_id: impl Into<String>) -> Self {
        let id = technique_id.into();
        Self {
            technique_id: id,
            technique_name: String::new(),
            tactic: String::new(),
            sub_technique: None,
        }
    }

    /// Port scanning - T1046
    pub fn port_scan() -> Self {
        Self::new("T1046", "Network Service Discovery", "Discovery")
    }

    /// Credential harvesting - T1003
    pub fn credential_dumping() -> Self {
        Self::new("T1003", "OS Credential Dumping", "Credential Access")
    }

    /// Remote services - T1021
    pub fn remote_services() -> Self {
        Self::new("T1021", "Remote Services", "Lateral Movement")
    }

    /// Exploitation - T1190
    pub fn exploit_public_app() -> Self {
        Self::new(
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
        )
    }

    /// Brute force - T1110
    pub fn brute_force() -> Self {
        Self::new("T1110", "Brute Force", "Credential Access")
    }

    /// Valid accounts - T1078
    pub fn valid_accounts() -> Self {
        Self::new("T1078", "Valid Accounts", "Defense Evasion")
    }

    /// Data from local system - T1005
    pub fn data_from_local() -> Self {
        Self::new("T1005", "Data from Local System", "Collection")
    }
}

/// Event metadata
#[derive(Debug, Clone)]
pub struct EventMetadata {
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Severity (0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical)
    pub severity: u8,
    /// MITRE ATT&CK mapping
    pub mitre: Option<MitreAttack>,
    /// Custom tags
    pub tags: Vec<String>,
    /// Additional key-value data
    pub extra: HashMap<String, String>,
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self {
            confidence: 1.0,
            severity: 0,
            mitre: None,
            tags: Vec::new(),
            extra: HashMap::new(),
        }
    }
}

impl EventMetadata {
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity.min(4);
        self
    }

    pub fn with_mitre(mut self, mitre: MitreAttack) -> Self {
        self.mitre = Some(mitre);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

/// Event emitted by modules
#[derive(Debug, Clone)]
pub struct Event {
    /// Unique event ID
    pub id: u64,
    /// Event type
    pub event_type: EventType,
    /// Source module name
    pub source_module: String,
    /// Primary entity affected
    pub entity: Option<EntityRef>,
    /// Related entities
    pub related: Vec<EntityRef>,
    /// Event timestamp (Unix millis)
    pub timestamp: u64,
    /// Event data (JSON-like key-value)
    pub data: HashMap<String, String>,
    /// Metadata
    pub metadata: EventMetadata,
}

impl Event {
    /// Create a new event
    pub fn new(event_type: EventType, source_module: impl Into<String>) -> Self {
        Self {
            id: generate_event_id(),
            event_type,
            source_module: source_module.into(),
            entity: None,
            related: Vec::new(),
            timestamp: current_timestamp_millis(),
            data: HashMap::new(),
            metadata: EventMetadata::default(),
        }
    }

    /// Set the primary entity
    pub fn with_entity(mut self, entity: EntityRef) -> Self {
        self.entity = Some(entity);
        self
    }

    /// Add a related entity
    pub fn with_related(mut self, entity: EntityRef) -> Self {
        self.related.push(entity);
        self
    }

    /// Add data field
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: EventMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.metadata.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: u8) -> Self {
        self.metadata.severity = severity.min(4);
        self
    }

    /// Set MITRE ATT&CK mapping
    pub fn with_mitre(mut self, mitre: MitreAttack) -> Self {
        self.metadata.mitre = Some(mitre);
        self
    }
}

/// Event handler trait
pub trait EventHandler: Send + Sync {
    /// Handle an event, return true if handled
    fn handle(&self, event: &Event) -> bool;

    /// Filter for event types this handler cares about
    fn event_types(&self) -> Option<Vec<EventType>> {
        None // None = all events
    }

    /// Filter for entity types this handler cares about
    fn entity_types(&self) -> Option<Vec<EntityType>> {
        None // None = all entity types
    }

    /// Handler name for debugging
    fn name(&self) -> &str {
        "unnamed"
    }
}

/// Subscription to event bus
struct Subscription {
    handler: Arc<dyn EventHandler>,
    event_filter: Option<Vec<EventType>>,
    entity_filter: Option<Vec<EntityType>>,
}

/// Event bus for pub/sub messaging
pub struct EventBus {
    subscriptions: RwLock<Vec<Subscription>>,
    event_log: RwLock<Vec<Event>>,
    max_log_size: usize,
    next_id: RwLock<u64>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a new event bus
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(Vec::new()),
            event_log: RwLock::new(Vec::new()),
            max_log_size: 10000,
            next_id: RwLock::new(1),
        }
    }

    /// Subscribe a handler to the event bus
    pub fn subscribe(&self, handler: Arc<dyn EventHandler>) {
        let event_filter = handler.event_types();
        let entity_filter = handler.entity_types();

        let mut subs = self.subscriptions.write().unwrap();
        subs.push(Subscription {
            handler,
            event_filter,
            entity_filter,
        });
    }

    /// Publish an event to all matching subscribers
    pub fn publish(&self, mut event: Event) -> u64 {
        // Assign ID
        {
            let mut next_id = self.next_id.write().unwrap();
            event.id = *next_id;
            *next_id += 1;
        }

        let event_id = event.id;

        // Store in log
        {
            let mut log = self.event_log.write().unwrap();
            log.push(event.clone());

            // Trim if over max size
            if log.len() > self.max_log_size {
                let drain_count = log.len() - self.max_log_size;
                log.drain(0..drain_count);
            }
        }

        // Dispatch to subscribers
        let subs = self.subscriptions.read().unwrap();
        for sub in subs.iter() {
            // Check event type filter
            if let Some(ref filter) = sub.event_filter {
                if !filter.contains(&event.event_type) {
                    continue;
                }
            }

            // Check entity type filter
            if let Some(ref filter) = sub.entity_filter {
                if let Some(ref entity) = event.entity {
                    if !filter.contains(&entity.entity_type) {
                        continue;
                    }
                }
            }

            // Dispatch to handler
            sub.handler.handle(&event);
        }

        event_id
    }

    /// Get recent events
    pub fn recent_events(&self, count: usize) -> Vec<Event> {
        let log = self.event_log.read().unwrap();
        log.iter().rev().take(count).cloned().collect()
    }

    /// Query events by type
    pub fn events_by_type(&self, event_type: EventType) -> Vec<Event> {
        let log = self.event_log.read().unwrap();
        log.iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Query events by entity
    pub fn events_for_entity(&self, entity_type: EntityType, entity_id: &str) -> Vec<Event> {
        let log = self.event_log.read().unwrap();
        log.iter()
            .filter(|e| {
                if let Some(ref entity) = e.entity {
                    entity.entity_type == entity_type && entity.id == entity_id
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    /// Query events in time range
    pub fn events_in_range(&self, start_ms: u64, end_ms: u64) -> Vec<Event> {
        let log = self.event_log.read().unwrap();
        log.iter()
            .filter(|e| e.timestamp >= start_ms && e.timestamp <= end_ms)
            .cloned()
            .collect()
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.event_log.read().unwrap().len()
    }

    /// Clear event log
    pub fn clear(&self) {
        self.event_log.write().unwrap().clear();
    }
}

// Global event bus singleton
static GLOBAL_BUS: OnceLock<EventBus> = OnceLock::new();

/// Get the global event bus
pub fn global_bus() -> &'static EventBus {
    GLOBAL_BUS.get_or_init(EventBus::new)
}

/// Emit an event to the global bus
pub fn emit(event: Event) -> u64 {
    global_bus().publish(event)
}

/// Subscribe a handler to the global bus
pub fn subscribe(handler: Arc<dyn EventHandler>) {
    global_bus().subscribe(handler);
}

// Helper functions

fn generate_event_id() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler {
        received: std::sync::Mutex<Vec<EventType>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                received: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn received_count(&self) -> usize {
            self.received.lock().unwrap().len()
        }
    }

    impl EventHandler for TestHandler {
        fn handle(&self, event: &Event) -> bool {
            self.received.lock().unwrap().push(event.event_type);
            true
        }

        fn name(&self) -> &str {
            "test"
        }
    }

    #[test]
    fn test_event_creation() {
        let event = Event::new(EventType::Discovery, "scanner")
            .with_entity(EntityRef::host("192.168.1.1"))
            .with_data("ports", "80,443")
            .with_mitre(MitreAttack::port_scan());

        assert_eq!(event.event_type, EventType::Discovery);
        assert_eq!(event.source_module, "scanner");
        assert!(event.entity.is_some());
        assert!(event.metadata.mitre.is_some());
    }

    #[test]
    fn test_event_bus_pubsub() {
        let bus = EventBus::new();
        let handler = Arc::new(TestHandler::new());

        bus.subscribe(handler.clone());

        bus.publish(Event::new(EventType::Discovery, "scanner"));
        bus.publish(Event::new(EventType::VulnFound, "vuln_scanner"));

        assert_eq!(handler.received_count(), 2);
        assert_eq!(bus.event_count(), 2);
    }

    #[test]
    fn test_event_filtering() {
        struct FilteredHandler;

        impl EventHandler for FilteredHandler {
            fn handle(&self, _event: &Event) -> bool {
                true
            }

            fn event_types(&self) -> Option<Vec<EventType>> {
                Some(vec![EventType::VulnFound])
            }

            fn name(&self) -> &str {
                "filtered"
            }
        }

        let bus = EventBus::new();
        let handler = Arc::new(TestHandler::new());
        let filtered = Arc::new(FilteredHandler);

        bus.subscribe(handler.clone());
        bus.subscribe(filtered);

        bus.publish(Event::new(EventType::Discovery, "scanner"));
        bus.publish(Event::new(EventType::VulnFound, "vuln_scanner"));

        // TestHandler receives both, FilteredHandler receives only VulnFound
        assert_eq!(handler.received_count(), 2);
    }
}
