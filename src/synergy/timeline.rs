/// Timeline for Audit Trail and Temporal Analysis
///
/// Tracks all operations chronologically for:
/// - Forensic analysis
/// - Attack chain visualization
/// - Change detection / diffing
/// - Compliance audit trail
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::events::{EntityRef, EntityType, EventType, MitreAttack};

/// Timeline entry representing a recorded action
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    /// Entry ID
    pub id: u64,
    /// Timestamp (Unix millis)
    pub timestamp: u64,
    /// Action type
    pub action_type: TimelineAction,
    /// Source module or user
    pub source: String,
    /// Primary entity involved
    pub entity: Option<EntityRef>,
    /// Related entities
    pub related: Vec<EntityRef>,
    /// Action description
    pub description: String,
    /// Result status
    pub status: TimelineStatus,
    /// MITRE ATT&CK mapping
    pub mitre: Option<MitreAttack>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of timeline actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimelineAction {
    /// Command executed by user
    CommandExecuted,
    /// Scan started
    ScanStarted,
    /// Scan completed
    ScanCompleted,
    /// Entity discovered
    EntityDiscovered,
    /// Entity updated/enriched
    EntityUpdated,
    /// Vulnerability found
    VulnFound,
    /// Credential found
    CredentialFound,
    /// Authentication attempted
    AuthAttempted,
    /// Access gained
    AccessGained,
    /// Session established
    SessionEstablished,
    /// Lateral movement
    LateralMovement,
    /// Data exfiltration
    DataExfiltrated,
    /// Exploit executed
    ExploitExecuted,
    /// Task created
    TaskCreated,
    /// Task completed
    TaskCompleted,
    /// Configuration changed
    ConfigChanged,
    /// Alert triggered
    AlertTriggered,
    /// Custom action
    Custom,
}

impl std::fmt::Display for TimelineAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelineAction::CommandExecuted => write!(f, "COMMAND"),
            TimelineAction::ScanStarted => write!(f, "SCAN_START"),
            TimelineAction::ScanCompleted => write!(f, "SCAN_END"),
            TimelineAction::EntityDiscovered => write!(f, "DISCOVERY"),
            TimelineAction::EntityUpdated => write!(f, "UPDATE"),
            TimelineAction::VulnFound => write!(f, "VULN"),
            TimelineAction::CredentialFound => write!(f, "CRED"),
            TimelineAction::AuthAttempted => write!(f, "AUTH"),
            TimelineAction::AccessGained => write!(f, "ACCESS"),
            TimelineAction::SessionEstablished => write!(f, "SESSION"),
            TimelineAction::LateralMovement => write!(f, "LATERAL"),
            TimelineAction::DataExfiltrated => write!(f, "EXFIL"),
            TimelineAction::ExploitExecuted => write!(f, "EXPLOIT"),
            TimelineAction::TaskCreated => write!(f, "TASK_NEW"),
            TimelineAction::TaskCompleted => write!(f, "TASK_DONE"),
            TimelineAction::ConfigChanged => write!(f, "CONFIG"),
            TimelineAction::AlertTriggered => write!(f, "ALERT"),
            TimelineAction::Custom => write!(f, "CUSTOM"),
        }
    }
}

/// Status of a timeline entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineStatus {
    Success,
    Failure,
    Partial,
    Pending,
    Skipped,
    Unknown,
}

impl std::fmt::Display for TimelineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelineStatus::Success => write!(f, "OK"),
            TimelineStatus::Failure => write!(f, "FAIL"),
            TimelineStatus::Partial => write!(f, "PARTIAL"),
            TimelineStatus::Pending => write!(f, "PENDING"),
            TimelineStatus::Skipped => write!(f, "SKIP"),
            TimelineStatus::Unknown => write!(f, "?"),
        }
    }
}

impl TimelineEntry {
    /// Create a new timeline entry
    pub fn new(action_type: TimelineAction, source: impl Into<String>) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            timestamp: current_timestamp_millis(),
            action_type,
            source: source.into(),
            entity: None,
            related: Vec::new(),
            description: String::new(),
            status: TimelineStatus::Success,
            mitre: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_entity(mut self, entity: EntityRef) -> Self {
        self.entity = Some(entity);
        self
    }

    pub fn with_related(mut self, entity: EntityRef) -> Self {
        self.related.push(entity);
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_status(mut self, status: TimelineStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_mitre(mut self, mitre: MitreAttack) -> Self {
        self.mitre = Some(mitre);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Convert from Event
    pub fn from_event(event: &super::events::Event) -> Self {
        let action_type = match event.event_type {
            EventType::Discovery => TimelineAction::EntityDiscovered,
            EventType::Enrichment => TimelineAction::EntityUpdated,
            EventType::VulnFound => TimelineAction::VulnFound,
            EventType::CredentialFound => TimelineAction::CredentialFound,
            EventType::AccessGained => TimelineAction::AccessGained,
            EventType::SessionEstablished => TimelineAction::SessionEstablished,
            EventType::LateralMovement => TimelineAction::LateralMovement,
            EventType::DataExfiltrated => TimelineAction::DataExfiltrated,
            EventType::TaskStarted => TimelineAction::TaskCreated,
            EventType::TaskCompleted => TimelineAction::TaskCompleted,
            EventType::Error => TimelineAction::Custom,
            EventType::Custom => TimelineAction::Custom,
        };

        let mut entry = Self {
            id: event.id,
            timestamp: event.timestamp,
            action_type,
            source: event.source_module.clone(),
            entity: event.entity.clone(),
            related: event.related.clone(),
            description: String::new(),
            status: TimelineStatus::Success,
            mitre: event.metadata.mitre.clone(),
            metadata: HashMap::new(),
        };

        // Copy data to metadata
        for (k, v) in &event.data {
            entry.metadata.insert(k.clone(), v.clone());
        }

        entry
    }
}

/// Query parameters for timeline search
#[derive(Debug, Clone, Default)]
pub struct TimelineQuery {
    /// Start time (Unix millis)
    pub start_time: Option<u64>,
    /// End time (Unix millis)
    pub end_time: Option<u64>,
    /// Filter by action types
    pub action_types: Option<Vec<TimelineAction>>,
    /// Filter by entity type
    pub entity_type: Option<EntityType>,
    /// Filter by entity ID (partial match)
    pub entity_id: Option<String>,
    /// Filter by source module
    pub source: Option<String>,
    /// Filter by status
    pub status: Option<TimelineStatus>,
    /// Filter by MITRE technique
    pub mitre_technique: Option<String>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

impl TimelineQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn in_range(mut self, start: u64, end: u64) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    pub fn last_hours(mut self, hours: u64) -> Self {
        let now = current_timestamp_millis();
        self.start_time = Some(now.saturating_sub(hours * 3600 * 1000));
        self.end_time = Some(now);
        self
    }

    pub fn with_action_types(mut self, types: Vec<TimelineAction>) -> Self {
        self.action_types = Some(types);
        self
    }

    pub fn with_entity_type(mut self, entity_type: EntityType) -> Self {
        self.entity_type = Some(entity_type);
        self
    }

    pub fn with_entity_id(mut self, id: impl Into<String>) -> Self {
        self.entity_id = Some(id.into());
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn with_status(mut self, status: TimelineStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_mitre(mut self, technique: impl Into<String>) -> Self {
        self.mitre_technique = Some(technique.into());
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Timeline storage and query engine
pub struct Timeline {
    entries: RwLock<Vec<TimelineEntry>>,
    max_entries: usize,
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Timeline {
    /// Create a new timeline
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            max_entries: 100000,
        }
    }

    /// Create timeline with custom max size
    pub fn with_max_entries(max: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            max_entries: max,
        }
    }

    /// Record a timeline entry
    pub fn record(&self, entry: TimelineEntry) -> u64 {
        let id = entry.id;
        let mut entries = self.entries.write().unwrap();
        entries.push(entry);

        // Trim if over max size
        if entries.len() > self.max_entries {
            let drain_count = entries.len() - self.max_entries;
            entries.drain(0..drain_count);
        }

        id
    }

    /// Record from an event
    pub fn record_event(&self, event: &super::events::Event) -> u64 {
        self.record(TimelineEntry::from_event(event))
    }

    /// Query timeline entries
    pub fn query(&self, query: &TimelineQuery) -> Vec<TimelineEntry> {
        let entries = self.entries.read().unwrap();

        let mut results: Vec<_> = entries
            .iter()
            .filter(|entry| {
                // Time range filter
                if let Some(start) = query.start_time {
                    if entry.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = query.end_time {
                    if entry.timestamp > end {
                        return false;
                    }
                }

                // Action type filter
                if let Some(ref types) = query.action_types {
                    if !types.contains(&entry.action_type) {
                        return false;
                    }
                }

                // Entity type filter
                if let Some(ref et) = query.entity_type {
                    if entry.entity.as_ref().map(|e| &e.entity_type) != Some(et) {
                        return false;
                    }
                }

                // Entity ID filter
                if let Some(ref id) = query.entity_id {
                    if !entry.entity.as_ref().map_or(false, |e| e.id.contains(id)) {
                        return false;
                    }
                }

                // Source filter
                if let Some(ref source) = query.source {
                    if !entry.source.contains(source) {
                        return false;
                    }
                }

                // Status filter
                if let Some(status) = query.status {
                    if entry.status != status {
                        return false;
                    }
                }

                // MITRE filter
                if let Some(ref technique) = query.mitre_technique {
                    if !entry
                        .mitre
                        .as_ref()
                        .map_or(false, |m| &m.technique_id == technique)
                    {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Apply offset
        if let Some(offset) = query.offset {
            if offset < results.len() {
                results = results.into_iter().skip(offset).collect();
            } else {
                results.clear();
            }
        }

        // Apply limit
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        results
    }

    /// Get recent entries
    pub fn recent(&self, count: usize) -> Vec<TimelineEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get entries for a specific entity
    pub fn for_entity(&self, entity_type: EntityType, entity_id: &str) -> Vec<TimelineEntry> {
        self.query(
            &TimelineQuery::new()
                .with_entity_type(entity_type)
                .with_entity_id(entity_id),
        )
    }

    /// Get entry count
    pub fn count(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Clear timeline
    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
    }

    /// Export to JSON format
    pub fn export_json(&self, query: &TimelineQuery) -> String {
        let entries = self.query(query);
        let mut output = String::from("[\n");

        for (i, entry) in entries.iter().enumerate() {
            if i > 0 {
                output.push_str(",\n");
            }
            output.push_str(&format!(
                r#"  {{"id": {}, "timestamp": {}, "action": "{}", "source": "{}", "status": "{}", "description": "{}"}}"#,
                entry.id,
                entry.timestamp,
                entry.action_type,
                entry.source,
                entry.status,
                entry.description.replace('"', "\\\""),
            ));
        }

        output.push_str("\n]");
        output
    }

    /// Compute diff between two time points
    pub fn diff(&self, before: u64, after: u64) -> TimelineDiff {
        let entries = self.entries.read().unwrap();

        let before_entries: Vec<_> = entries.iter().filter(|e| e.timestamp <= before).collect();

        let after_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.timestamp > before && e.timestamp <= after)
            .collect();

        let new_discoveries = after_entries
            .iter()
            .filter(|e| e.action_type == TimelineAction::EntityDiscovered)
            .count();

        let new_vulns = after_entries
            .iter()
            .filter(|e| e.action_type == TimelineAction::VulnFound)
            .count();

        let new_creds = after_entries
            .iter()
            .filter(|e| e.action_type == TimelineAction::CredentialFound)
            .count();

        TimelineDiff {
            before_count: before_entries.len(),
            after_count: before_entries.len() + after_entries.len(),
            new_entries: after_entries.len(),
            new_discoveries,
            new_vulns,
            new_creds,
        }
    }
}

/// Result of timeline diff operation
#[derive(Debug, Clone)]
pub struct TimelineDiff {
    pub before_count: usize,
    pub after_count: usize,
    pub new_entries: usize,
    pub new_discoveries: usize,
    pub new_vulns: usize,
    pub new_creds: usize,
}

// Global timeline singleton
static GLOBAL_TIMELINE: OnceLock<Timeline> = OnceLock::new();

/// Get the global timeline
pub fn global_timeline() -> &'static Timeline {
    GLOBAL_TIMELINE.get_or_init(Timeline::new)
}

/// Record an entry to the global timeline
pub fn record(entry: TimelineEntry) -> u64 {
    global_timeline().record(entry)
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

    #[test]
    fn test_timeline_entry_creation() {
        let entry = TimelineEntry::new(TimelineAction::ScanStarted, "scanner")
            .with_description("Port scan of 192.168.1.0/24")
            .with_status(TimelineStatus::Success);

        assert_eq!(entry.action_type, TimelineAction::ScanStarted);
        assert_eq!(entry.source, "scanner");
        assert_eq!(entry.status, TimelineStatus::Success);
    }

    #[test]
    fn test_timeline_query() {
        let timeline = Timeline::new();

        // Add some entries
        timeline.record(TimelineEntry::new(TimelineAction::ScanStarted, "scanner"));
        timeline.record(TimelineEntry::new(
            TimelineAction::EntityDiscovered,
            "scanner",
        ));
        timeline.record(TimelineEntry::new(
            TimelineAction::VulnFound,
            "vuln_scanner",
        ));
        timeline.record(TimelineEntry::new(
            TimelineAction::EntityDiscovered,
            "scanner",
        ));

        // Query all
        let all = timeline.query(&TimelineQuery::new());
        assert_eq!(all.len(), 4);

        // Query by action type
        let discoveries = timeline
            .query(&TimelineQuery::new().with_action_types(vec![TimelineAction::EntityDiscovered]));
        assert_eq!(discoveries.len(), 2);

        // Query by source
        let scanner_entries = timeline.query(&TimelineQuery::new().with_source("scanner"));
        assert_eq!(scanner_entries.len(), 3);
    }

    #[test]
    fn test_timeline_limit() {
        let timeline = Timeline::new();

        for i in 0..10 {
            timeline.record(
                TimelineEntry::new(TimelineAction::EntityDiscovered, "scanner")
                    .with_description(format!("Entry {}", i)),
            );
        }

        let limited = timeline.query(&TimelineQuery::new().with_limit(5));
        assert_eq!(limited.len(), 5);

        let offset = timeline.query(&TimelineQuery::new().with_offset(5).with_limit(3));
        assert_eq!(offset.len(), 3);
    }
}
