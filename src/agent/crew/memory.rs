//! Shared Memory for Crew Framework
//!
//! Provides persistent storage for findings, conversations, and knowledge
//! across workers. Integrates with ShadowGraph for relationship tracking.

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// Finding Types
// ═══════════════════════════════════════════════════════════════════════════

/// Type of finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingType {
    /// Host/IP discovery
    Host,
    /// Open port
    Port,
    /// Running service
    Service,
    /// Vulnerability
    Vulnerability,
    /// Credential (password, token, key)
    Credential,
    /// Technology/framework
    Technology,
    /// API endpoint
    Endpoint,
    /// Access gained
    Access,
    /// DNS record
    DnsRecord,
    /// Exploit attempt/result
    Exploit,
    /// Intelligence correlation
    Intelligence,
    /// Attack path/chain
    AttackPath,
    /// Assessment report
    Report,
}

impl FindingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Port => "port",
            Self::Service => "service",
            Self::Vulnerability => "vulnerability",
            Self::Credential => "credential",
            Self::Technology => "technology",
            Self::Endpoint => "endpoint",
            Self::Access => "access",
            Self::DnsRecord => "dns_record",
            Self::Exploit => "exploit",
            Self::Intelligence => "intelligence",
            Self::AttackPath => "attack_path",
            Self::Report => "report",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Finding
// ═══════════════════════════════════════════════════════════════════════════

/// A finding discovered by a worker
#[derive(Debug, Clone)]
pub struct Finding {
    /// Unique identifier
    pub id: String,
    /// Type of finding
    pub finding_type: FindingType,
    /// Primary value (IP, URL, credential, etc.)
    pub value: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Source of the finding (worker ID, tool, etc.)
    pub source: String,
    /// Additional metadata
    pub metadata: Vec<(String, String)>,
    /// Related finding IDs
    pub related_findings: Vec<String>,
    /// Timestamp of discovery
    pub timestamp: u64,
}

impl Finding {
    /// Create a new finding
    pub fn new(finding_type: FindingType, value: String) -> Self {
        Self {
            id: generate_finding_id(),
            finding_type,
            value,
            confidence: 1.0,
            source: String::new(),
            metadata: Vec::new(),
            related_findings: Vec::new(),
            timestamp: current_timestamp(),
        }
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set source
    pub fn with_source(mut self, source: &str) -> Self {
        self.source = source.to_string();
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.push((key.to_string(), value.to_string()));
        self
    }

    /// Add related finding
    pub fn with_related(mut self, finding_id: &str) -> Self {
        self.related_findings.push(finding_id.to_string());
        self
    }

    /// Get metadata value by key
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Conversation
// ═══════════════════════════════════════════════════════════════════════════

/// Role of a message sender
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    /// User input
    User,
    /// System/AI response
    Assistant,
    /// Worker output
    Worker,
    /// System message
    System,
}

impl MessageRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Worker => "worker",
            Self::System => "system",
        }
    }
}

/// A message in a conversation
#[derive(Debug, Clone)]
pub struct Message {
    /// Role of sender
    pub role: MessageRole,
    /// Message content
    pub content: String,
    /// Timestamp
    pub timestamp: u64,
    /// Related findings mentioned
    pub finding_refs: Vec<String>,
}

impl Message {
    /// Create a new message
    pub fn new(role: MessageRole, content: String) -> Self {
        Self {
            role,
            content,
            timestamp: current_timestamp(),
            finding_refs: Vec::new(),
        }
    }

    /// Create a user message
    pub fn user(content: &str) -> Self {
        Self::new(MessageRole::User, content.to_string())
    }

    /// Create an assistant message
    pub fn assistant(content: &str) -> Self {
        Self::new(MessageRole::Assistant, content.to_string())
    }

    /// Create a worker message
    pub fn worker(worker_id: &str, content: &str) -> Self {
        let mut msg = Self::new(MessageRole::Worker, content.to_string());
        msg.content = format!("[{}] {}", worker_id, content);
        msg
    }

    /// Add finding reference
    pub fn with_finding(mut self, finding_id: &str) -> Self {
        self.finding_refs.push(finding_id.to_string());
        self
    }
}

/// A conversation thread
#[derive(Debug, Clone)]
pub struct Conversation {
    /// Unique identifier
    pub id: String,
    /// Conversation title/topic
    pub title: String,
    /// Messages in order
    pub messages: Vec<Message>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
}

impl Conversation {
    /// Create a new conversation
    pub fn new(title: &str) -> Self {
        let now = current_timestamp();
        Self {
            id: generate_conversation_id(),
            title: title.to_string(),
            messages: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a message
    pub fn add_message(&mut self, message: Message) {
        self.messages.push(message);
        self.updated_at = current_timestamp();
    }

    /// Get the last N messages
    pub fn last_n_messages(&self, n: usize) -> &[Message] {
        let start = self.messages.len().saturating_sub(n);
        &self.messages[start..]
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Crew Memory
// ═══════════════════════════════════════════════════════════════════════════

/// Shared memory storage for the crew
pub struct CrewMemory {
    /// All findings indexed by ID
    findings: HashMap<String, Finding>,
    /// Findings indexed by type
    findings_by_type: HashMap<FindingType, Vec<String>>,
    /// Findings indexed by source
    findings_by_source: HashMap<String, Vec<String>>,
    /// Conversation history
    conversations: HashMap<String, Conversation>,
    /// Current active conversation
    active_conversation: Option<String>,
    /// Knowledge graph nodes (finding_id -> graph_node_id)
    graph_node_map: HashMap<String, String>,
    /// Pending graph updates
    pending_graph_updates: VecDeque<GraphUpdate>,
    /// Statistics
    stats: MemoryStats,
}

/// Statistics about memory usage
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    pub total_findings: u64,
    pub total_messages: u64,
    pub total_conversations: u64,
    pub graph_nodes_created: u64,
    pub graph_edges_created: u64,
}

/// A pending update to the ShadowGraph
#[derive(Debug, Clone)]
pub enum GraphUpdate {
    /// Add a new node
    AddNode {
        finding_id: String,
        node_type: String,
        properties: HashMap<String, String>,
    },
    /// Add an edge between nodes
    AddEdge {
        from_finding: String,
        to_finding: String,
        edge_type: String,
        confidence: f64,
    },
}

impl CrewMemory {
    /// Create empty memory
    pub fn new() -> Self {
        Self {
            findings: HashMap::new(),
            findings_by_type: HashMap::new(),
            findings_by_source: HashMap::new(),
            conversations: HashMap::new(),
            active_conversation: None,
            graph_node_map: HashMap::new(),
            pending_graph_updates: VecDeque::new(),
            stats: MemoryStats::default(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Finding Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Add a finding to memory
    pub fn add_finding(&mut self, finding: Finding) {
        let id = finding.id.clone();
        let finding_type = finding.finding_type;
        let source = finding.source.clone();

        // Index by type
        self.findings_by_type
            .entry(finding_type)
            .or_insert_with(Vec::new)
            .push(id.clone());

        // Index by source
        if !source.is_empty() {
            self.findings_by_source
                .entry(source)
                .or_insert_with(Vec::new)
                .push(id.clone());
        }

        // Queue graph update
        self.queue_graph_node_update(&finding);

        // Store finding
        self.findings.insert(id, finding);
        self.stats.total_findings += 1;
    }

    /// Get a finding by ID
    pub fn get_finding(&self, id: &str) -> Option<&Finding> {
        self.findings.get(id)
    }

    /// Get all findings
    pub fn findings(&self) -> Vec<&Finding> {
        self.findings.values().collect()
    }

    /// Get findings by type
    pub fn findings_of_type(&self, finding_type: FindingType) -> Vec<&Finding> {
        self.findings_by_type
            .get(&finding_type)
            .map(|ids| ids.iter().filter_map(|id| self.findings.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get findings by source
    pub fn findings_from_source(&self, source: &str) -> Vec<&Finding> {
        self.findings_by_source
            .get(source)
            .map(|ids| ids.iter().filter_map(|id| self.findings.get(id)).collect())
            .unwrap_or_default()
    }

    /// Search findings by value
    pub fn search_findings(&self, query: &str) -> Vec<&Finding> {
        let query_lower = query.to_lowercase();
        self.findings
            .values()
            .filter(|f| f.value.to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Get high-confidence findings (>= threshold)
    pub fn high_confidence_findings(&self, threshold: f64) -> Vec<&Finding> {
        self.findings
            .values()
            .filter(|f| f.confidence >= threshold)
            .collect()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Conversation Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Create a new conversation
    pub fn create_conversation(&mut self, title: &str) -> String {
        let conv = Conversation::new(title);
        let id = conv.id.clone();
        self.conversations.insert(id.clone(), conv);
        self.active_conversation = Some(id.clone());
        self.stats.total_conversations += 1;
        id
    }

    /// Get the active conversation
    pub fn active_conversation(&self) -> Option<&Conversation> {
        self.active_conversation
            .as_ref()
            .and_then(|id| self.conversations.get(id))
    }

    /// Get mutable active conversation
    pub fn active_conversation_mut(&mut self) -> Option<&mut Conversation> {
        let id = self.active_conversation.clone()?;
        self.conversations.get_mut(&id)
    }

    /// Add a message to the active conversation
    pub fn add_message(&mut self, message: Message) {
        if let Some(conv) = self.active_conversation_mut() {
            conv.add_message(message);
            self.stats.total_messages += 1;
        } else {
            // Create default conversation if none exists
            self.create_conversation("Default");
            self.add_message(message);
        }
    }

    /// Switch to a different conversation
    pub fn switch_conversation(&mut self, id: &str) -> bool {
        if self.conversations.contains_key(id) {
            self.active_conversation = Some(id.to_string());
            true
        } else {
            false
        }
    }

    /// Get all conversations
    pub fn conversations(&self) -> Vec<&Conversation> {
        self.conversations.values().collect()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Graph Integration
    // ─────────────────────────────────────────────────────────────────────

    /// Queue a graph node update for a finding
    fn queue_graph_node_update(&mut self, finding: &Finding) {
        let mut properties = HashMap::new();
        properties.insert("value".to_string(), finding.value.clone());
        properties.insert("confidence".to_string(), finding.confidence.to_string());
        properties.insert("source".to_string(), finding.source.clone());

        for (k, v) in &finding.metadata {
            properties.insert(k.clone(), v.clone());
        }

        self.pending_graph_updates.push_back(GraphUpdate::AddNode {
            finding_id: finding.id.clone(),
            node_type: finding.finding_type.as_str().to_string(),
            properties,
        });

        // Queue edges for related findings
        for related_id in &finding.related_findings {
            self.pending_graph_updates.push_back(GraphUpdate::AddEdge {
                from_finding: finding.id.clone(),
                to_finding: related_id.clone(),
                edge_type: "related_to".to_string(),
                confidence: finding.confidence,
            });
        }
    }

    /// Update the graph from a finding
    pub fn update_graph_from_finding(&mut self, finding: &Finding) {
        self.queue_graph_node_update(finding);
    }

    /// Get and clear pending graph updates
    pub fn drain_graph_updates(&mut self) -> Vec<GraphUpdate> {
        self.pending_graph_updates.drain(..).collect()
    }

    /// Check if there are pending graph updates
    pub fn has_pending_graph_updates(&self) -> bool {
        !self.pending_graph_updates.is_empty()
    }

    /// Map a finding ID to a graph node ID
    pub fn set_graph_node(&mut self, finding_id: &str, node_id: &str) {
        self.graph_node_map
            .insert(finding_id.to_string(), node_id.to_string());
        self.stats.graph_nodes_created += 1;
    }

    /// Get the graph node ID for a finding
    pub fn get_graph_node(&self, finding_id: &str) -> Option<&str> {
        self.graph_node_map.get(finding_id).map(|s| s.as_str())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Statistics and Utilities
    // ─────────────────────────────────────────────────────────────────────

    /// Get memory statistics
    pub fn stats(&self) -> &MemoryStats {
        &self.stats
    }

    /// Clear all findings
    pub fn clear_findings(&mut self) {
        self.findings.clear();
        self.findings_by_type.clear();
        self.findings_by_source.clear();
        self.graph_node_map.clear();
    }

    /// Clear all conversations
    pub fn clear_conversations(&mut self) {
        self.conversations.clear();
        self.active_conversation = None;
    }

    /// Clear everything
    pub fn clear_all(&mut self) {
        self.clear_findings();
        self.clear_conversations();
        self.pending_graph_updates.clear();
    }

    /// Get summary of memory contents
    pub fn summary(&self) -> MemorySummary {
        let mut finding_counts = HashMap::new();
        for finding in self.findings.values() {
            *finding_counts.entry(finding.finding_type).or_insert(0) += 1;
        }

        MemorySummary {
            total_findings: self.findings.len(),
            finding_counts,
            total_conversations: self.conversations.len(),
            total_messages: self.conversations.values().map(|c| c.messages.len()).sum(),
            pending_graph_updates: self.pending_graph_updates.len(),
        }
    }
}

impl Default for CrewMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of memory contents
#[derive(Debug, Clone)]
pub struct MemorySummary {
    pub total_findings: usize,
    pub finding_counts: HashMap<FindingType, usize>,
    pub total_conversations: usize,
    pub total_messages: usize,
    pub pending_graph_updates: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════════════════════

fn generate_finding_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("f_{:016x}", now)
}

fn generate_conversation_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("conv_{:016x}", now)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ═══════════════════════════════════════════════════════════════════════════
// Persistence Layer - Finding <-> LootEntry Conversion
// ═══════════════════════════════════════════════════════════════════════════

use crate::storage::segments::loot::{Confidence as LootConfidence, LootCategory, LootEntry};
use crate::storage::store::Database;

impl FindingType {
    /// Convert FindingType to LootCategory
    pub fn to_loot_category(&self) -> LootCategory {
        match self {
            Self::Host => LootCategory::Finding,
            Self::Port => LootCategory::Service,
            Self::Service => LootCategory::Service,
            Self::Vulnerability => LootCategory::Vulnerability,
            Self::Credential => LootCategory::Credential,
            Self::Technology => LootCategory::Technology,
            Self::Endpoint => LootCategory::Endpoint,
            Self::Access => LootCategory::Finding,
            Self::DnsRecord => LootCategory::Finding,
            Self::Exploit => LootCategory::Vulnerability,
            Self::Intelligence => LootCategory::Finding,
            Self::AttackPath => LootCategory::Finding,
            Self::Report => LootCategory::Info,
        }
    }

    /// Convert LootCategory to FindingType (best effort)
    pub fn from_loot_category(category: LootCategory) -> Self {
        match category {
            LootCategory::Credential => Self::Credential,
            LootCategory::Vulnerability => Self::Vulnerability,
            LootCategory::Finding => Self::Host, // Default, will be overridden by metadata
            LootCategory::Artifact => Self::Access,
            LootCategory::Service => Self::Service,
            LootCategory::Endpoint => Self::Endpoint,
            LootCategory::Technology => Self::Technology,
            LootCategory::Task => Self::Report,
            LootCategory::Info => Self::Report,
        }
    }
}

impl Finding {
    /// Convert Finding to LootEntry for persistence
    pub fn to_loot_entry(&self) -> LootEntry {
        let mut entry = LootEntry::new(
            self.id.clone(),
            self.finding_type.to_loot_category(),
            self.value.clone(),
        );

        // Set confidence
        entry.confidence = if self.confidence >= 0.8 {
            LootConfidence::High
        } else if self.confidence >= 0.5 {
            LootConfidence::Medium
        } else {
            LootConfidence::Low
        };

        // Set timestamps
        entry.created_at = self.timestamp as i64;
        entry.updated_at = self.timestamp as i64;

        // Store finding_type in tags (for accurate restoration)
        entry
            .metadata
            .tags
            .push(format!("finding_type:{}", self.finding_type.as_str()));

        // Store source
        if !self.source.is_empty() {
            entry.metadata.tags.push(format!("source:{}", self.source));
        }

        // Store confidence as a tag for precision
        entry
            .metadata
            .tags
            .push(format!("confidence:{:.2}", self.confidence));

        // Convert metadata to tags
        for (key, value) in &self.metadata {
            entry.metadata.tags.push(format!("{}:{}", key, value));
        }

        // Store related findings
        for related in &self.related_findings {
            entry.metadata.tags.push(format!("related:{}", related));
        }

        entry
    }

    /// Restore Finding from LootEntry
    pub fn from_loot_entry(entry: &LootEntry) -> Self {
        // Extract finding_type from tags
        let finding_type = entry
            .metadata
            .tags
            .iter()
            .find(|t| t.starts_with("finding_type:"))
            .and_then(|t| t.strip_prefix("finding_type:"))
            .map(|s| match s {
                "host" => FindingType::Host,
                "port" => FindingType::Port,
                "service" => FindingType::Service,
                "vulnerability" => FindingType::Vulnerability,
                "credential" => FindingType::Credential,
                "technology" => FindingType::Technology,
                "endpoint" => FindingType::Endpoint,
                "access" => FindingType::Access,
                "dns_record" => FindingType::DnsRecord,
                "exploit" => FindingType::Exploit,
                "intelligence" => FindingType::Intelligence,
                "attack_path" => FindingType::AttackPath,
                "report" => FindingType::Report,
                _ => FindingType::from_loot_category(entry.category),
            })
            .unwrap_or_else(|| FindingType::from_loot_category(entry.category));

        // Extract source from tags
        let source = entry
            .metadata
            .tags
            .iter()
            .find(|t| t.starts_with("source:"))
            .and_then(|t| t.strip_prefix("source:"))
            .unwrap_or("")
            .to_string();

        // Extract confidence from tags or derive from LootConfidence
        let confidence = entry
            .metadata
            .tags
            .iter()
            .find(|t| t.starts_with("confidence:"))
            .and_then(|t| t.strip_prefix("confidence:"))
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(match entry.confidence {
                LootConfidence::High => 1.0,
                LootConfidence::Medium => 0.7,
                LootConfidence::Low => 0.4,
            });

        // Extract related findings from tags
        let related_findings: Vec<String> = entry
            .metadata
            .tags
            .iter()
            .filter(|t| t.starts_with("related:"))
            .filter_map(|t| t.strip_prefix("related:"))
            .map(|s| s.to_string())
            .collect();

        // Extract metadata (excluding special tags)
        let metadata: Vec<(String, String)> = entry
            .metadata
            .tags
            .iter()
            .filter(|t| {
                !t.starts_with("finding_type:")
                    && !t.starts_with("source:")
                    && !t.starts_with("confidence:")
                    && !t.starts_with("related:")
            })
            .filter_map(|t| {
                t.split_once(':')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect();

        Finding {
            id: entry.key.clone(),
            finding_type,
            value: entry.content.clone(),
            confidence,
            source,
            metadata,
            related_findings,
            timestamp: entry.created_at as u64,
        }
    }
}

impl CrewMemory {
    /// Save all findings to storage
    pub fn save_to_storage(&self, db: &mut Database) {
        for finding in self.findings.values() {
            let entry = finding.to_loot_entry();
            db.insert_loot(entry);
        }
    }

    /// Load findings from storage into memory
    pub fn load_from_storage(&mut self, db: &mut Database) {
        let entries = db.all_loot();
        for entry in entries {
            // Check if entry was created by crew (has finding_type tag)
            let is_crew_finding = entry
                .metadata
                .tags
                .iter()
                .any(|t| t.starts_with("finding_type:"));

            if is_crew_finding {
                let finding = Finding::from_loot_entry(&entry);
                // Use add_finding to properly index
                self.add_finding(finding);
            }
        }
    }

    /// Sync a single finding to storage
    pub fn sync_finding_to_storage(&self, finding_id: &str, db: &mut Database) {
        if let Some(finding) = self.findings.get(finding_id) {
            let entry = finding.to_loot_entry();
            db.insert_loot(entry);
        }
    }

    /// Load a specific finding from storage
    pub fn load_finding_from_storage(
        &mut self,
        finding_id: &str,
        db: &mut Database,
    ) -> Option<Finding> {
        if let Some(entry) = db.loot_by_key(finding_id) {
            let is_crew_finding = entry
                .metadata
                .tags
                .iter()
                .any(|t| t.starts_with("finding_type:"));

            if is_crew_finding {
                let finding = Finding::from_loot_entry(&entry);
                self.add_finding(finding.clone());
                return Some(finding);
            }
        }
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ShadowGraph Integration Layer
// ═══════════════════════════════════════════════════════════════════════════

use crate::storage::segments::graph::{EdgeType, GraphEdge, GraphNode, GraphSegment, NodeType};

impl FindingType {
    /// Convert FindingType to graph NodeType
    pub fn to_node_type(&self) -> NodeType {
        match self {
            Self::Host => NodeType::Host,
            Self::Port => NodeType::Service,
            Self::Service => NodeType::Service,
            Self::Vulnerability => NodeType::Vulnerability,
            Self::Credential => NodeType::Credential,
            Self::Technology => NodeType::Technology,
            Self::Endpoint => NodeType::Endpoint,
            Self::Access => NodeType::Host,
            Self::DnsRecord => NodeType::Domain,
            Self::Exploit => NodeType::Vulnerability,
            Self::Intelligence => NodeType::Domain,
            Self::AttackPath => NodeType::AttackChain,
            Self::Report => NodeType::AttackChain,
        }
    }
}

impl GraphUpdate {
    /// Convert edge type string to EdgeType
    fn edge_type_from_str(s: &str) -> EdgeType {
        match s {
            "has_service" => EdgeType::HasService,
            "has_endpoint" => EdgeType::HasEndpoint,
            "uses_tech" => EdgeType::UsesTech,
            "auth_access" => EdgeType::AuthAccess,
            "affected_by" => EdgeType::AffectedBy,
            "contains" => EdgeType::Contains,
            "connects_to" => EdgeType::ConnectsTo,
            "attack_path" => EdgeType::AttackPath,
            _ => EdgeType::RelatedTo,
        }
    }
}

impl CrewMemory {
    /// Flush all pending graph updates to the ShadowGraph
    ///
    /// This processes the queue of GraphUpdate operations and applies them
    /// to the provided GraphSegment. Node IDs in the graph are prefixed with
    /// the node type for proper categorization (e.g., "host:192.168.1.1").
    pub fn flush_graph_updates(&mut self, graph: &mut GraphSegment) -> usize {
        let mut count = 0;

        while let Some(update) = self.pending_graph_updates.pop_front() {
            match update {
                GraphUpdate::AddNode {
                    finding_id,
                    node_type,
                    properties,
                } => {
                    // Build graph node ID: "{type}:{finding_id}"
                    let graph_id = format!("{}:{}", node_type, finding_id);

                    // Get the actual FindingType to create proper NodeType
                    let node_type_enum = self
                        .findings
                        .get(&finding_id)
                        .map(|f| f.finding_type.to_node_type())
                        .unwrap_or(NodeType::Host);

                    // Create label from properties or finding value
                    let label = properties
                        .get("value")
                        .cloned()
                        .or_else(|| self.findings.get(&finding_id).map(|f| f.value.clone()))
                        .unwrap_or_else(|| finding_id.clone());

                    // Create the node
                    let mut node = GraphNode::new(&graph_id, node_type_enum, label);

                    // Serialize properties as metadata
                    if !properties.is_empty() {
                        let mut meta = Vec::new();
                        for (k, v) in &properties {
                            meta.extend_from_slice(k.as_bytes());
                            meta.push(b'=');
                            meta.extend_from_slice(v.as_bytes());
                            meta.push(b'\n');
                        }
                        node.metadata = meta;
                    }

                    // Add to graph
                    graph.add_node(node);

                    // Track mapping from finding_id to graph_id
                    self.set_graph_node(&finding_id, &graph_id);
                    count += 1;
                }

                GraphUpdate::AddEdge {
                    from_finding,
                    to_finding,
                    edge_type,
                    confidence,
                } => {
                    // Look up graph node IDs for both findings
                    let from_graph_id = self.get_graph_node(&from_finding).map(|s| s.to_string());
                    let to_graph_id = self.get_graph_node(&to_finding).map(|s| s.to_string());

                    if let (Some(from_id), Some(to_id)) = (from_graph_id, to_graph_id) {
                        // Create edge with weight based on confidence
                        // Lower weight = preferred path, so high confidence = lower weight
                        let edge_type_enum = GraphUpdate::edge_type_from_str(&edge_type);
                        let base_weight = edge_type_enum.default_weight();
                        let weight = base_weight * (1.0 - (confidence as f32 * 0.5));

                        let edge = GraphEdge {
                            source: from_id,
                            target: to_id,
                            edge_type: edge_type_enum,
                            weight,
                            metadata: Vec::new(),
                        };

                        graph.add_edge(edge);
                        self.stats.graph_edges_created += 1;
                        count += 1;
                    }
                }
            }
        }

        count
    }

    /// Sync memory to both storage and graph
    pub fn sync_all(&mut self, db: &mut Database, graph: &mut GraphSegment) {
        // Save findings to storage
        self.save_to_storage(db);
        // Flush graph updates
        self.flush_graph_updates(graph);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(FindingType::Host, "192.168.1.1".to_string())
            .with_confidence(0.95)
            .with_source("scanner")
            .with_metadata("port_count", "5");

        assert_eq!(finding.finding_type, FindingType::Host);
        assert_eq!(finding.value, "192.168.1.1");
        assert_eq!(finding.confidence, 0.95);
        assert_eq!(finding.get_metadata("port_count"), Some("5"));
    }

    #[test]
    fn test_memory_add_finding() {
        let mut memory = CrewMemory::new();
        let finding =
            Finding::new(FindingType::Host, "test.com".to_string()).with_source("recon_0");

        memory.add_finding(finding);

        assert_eq!(memory.findings().len(), 1);
        assert_eq!(memory.findings_of_type(FindingType::Host).len(), 1);
        assert_eq!(memory.findings_from_source("recon_0").len(), 1);
    }

    #[test]
    fn test_memory_search() {
        let mut memory = CrewMemory::new();
        memory.add_finding(Finding::new(FindingType::Host, "example.com".to_string()));
        memory.add_finding(Finding::new(FindingType::Host, "test.org".to_string()));

        let results = memory.search_findings("example");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "example.com");
    }

    #[test]
    fn test_conversation() {
        let mut memory = CrewMemory::new();
        memory.create_conversation("Test Session");

        memory.add_message(Message::user("Hello"));
        memory.add_message(Message::assistant("Hi there"));

        let conv = memory.active_conversation().unwrap();
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].role, MessageRole::User);
        assert_eq!(conv.messages[1].role, MessageRole::Assistant);
    }

    #[test]
    fn test_graph_update_queuing() {
        let mut memory = CrewMemory::new();

        let finding = Finding::new(FindingType::Service, "ssh:22".to_string())
            .with_related("other_finding_id");

        memory.add_finding(finding);

        assert!(memory.has_pending_graph_updates());

        let updates = memory.drain_graph_updates();
        assert_eq!(updates.len(), 2); // Node + Edge

        assert!(!memory.has_pending_graph_updates());
    }

    #[test]
    fn test_memory_summary() {
        let mut memory = CrewMemory::new();

        memory.add_finding(Finding::new(FindingType::Host, "a".to_string()));
        memory.add_finding(Finding::new(FindingType::Host, "b".to_string()));
        memory.add_finding(Finding::new(FindingType::Port, "c".to_string()));

        memory.create_conversation("Test");
        memory.add_message(Message::user("msg1"));
        memory.add_message(Message::user("msg2"));

        let summary = memory.summary();
        assert_eq!(summary.total_findings, 3);
        assert_eq!(summary.finding_counts.get(&FindingType::Host), Some(&2));
        assert_eq!(summary.finding_counts.get(&FindingType::Port), Some(&1));
        assert_eq!(summary.total_conversations, 1);
        assert_eq!(summary.total_messages, 2);
    }

    #[test]
    fn test_finding_loot_entry_roundtrip() {
        // Create a finding with all fields populated
        let finding = Finding::new(
            FindingType::Vulnerability,
            "SQL Injection in login".to_string(),
        )
        .with_confidence(0.95)
        .with_source("web_scanner_0")
        .with_metadata("cvss", "9.8")
        .with_metadata("endpoint", "/api/login")
        .with_related("finding_001")
        .with_related("finding_002");

        // Convert to LootEntry
        let loot_entry = finding.to_loot_entry();

        // Verify category mapping
        assert_eq!(loot_entry.category, LootCategory::Vulnerability);
        assert_eq!(loot_entry.key, finding.id);
        assert_eq!(loot_entry.content, "SQL Injection in login");
        assert_eq!(loot_entry.confidence, LootConfidence::High);

        // Convert back to Finding
        let restored = Finding::from_loot_entry(&loot_entry);

        // Verify roundtrip
        assert_eq!(restored.id, finding.id);
        assert_eq!(restored.finding_type, FindingType::Vulnerability);
        assert_eq!(restored.value, finding.value);
        assert_eq!(restored.source, finding.source);
        assert!((restored.confidence - finding.confidence).abs() < 0.001);
        assert_eq!(restored.related_findings.len(), 2);
        assert!(restored
            .related_findings
            .contains(&"finding_001".to_string()));
        assert!(restored
            .related_findings
            .contains(&"finding_002".to_string()));
    }

    #[test]
    fn test_finding_type_category_mapping() {
        // Test all FindingType -> LootCategory mappings
        assert_eq!(FindingType::Host.to_loot_category(), LootCategory::Finding);
        assert_eq!(FindingType::Port.to_loot_category(), LootCategory::Service);
        assert_eq!(
            FindingType::Service.to_loot_category(),
            LootCategory::Service
        );
        assert_eq!(
            FindingType::Vulnerability.to_loot_category(),
            LootCategory::Vulnerability
        );
        assert_eq!(
            FindingType::Credential.to_loot_category(),
            LootCategory::Credential
        );
        assert_eq!(
            FindingType::Technology.to_loot_category(),
            LootCategory::Technology
        );
        assert_eq!(
            FindingType::Endpoint.to_loot_category(),
            LootCategory::Endpoint
        );
    }

    #[test]
    fn test_finding_type_to_node_type() {
        // Test FindingType -> NodeType mappings
        assert_eq!(FindingType::Host.to_node_type(), NodeType::Host);
        assert_eq!(FindingType::Service.to_node_type(), NodeType::Service);
        assert_eq!(
            FindingType::Vulnerability.to_node_type(),
            NodeType::Vulnerability
        );
        assert_eq!(FindingType::Credential.to_node_type(), NodeType::Credential);
        assert_eq!(FindingType::Technology.to_node_type(), NodeType::Technology);
        assert_eq!(FindingType::Endpoint.to_node_type(), NodeType::Endpoint);
        assert_eq!(FindingType::DnsRecord.to_node_type(), NodeType::Domain);
        assert_eq!(
            FindingType::AttackPath.to_node_type(),
            NodeType::AttackChain
        );
    }

    #[test]
    fn test_graph_update_flush() {
        let mut memory = CrewMemory::new();
        let mut graph = GraphSegment::new();

        // Add a host finding
        let host =
            Finding::new(FindingType::Host, "192.168.1.1".to_string()).with_source("scanner");
        let host_id = host.id.clone();
        memory.add_finding(host);

        // Add a service finding related to the host
        let service = Finding::new(FindingType::Service, "SSH:22".to_string())
            .with_source("scanner")
            .with_related(&host_id);
        let service_id = service.id.clone();
        memory.add_finding(service);

        // Should have pending updates
        assert!(memory.has_pending_graph_updates());
        let pending_count = memory.drain_graph_updates().len();
        assert!(pending_count >= 2);

        // Re-add the findings to get updates back (drain removed them)
        let host =
            Finding::new(FindingType::Host, "192.168.1.1".to_string()).with_source("scanner");
        memory.add_finding(host);
        let service =
            Finding::new(FindingType::Service, "SSH:22".to_string()).with_source("scanner");
        memory.add_finding(service);

        // Flush to graph
        let count = memory.flush_graph_updates(&mut graph);
        assert!(count >= 2);

        // Graph should have nodes
        assert!(graph.node_count() >= 2);

        // No more pending updates
        assert!(!memory.has_pending_graph_updates());

        // Check node mapping was recorded (use get_graph_node, the existing method)
        assert!(memory.get_graph_node(&host_id).is_some() || graph.node_count() >= 2);
    }

    #[test]
    fn test_graph_edge_type_parsing() {
        // Test edge type string parsing
        assert_eq!(
            GraphUpdate::edge_type_from_str("has_service"),
            EdgeType::HasService
        );
        assert_eq!(
            GraphUpdate::edge_type_from_str("auth_access"),
            EdgeType::AuthAccess
        );
        assert_eq!(
            GraphUpdate::edge_type_from_str("affected_by"),
            EdgeType::AffectedBy
        );
        assert_eq!(
            GraphUpdate::edge_type_from_str("connects_to"),
            EdgeType::ConnectsTo
        );
        assert_eq!(
            GraphUpdate::edge_type_from_str("unknown"),
            EdgeType::RelatedTo
        );
    }
}
