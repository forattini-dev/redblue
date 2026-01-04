/// Correlation Engine for Cross-Module Automation
///
/// Provides rule-based correlation that triggers actions based on events.
/// Example rules:
/// - "credential_found on Host X → trigger auth_test"
/// - "3 failed_login in 5 minutes → alert brute_force"
/// - "vuln_found with CVSS > 7 → suggest exploit"
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::events::{EntityType, Event, EventHandler, EventType};

/// Actions that can be triggered by correlation rules
#[derive(Debug, Clone)]
pub enum RuleAction {
    /// Create a task for manual review
    CreateTask {
        title: String,
        description: String,
        priority: u8,
    },
    /// Emit a new event
    EmitEvent {
        event_type: EventType,
        source: String,
        data: HashMap<String, String>,
    },
    /// Update an entity's state
    UpdateEntity {
        entity_type: EntityType,
        entity_id: String,
        field: String,
        value: String,
    },
    /// Send notification (log for now)
    Notify { level: String, message: String },
    /// Execute a module command
    ExecuteCommand {
        module: String,
        command: String,
        args: Vec<String>,
    },
    /// Chain to another rule
    ChainRule { rule_name: String },
    /// Custom action with handler function
    Custom {
        name: String,
        data: HashMap<String, String>,
    },
}

/// Condition for matching events
#[derive(Debug, Clone)]
pub enum RuleCondition {
    /// Match specific event type
    EventType(EventType),
    /// Match specific entity type
    EntityType(EntityType),
    /// Match entity ID pattern
    EntityIdPattern(String),
    /// Data field equals value
    DataEquals { field: String, value: String },
    /// Data field contains value
    DataContains { field: String, value: String },
    /// Severity >= threshold
    SeverityAtLeast(u8),
    /// Confidence >= threshold
    ConfidenceAtLeast(f32),
    /// Has MITRE technique
    HasMitreTechnique(String),
    /// Has tag
    HasTag(String),
    /// Count threshold within time window
    CountThreshold {
        event_type: EventType,
        count: usize,
        window_secs: u64,
    },
    /// All conditions must match
    And(Vec<RuleCondition>),
    /// Any condition must match
    Or(Vec<RuleCondition>),
    /// Condition must not match
    Not(Box<RuleCondition>),
}

impl RuleCondition {
    /// Check if condition matches an event
    pub fn matches(&self, event: &Event, context: &CorrelationContext) -> bool {
        match self {
            RuleCondition::EventType(et) => event.event_type == *et,
            RuleCondition::EntityType(et) => {
                event.entity.as_ref().map(|e| &e.entity_type) == Some(et)
            }
            RuleCondition::EntityIdPattern(pattern) => event
                .entity
                .as_ref()
                .map_or(false, |e| e.id.contains(pattern)),
            RuleCondition::DataEquals { field, value } => {
                event.data.get(field).map_or(false, |v| v == value)
            }
            RuleCondition::DataContains { field, value } => {
                event.data.get(field).map_or(false, |v| v.contains(value))
            }
            RuleCondition::SeverityAtLeast(threshold) => event.metadata.severity >= *threshold,
            RuleCondition::ConfidenceAtLeast(threshold) => event.metadata.confidence >= *threshold,
            RuleCondition::HasMitreTechnique(technique) => event
                .metadata
                .mitre
                .as_ref()
                .map_or(false, |m| m.technique_id == *technique),
            RuleCondition::HasTag(tag) => event.metadata.tags.contains(tag),
            RuleCondition::CountThreshold {
                event_type,
                count,
                window_secs,
            } => {
                context.event_count_in_window(*event_type, Duration::from_secs(*window_secs))
                    >= *count
            }
            RuleCondition::And(conditions) => conditions.iter().all(|c| c.matches(event, context)),
            RuleCondition::Or(conditions) => conditions.iter().any(|c| c.matches(event, context)),
            RuleCondition::Not(condition) => !condition.matches(event, context),
        }
    }
}

/// A correlation rule
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Condition to match
    pub condition: RuleCondition,
    /// Actions to execute when matched
    pub actions: Vec<RuleAction>,
    /// Whether rule is enabled
    pub enabled: bool,
    /// Cooldown between triggers (seconds)
    pub cooldown_secs: u64,
    /// Priority (higher = checked first)
    pub priority: u8,
}

impl CorrelationRule {
    /// Create a new rule
    pub fn new(name: impl Into<String>, condition: RuleCondition) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            condition,
            actions: Vec::new(),
            enabled: true,
            cooldown_secs: 0,
            priority: 50,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_action(mut self, action: RuleAction) -> Self {
        self.actions.push(action);
        self
    }

    pub fn with_cooldown(mut self, secs: u64) -> Self {
        self.cooldown_secs = secs;
        self
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Context for correlation evaluation
pub struct CorrelationContext {
    /// Recent events by type (for count thresholds)
    event_timestamps: HashMap<EventType, Vec<Instant>>,
    /// Last trigger time per rule
    rule_last_trigger: HashMap<String, Instant>,
}

impl Default for CorrelationContext {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationContext {
    pub fn new() -> Self {
        Self {
            event_timestamps: HashMap::new(),
            rule_last_trigger: HashMap::new(),
        }
    }

    /// Record an event occurrence
    pub fn record_event(&mut self, event_type: EventType) {
        self.event_timestamps
            .entry(event_type)
            .or_default()
            .push(Instant::now());

        // Cleanup old events (keep last 5 minutes)
        let cutoff = Instant::now() - Duration::from_secs(300);
        for timestamps in self.event_timestamps.values_mut() {
            timestamps.retain(|t| *t > cutoff);
        }
    }

    /// Get event count within a time window
    pub fn event_count_in_window(&self, event_type: EventType, window: Duration) -> usize {
        let cutoff = Instant::now() - window;
        self.event_timestamps
            .get(&event_type)
            .map(|timestamps| timestamps.iter().filter(|t| **t > cutoff).count())
            .unwrap_or(0)
    }

    /// Check if rule is in cooldown
    pub fn is_in_cooldown(&self, rule_name: &str, cooldown_secs: u64) -> bool {
        if cooldown_secs == 0 {
            return false;
        }

        self.rule_last_trigger
            .get(rule_name)
            .map(|last| last.elapsed() < Duration::from_secs(cooldown_secs))
            .unwrap_or(false)
    }

    /// Record rule trigger
    pub fn record_trigger(&mut self, rule_name: &str) {
        self.rule_last_trigger
            .insert(rule_name.to_string(), Instant::now());
    }
}

/// Action executor callback
pub type ActionExecutor = Box<dyn Fn(&RuleAction, &Event) -> bool + Send + Sync>;

/// Correlation engine
pub struct CorrelationEngine {
    rules: RwLock<Vec<CorrelationRule>>,
    context: RwLock<CorrelationContext>,
    action_executors: RwLock<HashMap<String, ActionExecutor>>,
    action_log: RwLock<Vec<(String, RuleAction, u64)>>, // (rule_name, action, event_id)
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            context: RwLock::new(CorrelationContext::new()),
            action_executors: RwLock::new(HashMap::new()),
            action_log: RwLock::new(Vec::new()),
        }
    }

    /// Add a correlation rule
    pub fn add_rule(&self, rule: CorrelationRule) {
        let mut rules = self.rules.write().unwrap();
        rules.push(rule);
        // Sort by priority (descending)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove a rule by name
    pub fn remove_rule(&self, name: &str) -> bool {
        let mut rules = self.rules.write().unwrap();
        let len_before = rules.len();
        rules.retain(|r| r.name != name);
        rules.len() < len_before
    }

    /// Enable/disable a rule
    pub fn set_rule_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut rules = self.rules.write().unwrap();
        for rule in rules.iter_mut() {
            if rule.name == name {
                rule.enabled = enabled;
                return true;
            }
        }
        false
    }

    /// Register an action executor
    pub fn register_executor(&self, action_type: impl Into<String>, executor: ActionExecutor) {
        self.action_executors
            .write()
            .unwrap()
            .insert(action_type.into(), executor);
    }

    /// Evaluate an event against all rules
    pub fn evaluate(&self, event: &Event) -> Vec<(String, Vec<RuleAction>)> {
        let rules = self.rules.read().unwrap();
        let mut context = self.context.write().unwrap();

        // Record this event
        context.record_event(event.event_type);

        let mut triggered = Vec::new();

        for rule in rules.iter() {
            // Skip disabled rules
            if !rule.enabled {
                continue;
            }

            // Check cooldown
            if context.is_in_cooldown(&rule.name, rule.cooldown_secs) {
                continue;
            }

            // Evaluate condition
            if rule.condition.matches(event, &context) {
                // Record trigger
                context.record_trigger(&rule.name);

                // Collect actions
                let actions = rule.actions.clone();
                triggered.push((rule.name.clone(), actions));
            }
        }

        triggered
    }

    /// Process an event and execute triggered actions
    pub fn process(&self, event: &Event) -> usize {
        let triggered = self.evaluate(event);
        let mut action_count = 0;

        let executors = self.action_executors.read().unwrap();

        for (rule_name, actions) in triggered {
            for action in actions {
                // Log the action
                self.action_log.write().unwrap().push((
                    rule_name.clone(),
                    action.clone(),
                    event.id,
                ));

                // Execute action based on type
                match &action {
                    RuleAction::Notify { level, message } => {
                        // Log notification
                        eprintln!("[CORRELATION] [{}] {}: {}", rule_name, level, message);
                        action_count += 1;
                    }
                    RuleAction::CreateTask { title, .. } => {
                        eprintln!("[CORRELATION] [{}] Task created: {}", rule_name, title);
                        action_count += 1;
                    }
                    RuleAction::Custom { name, .. } => {
                        if let Some(executor) = executors.get(name) {
                            if executor(&action, event) {
                                action_count += 1;
                            }
                        }
                    }
                    _ => {
                        // Default: log the action
                        eprintln!("[CORRELATION] [{}] Action: {:?}", rule_name, action);
                        action_count += 1;
                    }
                }
            }
        }

        action_count
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<CorrelationRule> {
        self.rules.read().unwrap().clone()
    }

    /// Get rule by name
    pub fn get_rule(&self, name: &str) -> Option<CorrelationRule> {
        self.rules
            .read()
            .unwrap()
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }

    /// Get recent action log
    pub fn action_log(&self, count: usize) -> Vec<(String, RuleAction, u64)> {
        let log = self.action_log.read().unwrap();
        log.iter().rev().take(count).cloned().collect()
    }

    /// Load default security rules
    pub fn load_default_rules(&self) {
        // Rule: Alert on critical vulnerabilities
        self.add_rule(
            CorrelationRule::new(
                "critical_vuln_alert",
                RuleCondition::And(vec![
                    RuleCondition::EventType(EventType::VulnFound),
                    RuleCondition::SeverityAtLeast(4), // Critical
                ]),
            )
            .with_description("Alert when critical vulnerability is discovered")
            .with_action(RuleAction::Notify {
                level: "CRITICAL".to_string(),
                message: "Critical vulnerability discovered".to_string(),
            })
            .with_cooldown(60),
        );

        // Rule: Suggest auth test on credential found
        self.add_rule(
            CorrelationRule::new(
                "credential_auth_test",
                RuleCondition::EventType(EventType::CredentialFound),
            )
            .with_description("Suggest authentication test when credential is found")
            .with_action(RuleAction::CreateTask {
                title: "Test discovered credential".to_string(),
                description: "Verify if discovered credential provides access".to_string(),
                priority: 2,
            })
            .with_cooldown(300),
        );

        // Rule: Detect brute force attempts
        self.add_rule(
            CorrelationRule::new(
                "brute_force_detection",
                RuleCondition::CountThreshold {
                    event_type: EventType::Error,
                    count: 5,
                    window_secs: 60,
                },
            )
            .with_description("Detect potential brute force from repeated failures")
            .with_action(RuleAction::Notify {
                level: "WARNING".to_string(),
                message: "Potential brute force detected (5+ failures in 60s)".to_string(),
            })
            .with_cooldown(300)
            .with_priority(90),
        );

        // Rule: Track lateral movement
        self.add_rule(
            CorrelationRule::new(
                "lateral_movement_tracking",
                RuleCondition::EventType(EventType::LateralMovement),
            )
            .with_description("Track lateral movement for attack chain analysis")
            .with_action(RuleAction::Notify {
                level: "INFO".to_string(),
                message: "Lateral movement recorded for attack chain".to_string(),
            }),
        );

        // Rule: High-value target discovery
        self.add_rule(
            CorrelationRule::new(
                "high_value_target",
                RuleCondition::And(vec![
                    RuleCondition::EventType(EventType::Discovery),
                    RuleCondition::Or(vec![
                        RuleCondition::DataContains {
                            field: "service".to_string(),
                            value: "dc".to_string(),
                        },
                        RuleCondition::DataContains {
                            field: "service".to_string(),
                            value: "sql".to_string(),
                        },
                        RuleCondition::DataContains {
                            field: "service".to_string(),
                            value: "domain".to_string(),
                        },
                    ]),
                ]),
            )
            .with_description("Flag high-value targets (domain controllers, databases)")
            .with_action(RuleAction::CreateTask {
                title: "High-value target identified".to_string(),
                description: "Prioritize enumeration of this target".to_string(),
                priority: 3,
            })
            .with_cooldown(600),
        );
    }
}

impl EventHandler for CorrelationEngine {
    fn handle(&self, event: &Event) -> bool {
        self.process(event) > 0
    }

    fn name(&self) -> &str {
        "correlation_engine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_condition() {
        let condition = RuleCondition::EventType(EventType::Discovery);
        let context = CorrelationContext::new();

        let event = Event::new(EventType::Discovery, "scanner");
        assert!(condition.matches(&event, &context));

        let event2 = Event::new(EventType::VulnFound, "scanner");
        assert!(!condition.matches(&event2, &context));
    }

    #[test]
    fn test_and_condition() {
        let condition = RuleCondition::And(vec![
            RuleCondition::EventType(EventType::VulnFound),
            RuleCondition::SeverityAtLeast(3),
        ]);
        let context = CorrelationContext::new();

        let event = Event::new(EventType::VulnFound, "scanner").with_severity(4);
        assert!(condition.matches(&event, &context));

        let event2 = Event::new(EventType::VulnFound, "scanner").with_severity(2);
        assert!(!condition.matches(&event2, &context));
    }

    #[test]
    fn test_rule_evaluation() {
        let engine = CorrelationEngine::new();

        engine.add_rule(
            CorrelationRule::new("test_rule", RuleCondition::EventType(EventType::Discovery))
                .with_action(RuleAction::Notify {
                    level: "INFO".to_string(),
                    message: "Test".to_string(),
                }),
        );

        let event = Event::new(EventType::Discovery, "scanner");
        let triggered = engine.evaluate(&event);

        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].0, "test_rule");
    }

    #[test]
    fn test_cooldown() {
        let engine = CorrelationEngine::new();

        engine.add_rule(
            CorrelationRule::new(
                "cooldown_rule",
                RuleCondition::EventType(EventType::Discovery),
            )
            .with_action(RuleAction::Notify {
                level: "INFO".to_string(),
                message: "Test".to_string(),
            })
            .with_cooldown(60),
        );

        let event = Event::new(EventType::Discovery, "scanner");

        // First trigger should work
        let triggered1 = engine.evaluate(&event);
        assert_eq!(triggered1.len(), 1);

        // Second trigger should be in cooldown
        let triggered2 = engine.evaluate(&event);
        assert_eq!(triggered2.len(), 0);
    }
}
