pub mod correlation;
/// Synergy Layer - Cross-Module Correlation Engine
///
/// The synergy layer provides event-driven correlation across all modules.
/// It enables:
/// - Event bus for producer/consumer pattern
/// - Correlation rules for automated actions
/// - Entity lifecycle tracking
/// - Timeline and audit trail
/// - MITRE ATT&CK auto-tagging
pub mod events;
pub mod timeline;

pub use correlation::{CorrelationEngine, CorrelationRule, RuleAction};
pub use events::{Event, EventBus, EventHandler, EventType};
pub use timeline::{Timeline, TimelineEntry, TimelineQuery};
