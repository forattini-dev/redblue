//! Crew Framework - Multi-Agent Task Orchestration
//!
//! Implements the Crew pattern from pentestagent for coordinated autonomous operations.
//! Workers execute specialized tasks while sharing knowledge through the ShadowGraph.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Crew                                     │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐                         │
//! │  │  Recon   │ │ Exploit  │ │ Analysis │  ← Worker Pool          │
//! │  │  Worker  │ │  Worker  │ │  Worker  │                         │
//! │  └────┬─────┘ └────┬─────┘ └────┬─────┘                         │
//! │       │            │            │                               │
//! │       └────────────┼────────────┘                               │
//! │                    ▼                                             │
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │              Shared Memory (CrewMemory)                      ││
//! │  │  ┌────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐    ││
//! │  │  │Findings│  │Conversations│  │Task Queue│  │ShadowGraph│    ││
//! │  │  └────────┘  └────────────┘  └──────────┘  └───────────┘    ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │                    ▲                                             │
//! │                    │                                             │
//! │  ┌─────────────────┴─────────────────┐                          │
//! │  │         Synergy Event Bus         │                          │
//! │  └───────────────────────────────────┘                          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use redblue::agent::crew::{Crew, CrewConfig, TaskPriority};
//!
//! let mut crew = Crew::new(CrewConfig::default());
//!
//! // Add a reconnaissance task
//! crew.submit_task(Task::recon("example.com", TaskPriority::High));
//!
//! // Run until all tasks complete
//! while crew.has_pending_tasks() {
//!     crew.step()?;
//! }
//!
//! // Get accumulated findings
//! let findings = crew.memory().findings();
//! ```

pub mod executor;
pub mod memory;
pub mod task;
pub mod worker;

pub use executor::{AnalysisExecutor, ExploitExecutor, ReconExecutor, TaskRouter};
pub use memory::{Conversation, CrewMemory, Finding, FindingType, Message, MessageRole};
pub use task::{Task, TaskDependency, TaskId, TaskPriority, TaskResult, TaskStatus};
pub use worker::{Worker, WorkerPool, WorkerStatus, WorkerType};

use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::synergy::events::{EntityType, EventType};

// ═══════════════════════════════════════════════════════════════════════════
// Crew Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for crew behavior
#[derive(Debug, Clone)]
pub struct CrewConfig {
  /// Maximum concurrent workers
  pub max_workers: usize,
  /// Task timeout in seconds
  pub task_timeout_secs: u64,
  /// Maximum retries for failed tasks
  pub max_retries: u32,
  /// Enable automatic graph updates
  pub auto_graph_update: bool,
  /// Enable event bus integration
  pub enable_events: bool,
  /// Worker types to spawn
  pub worker_types: Vec<WorkerType>,
}

impl Default for CrewConfig {
  fn default() -> Self {
    Self {
      max_workers: 4,
      task_timeout_secs: 300,
      max_retries: 3,
      auto_graph_update: true,
      enable_events: true,
      worker_types: vec![WorkerType::Recon, WorkerType::Exploit, WorkerType::Analysis],
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Crew State
// ═══════════════════════════════════════════════════════════════════════════

/// Current state of the crew
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrewState {
  /// Idle, no tasks running
  Idle,
  /// Processing tasks
  Running,
  /// Paused by user
  Paused,
  /// All tasks complete
  Complete,
  /// Fatal error occurred
  Failed,
}

// ═══════════════════════════════════════════════════════════════════════════
// Crew
// ═══════════════════════════════════════════════════════════════════════════

/// The Crew orchestrates multiple workers to complete complex operations.
///
/// Based on the "crew" pattern from pentestagent, adapted for redblue's
/// architecture with integration into the synergy layer.
pub struct Crew {
  config: CrewConfig,
  state: CrewState,
  memory: Arc<RwLock<CrewMemory>>,
  worker_pool: WorkerPool,
  task_queue: TaskQueue,
  running_tasks: HashMap<TaskId, RunningTask>,
  completed_tasks: Vec<TaskResult>,
  generation: u64,
  start_time: Option<Instant>,
  stats: CrewStats,
}

/// Statistics about crew execution
#[derive(Debug, Clone, Default)]
pub struct CrewStats {
  pub tasks_submitted: u64,
  pub tasks_completed: u64,
  pub tasks_failed: u64,
  pub tasks_retried: u64,
  pub findings_generated: u64,
  pub graph_updates: u64,
  pub events_emitted: u64,
  pub total_runtime_ms: u64,
}

/// A task currently being executed
struct RunningTask {
  task: Task,
  worker_type: WorkerType,
  started_at: Instant,
  retry_count: u32,
}

impl Crew {
  /// Create a new crew with the given configuration
  pub fn new(config: CrewConfig) -> Self {
    let memory = Arc::new(RwLock::new(CrewMemory::new()));
    let worker_pool = WorkerPool::new(&config.worker_types);

    Self {
      config,
      state: CrewState::Idle,
      memory,
      worker_pool,
      task_queue: TaskQueue::new(),
      running_tasks: HashMap::new(),
      completed_tasks: Vec::new(),
      generation: 0,
      start_time: None,
      stats: CrewStats::default(),
    }
  }

  /// Create with default configuration
  pub fn default_crew() -> Self {
    Self::new(CrewConfig::default())
  }

  // ─────────────────────────────────────────────────────────────────────
  // State Accessors
  // ─────────────────────────────────────────────────────────────────────

  /// Get current crew state
  pub fn state(&self) -> CrewState {
    self.state
  }

  /// Check if there are pending or running tasks
  pub fn has_pending_tasks(&self) -> bool {
    !self.task_queue.is_empty() || !self.running_tasks.is_empty()
  }

  /// Get current statistics
  pub fn stats(&self) -> &CrewStats {
    &self.stats
  }

  /// Get shared memory (read-only)
  pub fn memory(&self) -> std::sync::RwLockReadGuard<'_, CrewMemory> {
    self.memory.read().unwrap()
  }

  /// Get shared memory (mutable)
  pub fn memory_mut(&self) -> std::sync::RwLockWriteGuard<'_, CrewMemory> {
    self.memory.write().unwrap()
  }

  /// Get completed task results
  pub fn completed_tasks(&self) -> &[TaskResult] {
    &self.completed_tasks
  }

  // ─────────────────────────────────────────────────────────────────────
  // Task Submission
  // ─────────────────────────────────────────────────────────────────────

  /// Submit a new task to the crew
  pub fn submit_task(&mut self, task: Task) -> TaskId {
    let task_id = task.id.clone();
    self.task_queue.push(task);
    self.stats.tasks_submitted += 1;

    if self.state == CrewState::Idle {
      self.state = CrewState::Running;
      self.start_time = Some(Instant::now());
    }

    task_id
  }

  /// Submit multiple tasks at once
  pub fn submit_tasks(&mut self, tasks: Vec<Task>) -> Vec<TaskId> {
    tasks.into_iter().map(|t| self.submit_task(t)).collect()
  }

  /// Submit a reconnaissance task
  pub fn submit_recon(&mut self, target: &str, priority: TaskPriority) -> TaskId {
    self.submit_task(Task::recon(target, priority))
  }

  /// Submit an exploitation task
  pub fn submit_exploit(&mut self, target: &str, vuln_id: &str, priority: TaskPriority) -> TaskId {
    self.submit_task(Task::exploit(target, vuln_id, priority))
  }

  /// Submit an analysis task
  pub fn submit_analysis(&mut self, subject: &str, priority: TaskPriority) -> TaskId {
    self.submit_task(Task::analysis(subject, priority))
  }

  // ─────────────────────────────────────────────────────────────────────
  // Execution
  // ─────────────────────────────────────────────────────────────────────

  /// Execute one step of crew processing
  ///
  /// Returns Ok(true) if work was done, Ok(false) if idle
  pub fn step(&mut self) -> Result<bool, CrewError> {
    match self.state {
      CrewState::Idle | CrewState::Paused | CrewState::Complete | CrewState::Failed => {
        return Ok(false);
      }
      CrewState::Running => {}
    }

    let mut work_done = false;

    // Check for timed out tasks
    self.check_timeouts()?;

    // Check completed tasks from workers
    work_done |= self.collect_completed_tasks()?;

    // Dispatch new tasks to available workers
    work_done |= self.dispatch_tasks()?;

    // Update state if all tasks complete
    if !self.has_pending_tasks() {
      self.state = CrewState::Complete;
      if let Some(start) = self.start_time {
        self.stats.total_runtime_ms = start.elapsed().as_millis() as u64;
      }
    }

    Ok(work_done)
  }

  /// Run until all tasks are complete or an error occurs
  pub fn run_to_completion(&mut self) -> Result<(), CrewError> {
    while self.has_pending_tasks() {
      self.step()?;
    }
    Ok(())
  }

  /// Pause crew execution
  pub fn pause(&mut self) {
    if self.state == CrewState::Running {
      self.state = CrewState::Paused;
    }
  }

  /// Resume crew execution
  pub fn resume(&mut self) {
    if self.state == CrewState::Paused {
      self.state = CrewState::Running;
    }
  }

  /// Cancel all pending tasks
  pub fn cancel(&mut self) {
    self.task_queue.clear();
    self.running_tasks.clear();
    self.state = CrewState::Idle;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Internal Methods
  // ─────────────────────────────────────────────────────────────────────

  fn check_timeouts(&mut self) -> Result<(), CrewError> {
    let timeout = Duration::from_secs(self.config.task_timeout_secs);
    let mut timed_out = Vec::new();

    for (task_id, running) in &self.running_tasks {
      if running.started_at.elapsed() > timeout {
        timed_out.push(task_id.clone());
      }
    }

    for task_id in timed_out {
      if let Some(running) = self.running_tasks.remove(&task_id) {
        if running.retry_count < self.config.max_retries {
          // Retry the task
          let mut task = running.task;
          task.retry_count = running.retry_count + 1;
          self.task_queue.push(task);
          self.stats.tasks_retried += 1;
        } else {
          // Task failed permanently
          self.completed_tasks.push(TaskResult {
            task_id: task_id.clone(),
            status: TaskStatus::Failed,
            output: None,
            error: Some("Task timed out after max retries".to_string()),
            duration_ms: running.started_at.elapsed().as_millis() as u64,
            findings: Vec::new(),
          });
          self.stats.tasks_failed += 1;
        }
      }
    }

    Ok(())
  }

  fn collect_completed_tasks(&mut self) -> Result<bool, CrewError> {
    let completed = self.worker_pool.collect_completed();
    let has_completed = !completed.is_empty();

    for result in completed {
      // Remove from running tasks
      self.running_tasks.remove(&result.task_id);

      // Process findings
      for finding in &result.findings {
        self.process_finding(finding)?;
      }

      // Update stats
      match result.status {
        TaskStatus::Completed => self.stats.tasks_completed += 1,
        TaskStatus::Failed => self.stats.tasks_failed += 1,
        _ => {}
      }

      self.stats.findings_generated += result.findings.len() as u64;
      self.completed_tasks.push(result);
    }

    Ok(has_completed)
  }

  fn dispatch_tasks(&mut self) -> Result<bool, CrewError> {
    let mut dispatched = false;

    while let Some(worker_type) = self.worker_pool.get_available_worker() {
      if let Some(task) = self.task_queue.pop_for_worker(worker_type) {
        let task_id = task.id.clone();
        let retry_count = task.retry_count;

        // Start the task
        self
          .worker_pool
          .submit_task(worker_type, task.clone(), self.memory.clone())?;

        // Track as running
        self.running_tasks.insert(
          task_id,
          RunningTask {
            task,
            worker_type,
            started_at: Instant::now(),
            retry_count,
          },
        );

        dispatched = true;
      } else {
        break;
      }
    }

    Ok(dispatched)
  }

  fn process_finding(&mut self, finding: &Finding) -> Result<(), CrewError> {
    // Store in memory
    {
      let mut memory = self.memory.write().unwrap();
      memory.add_finding(finding.clone());
    }

    // Update graph if enabled
    if self.config.auto_graph_update {
      self.update_graph_from_finding(finding)?;
      self.stats.graph_updates += 1;
    }

    // Emit event if enabled
    if self.config.enable_events {
      self.emit_finding_event(finding)?;
      self.stats.events_emitted += 1;
    }

    Ok(())
  }

  fn update_graph_from_finding(&mut self, finding: &Finding) -> Result<(), CrewError> {
    let mut memory = self.memory.write().unwrap();
    memory.update_graph_from_finding(finding);
    Ok(())
  }

  fn emit_finding_event(&self, finding: &Finding) -> Result<(), CrewError> {
    let event_type = match finding.finding_type {
      FindingType::Host => EventType::Discovery,
      FindingType::Port => EventType::Discovery,
      FindingType::Service => EventType::Discovery,
      FindingType::Vulnerability => EventType::VulnFound,
      FindingType::Credential => EventType::CredentialFound,
      FindingType::Technology => EventType::Enrichment,
      FindingType::Endpoint => EventType::Discovery,
      FindingType::Access => EventType::AccessGained,
      FindingType::DnsRecord => EventType::Discovery,
      FindingType::Exploit => EventType::Custom, // Exploit attempts
      FindingType::Intelligence => EventType::Enrichment,
      FindingType::AttackPath => EventType::Enrichment,
      FindingType::Report => EventType::Custom, // Reports
    };

    let entity_type = match finding.finding_type {
      FindingType::Host => EntityType::Host,
      FindingType::Port => EntityType::Port,
      FindingType::Service => EntityType::Service,
      FindingType::Vulnerability => EntityType::Vulnerability,
      FindingType::Credential => EntityType::Credential,
      FindingType::Technology => EntityType::Technology,
      FindingType::Endpoint => EntityType::Endpoint,
      FindingType::Access => EntityType::Session,
      FindingType::DnsRecord => EntityType::Domain,
      FindingType::Exploit => EntityType::Vulnerability,
      FindingType::Intelligence => EntityType::Loot, // Map to Loot for intelligence data
      FindingType::AttackPath => EntityType::Loot,   // Map to Loot for attack paths
      FindingType::Report => EntityType::Loot,       // Map to Loot for reports
    };

    // Event emission would go through synergy::events::emit()
    // For now we just track it in stats
    Ok(())
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Task Queue
// ═══════════════════════════════════════════════════════════════════════════

/// Priority queue for tasks
struct TaskQueue {
  queue: BinaryHeap<PrioritizedTask>,
}

#[derive(Eq, PartialEq)]
struct PrioritizedTask {
  priority: TaskPriority,
  submitted_at: u64,
  task: Task,
}

impl Ord for PrioritizedTask {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    // Higher priority first, then earlier submission
    self
      .priority
      .cmp(&other.priority)
      .then_with(|| other.submitted_at.cmp(&self.submitted_at))
  }
}

impl PartialOrd for PrioritizedTask {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl TaskQueue {
  fn new() -> Self {
    Self {
      queue: BinaryHeap::new(),
    }
  }

  fn push(&mut self, task: Task) {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_millis() as u64;

    self.queue.push(PrioritizedTask {
      priority: task.priority,
      submitted_at: now,
      task,
    });
  }

  fn pop_for_worker(&mut self, worker_type: WorkerType) -> Option<Task> {
    // Try to find a task suitable for this worker type
    let mut temp = Vec::new();
    let mut result = None;

    while let Some(pt) = self.queue.pop() {
      if pt.task.suitable_for_worker(worker_type) {
        result = Some(pt.task);
        break;
      } else {
        temp.push(pt);
      }
    }

    // Put back tasks that weren't suitable
    for pt in temp {
      self.queue.push(pt);
    }

    result
  }

  fn is_empty(&self) -> bool {
    self.queue.is_empty()
  }

  fn clear(&mut self) {
    self.queue.clear();
  }

  fn len(&self) -> usize {
    self.queue.len()
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur during crew operations
#[derive(Debug)]
pub enum CrewError {
  /// Worker pool error
  WorkerError(String),
  /// Task execution failed
  TaskFailed(String),
  /// Memory access error
  MemoryError(String),
  /// Graph operation failed
  GraphError(String),
  /// Configuration error
  ConfigError(String),
}

impl std::fmt::Display for CrewError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      CrewError::WorkerError(msg) => write!(f, "Worker error: {}", msg),
      CrewError::TaskFailed(msg) => write!(f, "Task failed: {}", msg),
      CrewError::MemoryError(msg) => write!(f, "Memory error: {}", msg),
      CrewError::GraphError(msg) => write!(f, "Graph error: {}", msg),
      CrewError::ConfigError(msg) => write!(f, "Config error: {}", msg),
    }
  }
}

impl std::error::Error for CrewError {}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_crew_creation() {
    let crew = Crew::default_crew();
    assert_eq!(crew.state(), CrewState::Idle);
    assert!(!crew.has_pending_tasks());
  }

  #[test]
  fn test_task_submission() {
    let mut crew = Crew::default_crew();
    let task_id = crew.submit_recon("example.com", TaskPriority::High);

    assert!(crew.has_pending_tasks());
    assert_eq!(crew.state(), CrewState::Running);
    assert_eq!(crew.stats().tasks_submitted, 1);
  }

  #[test]
  fn test_task_queue_priority() {
    let mut queue = TaskQueue::new();

    queue.push(Task::recon("low", TaskPriority::Low));
    queue.push(Task::recon("critical", TaskPriority::Critical));
    queue.push(Task::recon("high", TaskPriority::High));

    // Should pop in priority order: Critical, High, Low
    let first = queue.pop_for_worker(WorkerType::Recon).unwrap();
    assert_eq!(first.target.as_deref(), Some("critical"));

    let second = queue.pop_for_worker(WorkerType::Recon).unwrap();
    assert_eq!(second.target.as_deref(), Some("high"));

    let third = queue.pop_for_worker(WorkerType::Recon).unwrap();
    assert_eq!(third.target.as_deref(), Some("low"));
  }

  #[test]
  fn test_task_dependencies() {
    use super::task::DependencyType;
    use std::collections::HashSet;

    // Create a task with dependencies
    let parent_task = Task::recon("parent.com", TaskPriority::High);
    let parent_id = parent_task.id.clone();

    let child_task = Task::analysis("results", TaskPriority::Normal)
      .depends_on(parent_id.clone(), DependencyType::Success);

    // Initially, dependencies are not satisfied
    let completed = HashSet::new();
    let failed = HashSet::new();
    assert!(!child_task.dependencies_satisfied(&completed, &failed));

    // After parent completes, dependencies are satisfied
    let mut completed = HashSet::new();
    completed.insert(parent_id);
    assert!(child_task.dependencies_satisfied(&completed, &failed));
  }

  #[test]
  fn test_worker_type_routing() {
    let recon_task = Task::recon("target.com", TaskPriority::Normal);
    let exploit_task = Task::exploit("target.com", "CVE-2024-1234", TaskPriority::Normal);
    let analysis_task = Task::analysis("findings", TaskPriority::Normal);

    // Tasks should route to correct workers
    assert!(recon_task.suitable_for_worker(WorkerType::Recon));
    assert!(!recon_task.suitable_for_worker(WorkerType::Exploit));

    assert!(exploit_task.suitable_for_worker(WorkerType::Exploit));
    assert!(!exploit_task.suitable_for_worker(WorkerType::Analysis));

    assert!(analysis_task.suitable_for_worker(WorkerType::Analysis));
    assert!(!analysis_task.suitable_for_worker(WorkerType::Recon));
  }
}
