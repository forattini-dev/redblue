//! Task Definitions for Crew Framework
//!
//! Tasks represent units of work that workers execute.
//! Each task has a type, priority, target, and optional dependencies.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use super::memory::Finding;
use super::worker::WorkerType;

// ═══════════════════════════════════════════════════════════════════════════
// Task ID
// ═══════════════════════════════════════════════════════════════════════════

/// Unique identifier for a task
pub type TaskId = String;

/// Generate a unique task ID
fn generate_task_id(prefix: &str) -> TaskId {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos();
  format!("{}_{:016x}", prefix, now)
}

// ═══════════════════════════════════════════════════════════════════════════
// Task Priority
// ═══════════════════════════════════════════════════════════════════════════

/// Priority level for task scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskPriority {
  /// Lowest priority - background tasks
  Low = 0,
  /// Normal priority - standard tasks
  Normal = 1,
  /// High priority - important tasks
  High = 2,
  /// Critical priority - urgent tasks
  Critical = 3,
}

impl Default for TaskPriority {
  fn default() -> Self {
    Self::Normal
  }
}

impl TaskPriority {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Low => "low",
      Self::Normal => "normal",
      Self::High => "high",
      Self::Critical => "critical",
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Task Type
// ═══════════════════════════════════════════════════════════════════════════

/// Type of task to execute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskType {
  /// Reconnaissance task (discovery, enumeration)
  Recon,
  /// Exploitation task (vulnerability exploitation)
  Exploit,
  /// Analysis task (data analysis, correlation)
  Analysis,
  /// Persistence task (maintaining access)
  Persistence,
  /// Exfiltration task (data collection)
  Exfiltration,
  /// Custom task type
  Custom,
}

impl TaskType {
  /// Get the preferred worker type for this task
  pub fn preferred_worker(&self) -> WorkerType {
    match self {
      TaskType::Recon => WorkerType::Recon,
      TaskType::Exploit | TaskType::Persistence => WorkerType::Exploit,
      TaskType::Analysis | TaskType::Exfiltration | TaskType::Custom => WorkerType::Analysis,
    }
  }

  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Recon => "recon",
      Self::Exploit => "exploit",
      Self::Analysis => "analysis",
      Self::Persistence => "persistence",
      Self::Exfiltration => "exfiltration",
      Self::Custom => "custom",
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Task Status
// ═══════════════════════════════════════════════════════════════════════════

/// Current status of a task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
  /// Waiting to be executed
  Pending,
  /// Currently being executed
  Running,
  /// Successfully completed
  Completed,
  /// Execution failed
  Failed,
  /// Cancelled by user
  Cancelled,
  /// Waiting for dependencies
  Blocked,
}

impl TaskStatus {
  pub fn is_terminal(&self) -> bool {
    matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
  }

  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Running => "running",
      Self::Completed => "completed",
      Self::Failed => "failed",
      Self::Cancelled => "cancelled",
      Self::Blocked => "blocked",
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Task Dependency
// ═══════════════════════════════════════════════════════════════════════════

/// Dependency relationship between tasks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDependency {
  /// Task that must complete first
  pub depends_on: TaskId,
  /// Type of dependency
  pub dependency_type: DependencyType,
}

/// Type of task dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyType {
  /// Must complete successfully before this task starts
  Success,
  /// Must complete (success or failure) before this task starts
  Completion,
  /// Must fail for this task to start (alternative path)
  Failure,
}

// ═══════════════════════════════════════════════════════════════════════════
// Task
// ═══════════════════════════════════════════════════════════════════════════

/// A task to be executed by a worker
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
  /// Unique task identifier
  pub id: TaskId,
  /// Type of task
  pub task_type: TaskType,
  /// Priority level
  pub priority: TaskPriority,
  /// Target (host, URL, file, etc.)
  pub target: Option<String>,
  /// Additional context/parameters
  pub context: TaskContext,
  /// Dependencies on other tasks
  pub dependencies: Vec<TaskDependency>,
  /// Number of retry attempts
  pub retry_count: u32,
  /// Tags for categorization
  pub tags: HashSet<String>,
}

/// Additional context for a task
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskContext {
  /// Vulnerability ID for exploit tasks
  pub vuln_id: Option<String>,
  /// Subject for analysis tasks
  pub subject: Option<String>,
  /// Ports to focus on
  pub ports: Option<Vec<u16>>,
  /// Protocol to use
  pub protocol: Option<String>,
  /// Credentials to use
  pub credentials: Option<(String, String)>,
  /// Custom parameters
  pub params: Vec<(String, String)>,
}

impl Task {
  /// Create a new task
  pub fn new(task_type: TaskType, priority: TaskPriority) -> Self {
    Self {
      id: generate_task_id(task_type.as_str()),
      task_type,
      priority,
      target: None,
      context: TaskContext::default(),
      dependencies: Vec::new(),
      retry_count: 0,
      tags: HashSet::new(),
    }
  }

  /// Create a reconnaissance task
  pub fn recon(target: &str, priority: TaskPriority) -> Self {
    let mut task = Self::new(TaskType::Recon, priority);
    task.target = Some(target.to_string());
    task
  }

  /// Create an exploitation task
  pub fn exploit(target: &str, vuln_id: &str, priority: TaskPriority) -> Self {
    let mut task = Self::new(TaskType::Exploit, priority);
    task.target = Some(target.to_string());
    task.context.vuln_id = Some(vuln_id.to_string());
    task
  }

  /// Create an analysis task
  pub fn analysis(subject: &str, priority: TaskPriority) -> Self {
    let mut task = Self::new(TaskType::Analysis, priority);
    task.context.subject = Some(subject.to_string());
    task
  }

  /// Create a persistence task
  pub fn persistence(target: &str, priority: TaskPriority) -> Self {
    let mut task = Self::new(TaskType::Persistence, priority);
    task.target = Some(target.to_string());
    task
  }

  /// Create an exfiltration task
  pub fn exfiltration(target: &str, priority: TaskPriority) -> Self {
    let mut task = Self::new(TaskType::Exfiltration, priority);
    task.target = Some(target.to_string());
    task
  }

  // ─────────────────────────────────────────────────────────────────────
  // Builder Methods
  // ─────────────────────────────────────────────────────────────────────

  /// Set the target
  pub fn with_target(mut self, target: &str) -> Self {
    self.target = Some(target.to_string());
    self
  }

  /// Set specific ports
  pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
    self.context.ports = Some(ports);
    self
  }

  /// Set protocol
  pub fn with_protocol(mut self, protocol: &str) -> Self {
    self.context.protocol = Some(protocol.to_string());
    self
  }

  /// Set credentials
  pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
    self.context.credentials = Some((username.to_string(), password.to_string()));
    self
  }

  /// Add a dependency
  pub fn depends_on(mut self, task_id: TaskId, dep_type: DependencyType) -> Self {
    self.dependencies.push(TaskDependency {
      depends_on: task_id,
      dependency_type: dep_type,
    });
    self
  }

  /// Add a tag
  pub fn with_tag(mut self, tag: &str) -> Self {
    self.tags.insert(tag.to_string());
    self
  }

  /// Add a custom parameter
  pub fn with_param(mut self, key: &str, value: &str) -> Self {
    self
      .context
      .params
      .push((key.to_string(), value.to_string()));
    self
  }

  // ─────────────────────────────────────────────────────────────────────
  // Utility Methods
  // ─────────────────────────────────────────────────────────────────────

  /// Check if this task is suitable for a given worker type
  pub fn suitable_for_worker(&self, worker_type: WorkerType) -> bool {
    match (self.task_type, worker_type) {
      // Recon tasks go to recon workers
      (TaskType::Recon, WorkerType::Recon) => true,
      // Exploit/persistence to exploit workers
      (TaskType::Exploit | TaskType::Persistence, WorkerType::Exploit) => true,
      // Analysis/exfil/custom to analysis workers
      (TaskType::Analysis | TaskType::Exfiltration | TaskType::Custom, WorkerType::Analysis) => {
        true
      }
      // Any worker can handle their preferred type
      _ => self.task_type.preferred_worker() == worker_type,
    }
  }

  /// Check if all dependencies are satisfied
  pub fn dependencies_satisfied(
    &self,
    completed: &HashSet<TaskId>,
    failed: &HashSet<TaskId>,
  ) -> bool {
    for dep in &self.dependencies {
      let is_satisfied = match dep.dependency_type {
        DependencyType::Success => completed.contains(&dep.depends_on),
        DependencyType::Completion => {
          completed.contains(&dep.depends_on) || failed.contains(&dep.depends_on)
        }
        DependencyType::Failure => failed.contains(&dep.depends_on),
      };
      if !is_satisfied {
        return false;
      }
    }
    true
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Task Result
// ═══════════════════════════════════════════════════════════════════════════

/// Result of task execution
#[derive(Debug, Clone)]
pub struct TaskResult {
  /// Task ID
  pub task_id: TaskId,
  /// Final status
  pub status: TaskStatus,
  /// Output data (serialized)
  pub output: Option<String>,
  /// Error message if failed
  pub error: Option<String>,
  /// Execution duration in milliseconds
  pub duration_ms: u64,
  /// Findings generated by this task
  pub findings: Vec<Finding>,
}

impl TaskResult {
  /// Create a successful result
  pub fn success(task_id: TaskId, output: Option<String>, duration_ms: u64) -> Self {
    Self {
      task_id,
      status: TaskStatus::Completed,
      output,
      error: None,
      duration_ms,
      findings: Vec::new(),
    }
  }

  /// Create a failed result
  pub fn failure(task_id: TaskId, error: String, duration_ms: u64) -> Self {
    Self {
      task_id,
      status: TaskStatus::Failed,
      output: None,
      error: Some(error),
      duration_ms,
      findings: Vec::new(),
    }
  }

  /// Add findings to the result
  pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
    self.findings = findings;
    self
  }

  /// Add a single finding
  pub fn add_finding(&mut self, finding: Finding) {
    self.findings.push(finding);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_task_creation() {
    let task = Task::recon("example.com", TaskPriority::High);
    assert_eq!(task.task_type, TaskType::Recon);
    assert_eq!(task.priority, TaskPriority::High);
    assert_eq!(task.target, Some("example.com".to_string()));
    assert!(task.id.starts_with("recon_"));
  }

  #[test]
  fn test_task_builder() {
    let task = Task::exploit("192.168.1.1", "CVE-2024-1234", TaskPriority::Critical)
      .with_ports(vec![80, 443])
      .with_credentials("admin", "password")
      .with_tag("web")
      .with_param("timeout", "30");

    assert_eq!(task.context.vuln_id, Some("CVE-2024-1234".to_string()));
    assert_eq!(task.context.ports, Some(vec![80, 443]));
    assert!(task.tags.contains("web"));
  }

  #[test]
  fn test_task_priority_order() {
    assert!(TaskPriority::Critical > TaskPriority::High);
    assert!(TaskPriority::High > TaskPriority::Normal);
    assert!(TaskPriority::Normal > TaskPriority::Low);
  }

  #[test]
  fn test_worker_suitability() {
    let recon_task = Task::recon("test", TaskPriority::Normal);
    let exploit_task = Task::exploit("test", "CVE-123", TaskPriority::Normal);
    let analysis_task = Task::analysis("data", TaskPriority::Normal);

    assert!(recon_task.suitable_for_worker(WorkerType::Recon));
    assert!(!recon_task.suitable_for_worker(WorkerType::Exploit));

    assert!(exploit_task.suitable_for_worker(WorkerType::Exploit));
    assert!(!exploit_task.suitable_for_worker(WorkerType::Recon));

    assert!(analysis_task.suitable_for_worker(WorkerType::Analysis));
  }

  #[test]
  fn test_dependency_satisfaction() {
    let dep_task_id = "dep_task_123".to_string();
    let task = Task::recon("test", TaskPriority::Normal)
      .depends_on(dep_task_id.clone(), DependencyType::Success);

    let mut completed = HashSet::new();
    let failed = HashSet::new();

    // Not satisfied initially
    assert!(!task.dependencies_satisfied(&completed, &failed));

    // Satisfied after completion
    completed.insert(dep_task_id);
    assert!(task.dependencies_satisfied(&completed, &failed));
  }
}
