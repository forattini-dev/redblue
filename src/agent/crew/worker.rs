//! Worker Agents for Crew Framework
//!
//! Workers are specialized agents that execute tasks. Each worker type
//! handles specific categories of work (recon, exploit, analysis).

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use super::executor::TaskRouter;
use super::memory::{CrewMemory, Finding};
use super::task::{Task, TaskResult};
use super::CrewError;

// ═══════════════════════════════════════════════════════════════════════════
// Worker Type
// ═══════════════════════════════════════════════════════════════════════════

/// Type of worker agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkerType {
  /// Reconnaissance worker - discovery, enumeration, scanning
  Recon,
  /// Exploitation worker - vulnerability exploitation, access
  Exploit,
  /// Analysis worker - data analysis, correlation, reporting
  Analysis,
}

impl WorkerType {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Recon => "recon",
      Self::Exploit => "exploit",
      Self::Analysis => "analysis",
    }
  }

  /// Get the icon for this worker type (for display)
  pub fn icon(&self) -> char {
    match self {
      Self::Recon => '🔍',
      Self::Exploit => '💥',
      Self::Analysis => '📊',
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Worker Status
// ═══════════════════════════════════════════════════════════════════════════

/// Current status of a worker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus {
  /// Worker is idle and ready for work
  Idle,
  /// Worker is executing a task
  Busy,
  /// Worker is paused
  Paused,
  /// Worker has encountered an error
  Error,
}

// ═══════════════════════════════════════════════════════════════════════════
// Worker
// ═══════════════════════════════════════════════════════════════════════════

/// A worker agent that executes tasks
pub struct Worker {
  /// Worker identifier
  pub id: String,
  /// Type of worker
  pub worker_type: WorkerType,
  /// Current status
  status: WorkerStatus,
  /// Currently executing task
  current_task: Option<RunningTaskState>,
  /// Completed results waiting to be collected
  completed_results: VecDeque<TaskResult>,
  /// Statistics
  stats: WorkerStats,
}

/// State of a running task in a worker
struct RunningTaskState {
  task: Task,
  started_at: Instant,
  memory: Arc<RwLock<CrewMemory>>,
}

/// Worker statistics
#[derive(Debug, Clone, Default)]
pub struct WorkerStats {
  pub tasks_completed: u64,
  pub tasks_failed: u64,
  pub total_runtime_ms: u64,
  pub findings_generated: u64,
}

impl Worker {
  /// Create a new worker
  pub fn new(worker_type: WorkerType, id: usize) -> Self {
    Self {
      id: format!("{}_{}", worker_type.as_str(), id),
      worker_type,
      status: WorkerStatus::Idle,
      current_task: None,
      completed_results: VecDeque::new(),
      stats: WorkerStats::default(),
    }
  }

  /// Get current status
  pub fn status(&self) -> WorkerStatus {
    self.status
  }

  /// Check if worker is available for new tasks
  pub fn is_available(&self) -> bool {
    self.status == WorkerStatus::Idle
  }

  /// Submit a task to this worker
  pub fn submit(&mut self, task: Task, memory: Arc<RwLock<CrewMemory>>) -> Result<(), CrewError> {
    if self.status != WorkerStatus::Idle {
      return Err(CrewError::WorkerError(format!(
        "Worker {} is not idle",
        self.id
      )));
    }

    self.current_task = Some(RunningTaskState {
      task,
      started_at: Instant::now(),
      memory,
    });
    self.status = WorkerStatus::Busy;
    Ok(())
  }

  /// Execute one step of the current task
  ///
  /// In a real implementation, this would do async work.
  /// For now, we simulate synchronous execution.
  pub fn step(&mut self) -> Result<bool, CrewError> {
    if self.status != WorkerStatus::Busy {
      return Ok(false);
    }

    let state = self.current_task.take();
    if let Some(state) = state {
      // Execute the task based on type
      let result = self.execute_task(&state);
      let duration_ms = state.started_at.elapsed().as_millis() as u64;

      let result = match result {
        Ok(findings) => {
          self.stats.tasks_completed += 1;
          self.stats.findings_generated += findings.len() as u64;
          TaskResult::success(state.task.id.clone(), None, duration_ms).with_findings(findings)
        }
        Err(e) => {
          self.stats.tasks_failed += 1;
          TaskResult::failure(state.task.id.clone(), e.to_string(), duration_ms)
        }
      };

      self.stats.total_runtime_ms += duration_ms;
      self.completed_results.push_back(result);
      self.status = WorkerStatus::Idle;
      Ok(true)
    } else {
      self.status = WorkerStatus::Idle;
      Ok(false)
    }
  }

  /// Collect completed results
  pub fn collect_completed(&mut self) -> Vec<TaskResult> {
    self.completed_results.drain(..).collect()
  }

  /// Get statistics
  pub fn stats(&self) -> &WorkerStats {
    &self.stats
  }

  // ─────────────────────────────────────────────────────────────────────
  // Task Execution
  // ─────────────────────────────────────────────────────────────────────

  /// Execute task by routing to the appropriate executor
  fn execute_task(&self, state: &RunningTaskState) -> Result<Vec<Finding>, CrewError> {
    match self.worker_type {
      WorkerType::Recon => TaskRouter::execute_recon(&state.task, &state.memory),
      WorkerType::Exploit => TaskRouter::execute_exploit(&state.task, &state.memory),
      WorkerType::Analysis => TaskRouter::execute_analysis(&state.task, &state.memory),
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Worker Pool
// ═══════════════════════════════════════════════════════════════════════════

/// Pool of workers for parallel execution
pub struct WorkerPool {
  workers: Vec<Worker>,
}

impl WorkerPool {
  /// Create a new worker pool with specified worker types
  pub fn new(worker_types: &[WorkerType]) -> Self {
    let mut workers = Vec::new();
    let mut type_counts: std::collections::HashMap<WorkerType, usize> =
      std::collections::HashMap::new();

    for wt in worker_types {
      let count = type_counts.entry(*wt).or_insert(0);
      workers.push(Worker::new(*wt, *count));
      *count += 1;
    }

    Self { workers }
  }

  /// Get an available worker of any type
  pub fn get_available_worker(&self) -> Option<WorkerType> {
    self
      .workers
      .iter()
      .find(|w| w.is_available())
      .map(|w| w.worker_type)
  }

  /// Submit a task to a worker of the specified type
  pub fn submit_task(
    &mut self,
    worker_type: WorkerType,
    task: Task,
    memory: Arc<RwLock<CrewMemory>>,
  ) -> Result<(), CrewError> {
    let worker = self
      .workers
      .iter_mut()
      .find(|w| w.worker_type == worker_type && w.is_available())
      .ok_or_else(|| {
        CrewError::WorkerError(format!("No available {} worker", worker_type.as_str()))
      })?;

    worker.submit(task, memory)?;

    // Execute the task synchronously (in real impl, this would be async)
    worker.step()?;

    Ok(())
  }

  /// Collect completed results from all workers
  pub fn collect_completed(&mut self) -> Vec<TaskResult> {
    let mut results = Vec::new();
    for worker in &mut self.workers {
      results.extend(worker.collect_completed());
    }
    results
  }

  /// Step all workers
  pub fn step_all(&mut self) -> Result<bool, CrewError> {
    let mut any_work = false;
    for worker in &mut self.workers {
      if worker.step()? {
        any_work = true;
      }
    }
    Ok(any_work)
  }

  /// Get total statistics across all workers
  pub fn total_stats(&self) -> WorkerStats {
    let mut total = WorkerStats::default();
    for worker in &self.workers {
      let stats = worker.stats();
      total.tasks_completed += stats.tasks_completed;
      total.tasks_failed += stats.tasks_failed;
      total.total_runtime_ms += stats.total_runtime_ms;
      total.findings_generated += stats.findings_generated;
    }
    total
  }

  /// Get worker count by type
  pub fn worker_count(&self, worker_type: WorkerType) -> usize {
    self
      .workers
      .iter()
      .filter(|w| w.worker_type == worker_type)
      .count()
  }

  /// Get all workers
  pub fn workers(&self) -> &[Worker] {
    &self.workers
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
  use super::*;
  use crate::agent::crew::TaskStatus;

  #[test]
  fn test_worker_creation() {
    let worker = Worker::new(WorkerType::Recon, 0);
    assert_eq!(worker.worker_type, WorkerType::Recon);
    assert_eq!(worker.status(), WorkerStatus::Idle);
    assert!(worker.is_available());
  }

  #[test]
  fn test_worker_task_submission() {
    let mut worker = Worker::new(WorkerType::Recon, 0);
    let memory = Arc::new(RwLock::new(CrewMemory::new()));
    let task = Task::recon("example.com", super::super::task::TaskPriority::Normal);

    worker.submit(task, memory).unwrap();
    assert_eq!(worker.status(), WorkerStatus::Busy);
    assert!(!worker.is_available());
  }

  #[test]
  fn test_worker_pool_creation() {
    let pool = WorkerPool::new(&[WorkerType::Recon, WorkerType::Exploit, WorkerType::Analysis]);

    assert_eq!(pool.worker_count(WorkerType::Recon), 1);
    assert_eq!(pool.worker_count(WorkerType::Exploit), 1);
    assert_eq!(pool.worker_count(WorkerType::Analysis), 1);
  }

  #[test]
  fn test_worker_pool_task_execution() {
    let mut pool = WorkerPool::new(&[WorkerType::Recon]);
    let memory = Arc::new(RwLock::new(CrewMemory::new()));
    let task = Task::recon("test.com", super::super::task::TaskPriority::High);

    pool.submit_task(WorkerType::Recon, task, memory).unwrap();

    let results = pool.collect_completed();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, TaskStatus::Completed);
    assert!(!results[0].findings.is_empty());
  }
}
