/// Simple thread pool for reusing worker threads
/// This avoids the overhead of creating/destroying threads for each test
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

enum Message {
    NewJob(Job),
    Terminate,
}

/// Worker thread that executes jobs from the queue
struct Worker {
    _id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<std::sync::mpsc::Receiver<Message>>>) -> Self {
        let thread = thread::Builder::new()
            .stack_size(256 * 1024) // Same 256KB stack as before
            .spawn(move || loop {
                // Wait for a job or termination signal
                let message = {
                    let receiver = receiver.lock().unwrap();
                    receiver.recv()
                };

                match message {
                    Ok(Message::NewJob(job)) => {
                        // Execute the job
                        job();
                    }
                    Ok(Message::Terminate) | Err(_) => {
                        // Terminate this worker
                        break;
                    }
                }
            })
            .expect("Failed to spawn worker thread");

        Self {
            _id: id,
            thread: Some(thread),
        }
    }
}

/// Thread pool that maintains a pool of reusable worker threads
pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<Sender<Message>>,
}

impl ThreadPool {
    /// Create a new thread pool with the specified number of workers
    pub fn new(size: usize) -> Self {
        assert!(size > 0, "Thread pool size must be greater than 0");

        let (sender, receiver) = channel();
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        Self {
            workers,
            sender: Some(sender),
        }
    }

    /// Execute a job on the thread pool
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender
            .as_ref()
            .expect("Thread pool has been dropped")
            .send(Message::NewJob(job))
            .expect("Failed to send job to thread pool");
    }

    /// Get the number of workers in the pool
    pub fn size(&self) -> usize {
        self.workers.len()
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        // Send terminate message to all workers
        if let Some(sender) = self.sender.take() {
            for _ in &self.workers {
                let _ = sender.send(Message::Terminate);
            }
        }

        // Wait for all workers to finish
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_thread_pool_execution() {
        let pool = ThreadPool::new(4);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..10 {
            let counter = Arc::clone(&counter);
            pool.execute(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Give threads time to execute
        thread::sleep(Duration::from_millis(100));

        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn test_thread_pool_size() {
        let pool = ThreadPool::new(8);
        assert_eq!(pool.size(), 8);
    }
}
