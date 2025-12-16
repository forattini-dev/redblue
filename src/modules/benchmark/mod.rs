/// Load testing and performance benchmarking
#[cfg(not(target_os = "windows"))]
#[path = "load-generator.rs"]
pub mod load_generator;
pub mod stats;
#[path = "thread-pool.rs"]
pub mod thread_pool;

pub use crate::protocols::http::pool::{ConnectionPool, PooledHttpClient};
#[cfg(not(target_os = "windows"))]
pub use load_generator::{
    LiveSnapshot, LoadConfig, LoadGenerator, LoadMode, LoadTestResults, ProtocolOutcome,
    ProtocolPreference,
};
pub use stats::{AtomicStatsCollector, Percentile, RequestStats, StatsAggregator};
pub use thread_pool::ThreadPool;
