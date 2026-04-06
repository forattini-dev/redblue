pub mod analysis;
pub mod combinator;
pub mod context;
pub mod dedup;
pub mod extractor;
pub mod filter;
pub mod loader;
pub mod manager;
pub mod mutations;
pub mod patterns;
pub mod preview;
pub mod rules;
pub mod sorter;
pub mod tfidf;
pub mod vhosts;

// Re-export key types
pub use context::ContextResolver;
pub use extractor::{ExtractionResult, ExtractorBuilder, ExtractorConfig, WordExtractor};
pub use manager::{
  LearnedWord, MutationRule, WordlistConfig, WordlistContext, WordlistFilter, WordlistIterator,
  WordlistManager, WordlistRequest, WordlistSize,
};
pub use tfidf::{Document, IncrementalLearner, ScoredWord, TfIdfBuilder, TfIdfConfig, TfIdfEngine};
pub use vhosts::{VHostCategory, VHostWordlist, CLOUD_MODERN, COMMON_VHOSTS, PENTEST_FOCUSED};
