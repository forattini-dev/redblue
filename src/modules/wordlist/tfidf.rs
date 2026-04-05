//! TF-IDF Learning Engine for Intelligent Discovery
//!
//! Calculates Term Frequency - Inverse Document Frequency scores for learned words.
//! Used to prioritize the most relevant discovered words for fuzzing.

use std::collections::{HashMap, HashSet};

/// A document for TF-IDF analysis (represents a single HTTP response)
#[derive(Debug, Clone)]
pub struct Document {
    /// Unique identifier (URL or response hash)
    pub id: String,
    /// Words extracted from this document
    pub words: Vec<String>,
    /// Domain this document belongs to
    pub domain: Option<String>,
}

impl Document {
    /// Create a new document
    pub fn new(id: impl Into<String>, words: Vec<String>) -> Self {
        Self {
            id: id.into(),
            words,
            domain: None,
        }
    }

    /// Create a document with domain association
    pub fn with_domain(
        id: impl Into<String>,
        words: Vec<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            words,
            domain: Some(domain.into()),
        }
    }
}

/// TF-IDF scored word
#[derive(Debug, Clone)]
pub struct ScoredWord {
    /// The word
    pub word: String,
    /// Term frequency in the corpus
    pub tf: f64,
    /// Inverse document frequency
    pub idf: f64,
    /// Combined TF-IDF score
    pub tfidf: f64,
    /// Number of documents containing this word
    pub document_count: usize,
    /// Total occurrences across all documents
    pub total_occurrences: usize,
}

impl ScoredWord {
    /// Check if this word is considered "rare" (high IDF)
    pub fn is_rare(&self) -> bool {
        self.idf > 2.0
    }

    /// Check if this word is considered "common" (low IDF)
    pub fn is_common(&self) -> bool {
        self.idf < 0.5
    }
}

/// Configuration for the TF-IDF engine
#[derive(Debug, Clone)]
pub struct TfIdfConfig {
    /// Minimum TF-IDF score to keep a word
    pub min_score: f64,
    /// Maximum number of words to keep in vocabulary
    pub max_vocabulary_size: usize,
    /// Whether to use sublinear TF scaling (1 + log(tf))
    pub sublinear_tf: bool,
    /// Whether to smooth IDF (add 1 to document counts)
    pub smooth_idf: bool,
    /// Minimum document frequency to consider a word
    pub min_df: usize,
    /// Maximum document frequency ratio (0.0-1.0) to filter common words
    pub max_df_ratio: f64,
}

impl Default for TfIdfConfig {
    fn default() -> Self {
        Self {
            min_score: 0.01,
            max_vocabulary_size: 10000,
            sublinear_tf: true,
            smooth_idf: true,
            min_df: 1,
            max_df_ratio: 0.95,
        }
    }
}

impl TfIdfConfig {
    /// Configuration optimized for discovery (favor rare words)
    pub fn for_discovery() -> Self {
        Self {
            min_score: 0.05,
            max_vocabulary_size: 5000,
            sublinear_tf: true,
            smooth_idf: true,
            min_df: 1,
            max_df_ratio: 0.5, // Exclude words in >50% of documents
        }
    }

    /// Configuration for comprehensive vocabulary
    pub fn comprehensive() -> Self {
        Self {
            min_score: 0.001,
            max_vocabulary_size: 50000,
            sublinear_tf: true,
            smooth_idf: true,
            min_df: 1,
            max_df_ratio: 0.99,
        }
    }
}

/// TF-IDF Learning Engine
///
/// Tracks word frequencies across documents and calculates TF-IDF scores.
pub struct TfIdfEngine {
    config: TfIdfConfig,
    /// Document frequency: word -> set of document IDs containing the word
    document_frequency: HashMap<String, HashSet<String>>,
    /// Term frequency: word -> total count across all documents
    term_frequency: HashMap<String, usize>,
    /// Document count
    document_count: usize,
    /// Per-document term counts for incremental updates
    document_terms: HashMap<String, HashMap<String, usize>>,
    /// Cached TF-IDF scores (invalidated on updates)
    cached_scores: Option<Vec<ScoredWord>>,
}

impl TfIdfEngine {
    /// Create a new TF-IDF engine with the given configuration
    pub fn new(config: TfIdfConfig) -> Self {
        Self {
            config,
            document_frequency: HashMap::new(),
            term_frequency: HashMap::new(),
            document_count: 0,
            document_terms: HashMap::new(),
            cached_scores: None,
        }
    }

    /// Create a TF-IDF engine with default configuration
    pub fn with_defaults() -> Self {
        Self::new(TfIdfConfig::default())
    }

    /// Add a document to the corpus
    pub fn add_document(&mut self, doc: Document) {
        // Invalidate cache
        self.cached_scores = None;

        // Track document
        self.document_count += 1;

        // Count words in this document
        let mut word_counts: HashMap<String, usize> = HashMap::new();
        for word in &doc.words {
            *word_counts.entry(word.clone()).or_insert(0) += 1;
        }

        // Update global frequencies
        for (word, count) in &word_counts {
            // Update document frequency (which documents contain this word)
            self.document_frequency
                .entry(word.clone())
                .or_insert_with(HashSet::new)
                .insert(doc.id.clone());

            // Update term frequency (total occurrences)
            *self.term_frequency.entry(word.clone()).or_insert(0) += count;
        }

        // Store per-document terms for potential removal
        self.document_terms.insert(doc.id.clone(), word_counts);
    }

    /// Add multiple documents at once
    pub fn add_documents(&mut self, docs: Vec<Document>) {
        for doc in docs {
            self.add_document(doc);
        }
    }

    /// Remove a document from the corpus
    pub fn remove_document(&mut self, doc_id: &str) -> bool {
        if let Some(word_counts) = self.document_terms.remove(doc_id) {
            // Invalidate cache
            self.cached_scores = None;
            self.document_count = self.document_count.saturating_sub(1);

            // Update frequencies
            for (word, count) in word_counts {
                // Remove from document frequency
                if let Some(doc_set) = self.document_frequency.get_mut(&word) {
                    doc_set.remove(doc_id);
                    if doc_set.is_empty() {
                        self.document_frequency.remove(&word);
                    }
                }

                // Update term frequency
                if let Some(tf) = self.term_frequency.get_mut(&word) {
                    *tf = tf.saturating_sub(count);
                    if *tf == 0 {
                        self.term_frequency.remove(&word);
                    }
                }
            }

            true
        } else {
            false
        }
    }

    /// Calculate TF (Term Frequency) for a word
    fn calculate_tf(&self, word: &str) -> f64 {
        let count = *self.term_frequency.get(word).unwrap_or(&0) as f64;

        if self.config.sublinear_tf {
            // Sublinear scaling: 1 + log(tf)
            if count > 0.0 {
                1.0 + count.ln()
            } else {
                0.0
            }
        } else {
            count
        }
    }

    /// Calculate IDF (Inverse Document Frequency) for a word
    fn calculate_idf(&self, word: &str) -> f64 {
        let doc_freq = self
            .document_frequency
            .get(word)
            .map(|s| s.len())
            .unwrap_or(0) as f64;

        let n = self.document_count as f64;

        if self.config.smooth_idf {
            // Smooth IDF: log((N + 1) / (df + 1)) + 1
            ((n + 1.0) / (doc_freq + 1.0)).ln() + 1.0
        } else {
            // Standard IDF: log(N / df)
            if doc_freq > 0.0 {
                (n / doc_freq).ln()
            } else {
                0.0
            }
        }
    }

    /// Calculate TF-IDF scores for all words
    pub fn calculate_scores(&mut self) -> &[ScoredWord] {
        if self.cached_scores.is_none() {
            let mut scores: Vec<ScoredWord> = Vec::new();
            let n = self.document_count as f64;
            let max_df = (n * self.config.max_df_ratio) as usize;

            for (word, doc_set) in &self.document_frequency {
                let doc_count = doc_set.len();

                // Filter by document frequency
                if doc_count < self.config.min_df {
                    continue;
                }
                if doc_count > max_df {
                    continue;
                }

                let tf = self.calculate_tf(word);
                let idf = self.calculate_idf(word);
                let tfidf = tf * idf;

                // Filter by minimum score
                if tfidf < self.config.min_score {
                    continue;
                }

                let total_occurrences = *self.term_frequency.get(word).unwrap_or(&0);

                scores.push(ScoredWord {
                    word: word.clone(),
                    tf,
                    idf,
                    tfidf,
                    document_count: doc_count,
                    total_occurrences,
                });
            }

            // Sort by TF-IDF score (descending)
            scores.sort_by(|a, b| {
                b.tfidf
                    .partial_cmp(&a.tfidf)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Limit vocabulary size
            if scores.len() > self.config.max_vocabulary_size {
                scores.truncate(self.config.max_vocabulary_size);
            }

            self.cached_scores = Some(scores);
        }

        self.cached_scores.as_ref().unwrap()
    }

    /// Get top N words by TF-IDF score
    pub fn top_words(&mut self, n: usize) -> Vec<ScoredWord> {
        let scores = self.calculate_scores();
        scores.iter().take(n).cloned().collect()
    }

    /// Get words above a minimum TF-IDF score
    pub fn words_above_score(&mut self, min_score: f64) -> Vec<ScoredWord> {
        let scores = self.calculate_scores();
        scores
            .iter()
            .filter(|w| w.tfidf >= min_score)
            .cloned()
            .collect()
    }

    /// Get rare words (high IDF, likely unique to specific endpoints)
    pub fn rare_words(&mut self, n: usize) -> Vec<ScoredWord> {
        let scores = self.calculate_scores();
        let mut rare: Vec<_> = scores.iter().filter(|w| w.is_rare()).cloned().collect();
        rare.sort_by(|a, b| {
            b.idf
                .partial_cmp(&a.idf)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        rare.truncate(n);
        rare
    }

    /// Get common words (low IDF, present in many documents)
    pub fn common_words(&mut self, n: usize) -> Vec<ScoredWord> {
        let scores = self.calculate_scores();
        let mut common: Vec<_> = scores.iter().filter(|w| w.is_common()).cloned().collect();
        common.sort_by(|a, b| {
            a.idf
                .partial_cmp(&b.idf)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        common.truncate(n);
        common
    }

    /// Get just the words as a vector of strings (for wordlist generation)
    pub fn vocabulary(&mut self) -> Vec<String> {
        self.calculate_scores()
            .iter()
            .map(|w| w.word.clone())
            .collect()
    }

    /// Get statistics about the corpus
    pub fn stats(&self) -> TfIdfStats {
        TfIdfStats {
            document_count: self.document_count,
            vocabulary_size: self.document_frequency.len(),
            total_term_occurrences: self.term_frequency.values().sum(),
        }
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.document_frequency.clear();
        self.term_frequency.clear();
        self.document_count = 0;
        self.document_terms.clear();
        self.cached_scores = None;
    }

    /// Merge another TF-IDF engine's data into this one
    pub fn merge(&mut self, other: &TfIdfEngine) {
        // Invalidate cache
        self.cached_scores = None;

        for (doc_id, word_counts) in &other.document_terms {
            // Skip if already present
            if self.document_terms.contains_key(doc_id) {
                continue;
            }

            self.document_count += 1;

            for (word, count) in word_counts {
                self.document_frequency
                    .entry(word.clone())
                    .or_insert_with(HashSet::new)
                    .insert(doc_id.clone());

                *self.term_frequency.entry(word.clone()).or_insert(0) += count;
            }

            self.document_terms
                .insert(doc_id.clone(), word_counts.clone());
        }
    }

    /// Export vocabulary with scores for persistence
    pub fn export(&mut self) -> Vec<(String, f64, usize)> {
        self.calculate_scores()
            .iter()
            .map(|w| (w.word.clone(), w.tfidf, w.document_count))
            .collect()
    }

    /// Import vocabulary from persistence
    /// Note: This is a simplified import that doesn't reconstruct full document relationships
    pub fn import_vocabulary(&mut self, vocab: Vec<(String, f64, usize)>) {
        self.cached_scores = None;

        for (word, _score, doc_count) in vocab {
            // Create synthetic document frequency
            let mut doc_set = HashSet::new();
            for i in 0..doc_count {
                doc_set.insert(format!("_imported_{}", i));
            }
            self.document_frequency.insert(word.clone(), doc_set);
            self.term_frequency.insert(word, doc_count);
        }

        // Update document count estimate
        self.document_count = self
            .document_frequency
            .values()
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
    }
}

/// Statistics about the TF-IDF corpus
#[derive(Debug, Clone)]
pub struct TfIdfStats {
    /// Number of documents in the corpus
    pub document_count: usize,
    /// Number of unique words in vocabulary
    pub vocabulary_size: usize,
    /// Total term occurrences across all documents
    pub total_term_occurrences: usize,
}

/// Builder for TfIdfEngine
pub struct TfIdfBuilder {
    config: TfIdfConfig,
    initial_docs: Vec<Document>,
}

impl TfIdfBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: TfIdfConfig::default(),
            initial_docs: Vec::new(),
        }
    }

    /// Set minimum TF-IDF score
    pub fn min_score(mut self, score: f64) -> Self {
        self.config.min_score = score;
        self
    }

    /// Set maximum vocabulary size
    pub fn max_vocabulary(mut self, size: usize) -> Self {
        self.config.max_vocabulary_size = size;
        self
    }

    /// Enable/disable sublinear TF scaling
    pub fn sublinear_tf(mut self, enable: bool) -> Self {
        self.config.sublinear_tf = enable;
        self
    }

    /// Enable/disable IDF smoothing
    pub fn smooth_idf(mut self, enable: bool) -> Self {
        self.config.smooth_idf = enable;
        self
    }

    /// Set minimum document frequency
    pub fn min_df(mut self, min: usize) -> Self {
        self.config.min_df = min;
        self
    }

    /// Set maximum document frequency ratio
    pub fn max_df_ratio(mut self, ratio: f64) -> Self {
        self.config.max_df_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Add initial documents
    pub fn with_documents(mut self, docs: Vec<Document>) -> Self {
        self.initial_docs = docs;
        self
    }

    /// Build the TF-IDF engine
    pub fn build(self) -> TfIdfEngine {
        let mut engine = TfIdfEngine::new(self.config);
        engine.add_documents(self.initial_docs);
        engine
    }
}

impl Default for TfIdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental TF-IDF learner for real-time learning during scans
pub struct IncrementalLearner {
    engine: TfIdfEngine,
    /// Minimum documents before calculating scores
    min_documents: usize,
    /// How often to recalculate scores (every N documents)
    recalc_interval: usize,
    docs_since_recalc: usize,
}

impl IncrementalLearner {
    /// Create a new incremental learner
    pub fn new(min_documents: usize, recalc_interval: usize) -> Self {
        Self {
            engine: TfIdfEngine::new(TfIdfConfig::for_discovery()),
            min_documents,
            recalc_interval,
            docs_since_recalc: 0,
        }
    }

    /// Learn from a new response
    pub fn learn(&mut self, doc_id: &str, words: Vec<String>) {
        self.engine.add_document(Document::new(doc_id, words));
        self.docs_since_recalc += 1;
    }

    /// Learn from a new response with domain association
    pub fn learn_with_domain(&mut self, doc_id: &str, words: Vec<String>, domain: &str) {
        self.engine
            .add_document(Document::with_domain(doc_id, words, domain));
        self.docs_since_recalc += 1;
    }

    /// Check if ready to provide word suggestions
    pub fn is_ready(&self) -> bool {
        self.engine.document_count >= self.min_documents
    }

    /// Get current top learned words (if ready)
    pub fn suggestions(&mut self, n: usize) -> Option<Vec<String>> {
        if !self.is_ready() {
            return None;
        }

        // Recalculate if needed
        if self.docs_since_recalc >= self.recalc_interval {
            self.engine.cached_scores = None;
            self.docs_since_recalc = 0;
        }

        Some(
            self.engine
                .top_words(n)
                .into_iter()
                .map(|w| w.word)
                .collect(),
        )
    }

    /// Get all learned vocabulary
    pub fn vocabulary(&mut self) -> Vec<String> {
        self.engine.vocabulary()
    }

    /// Get the underlying engine for persistence
    pub fn engine(&self) -> &TfIdfEngine {
        &self.engine
    }

    /// Get mutable access to the engine
    pub fn engine_mut(&mut self) -> &mut TfIdfEngine {
        &mut self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tfidf() {
        let mut engine = TfIdfEngine::with_defaults();

        // Add some documents
        engine.add_document(Document::new(
            "doc1",
            vec!["admin".into(), "dashboard".into(), "login".into()],
        ));
        engine.add_document(Document::new(
            "doc2",
            vec!["admin".into(), "users".into(), "settings".into()],
        ));
        engine.add_document(Document::new(
            "doc3",
            vec!["config".into(), "settings".into(), "backup".into()],
        ));

        let scores = engine.calculate_scores();

        // admin appears in 2/3 docs, so moderate IDF
        // config and backup appear in 1/3 docs, so higher IDF
        assert!(scores.iter().any(|s| s.word == "admin"));
        assert!(scores.iter().any(|s| s.word == "backup"));
    }

    #[test]
    fn test_top_words() {
        let mut engine = TfIdfEngine::with_defaults();

        engine.add_document(Document::new(
            "doc1",
            vec![
                "rare_word".into(),
                "common".into(),
                "common".into(),
                "common".into(),
            ],
        ));
        engine.add_document(Document::new(
            "doc2",
            vec!["common".into(), "another".into()],
        ));

        let top = engine.top_words(2);
        assert!(!top.is_empty());
    }

    #[test]
    fn test_incremental_learner() {
        let mut learner = IncrementalLearner::new(3, 5);

        // Not ready yet
        assert!(!learner.is_ready());

        learner.learn("r1", vec!["admin".into(), "api".into()]);
        learner.learn("r2", vec!["admin".into(), "config".into()]);

        // Still not ready (need 3 docs)
        assert!(!learner.is_ready());
        assert!(learner.suggestions(5).is_none());

        learner.learn("r3", vec!["api".into(), "endpoint".into()]);

        // Now ready
        assert!(learner.is_ready());
        let suggestions = learner.suggestions(5);
        assert!(suggestions.is_some());
    }

    #[test]
    fn test_document_removal() {
        let mut engine = TfIdfEngine::with_defaults();

        engine.add_document(Document::new(
            "doc1",
            vec!["unique".into(), "shared".into()],
        ));
        engine.add_document(Document::new("doc2", vec!["other".into(), "shared".into()]));

        assert_eq!(engine.stats().document_count, 2);

        engine.remove_document("doc1");

        assert_eq!(engine.stats().document_count, 1);
        // "unique" should be removed since it was only in doc1
        assert!(!engine.document_frequency.contains_key("unique"));
        // "shared" should still exist
        assert!(engine.document_frequency.contains_key("shared"));
    }

    #[test]
    fn test_builder() {
        let engine = TfIdfBuilder::new()
            .min_score(0.1)
            .max_vocabulary(1000)
            .sublinear_tf(true)
            .build();

        assert_eq!(engine.config.min_score, 0.1);
        assert_eq!(engine.config.max_vocabulary_size, 1000);
    }
}
