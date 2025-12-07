//! Hybrid search implementation combining fuzzy and semantic search.
//!
//! This module provides:
//! - Fuzzy text search using Levenshtein distance and n-gram matching
//! - Semantic search using cosine similarity with pre-computed vectors
//! - Hybrid search combining both with Reciprocal Rank Fusion

use super::embeddings::EmbeddedDocument;
use std::collections::HashMap;

/// Search result with score and match details
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub document: EmbeddedDocument,
    pub score: f32,
    pub match_type: MatchType,
    pub highlights: Vec<String>,
}

/// Type of match that produced this result
#[derive(Debug, Clone, PartialEq)]
pub enum MatchType {
    Fuzzy,
    Semantic,
    Hybrid,
}

/// Search configuration
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Maximum number of results to return
    pub max_results: usize,
    /// Minimum score threshold (0.0 to 1.0)
    pub min_score: f32,
    /// Weight for fuzzy search in hybrid mode (0.0 to 1.0)
    pub fuzzy_weight: f32,
    /// Weight for semantic search in hybrid mode (0.0 to 1.0)
    pub semantic_weight: f32,
    /// Search mode
    pub mode: SearchMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SearchMode {
    Fuzzy,
    Semantic,
    Hybrid,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_results: 10,
            min_score: 0.1,
            fuzzy_weight: 0.4,
            semantic_weight: 0.6,
            mode: SearchMode::Hybrid,
        }
    }
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let len1 = s1_chars.len();
    let len2 = s2_chars.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0usize; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                0
            } else {
                1
            };

            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[len1][len2]
}

/// Calculate similarity score from Levenshtein distance (0.0 to 1.0)
fn levenshtein_similarity(s1: &str, s2: &str) -> f32 {
    let max_len = s1.len().max(s2.len());
    if max_len == 0 {
        return 1.0;
    }
    let distance = levenshtein_distance(s1, s2);
    1.0 - (distance as f32 / max_len as f32)
}

/// Generate n-grams from a string
fn ngrams(s: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < n {
        return vec![s.to_string()];
    }

    chars
        .windows(n)
        .map(|w| w.iter().collect::<String>())
        .collect()
}

/// Calculate Jaccard similarity between two sets of n-grams
fn ngram_similarity(s1: &str, s2: &str, n: usize) -> f32 {
    let ng1: std::collections::HashSet<_> = ngrams(&s1.to_lowercase(), n).into_iter().collect();
    let ng2: std::collections::HashSet<_> = ngrams(&s2.to_lowercase(), n).into_iter().collect();

    if ng1.is_empty() && ng2.is_empty() {
        return 1.0;
    }

    let intersection = ng1.intersection(&ng2).count();
    let union = ng1.union(&ng2).count();

    if union == 0 {
        return 0.0;
    }

    intersection as f32 / union as f32
}

/// Tokenize text into words
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .filter(|s| s.len() > 1)
        .map(String::from)
        .collect()
}

/// Calculate TF-IDF-like score for query terms in document
fn term_frequency_score(query_terms: &[String], doc_text: &str) -> f32 {
    let doc_lower = doc_text.to_lowercase();
    let doc_tokens: Vec<String> = tokenize(&doc_lower);

    if doc_tokens.is_empty() {
        return 0.0;
    }

    let mut score = 0.0;
    for term in query_terms {
        // Exact match
        let exact_count = doc_tokens.iter().filter(|t| *t == term).count();
        score += exact_count as f32 * 2.0;

        // Prefix match
        let prefix_count = doc_tokens
            .iter()
            .filter(|t| t.starts_with(term) && *t != term)
            .count();
        score += prefix_count as f32 * 1.0;

        // Contains match
        if doc_lower.contains(term) {
            score += 0.5;
        }
    }

    // Normalize by document length (avoid favoring long documents)
    score / (1.0 + (doc_tokens.len() as f32).ln())
}

/// Perform fuzzy search on documents
pub fn fuzzy_search(
    query: &str,
    documents: &[EmbeddedDocument],
    config: &SearchConfig,
) -> Vec<SearchResult> {
    let query_lower = query.to_lowercase();
    let query_terms = tokenize(&query_lower);

    let mut results: Vec<(usize, f32, Vec<String>)> = Vec::new();

    for (idx, doc) in documents.iter().enumerate() {
        let mut score = 0.0;
        let mut highlights = Vec::new();

        // Title match (highest weight)
        let title_lower = doc.title.to_lowercase();
        if title_lower.contains(&query_lower) {
            score += 10.0;
            highlights.push(format!("Title: {}", doc.title));
        } else {
            let title_sim = ngram_similarity(&query_lower, &title_lower, 3);
            if title_sim > 0.3 {
                score += title_sim * 6.0;
            }
        }

        // Section match (high weight)
        if let Some(ref section) = doc.section {
            let section_lower = section.to_lowercase();
            if section_lower.contains(&query_lower) {
                score += 5.0;
                highlights.push(format!("Section: {}", section));
            } else {
                let section_sim = ngram_similarity(&query_lower, &section_lower, 3);
                if section_sim > 0.3 {
                    score += section_sim * 3.0;
                }
            }
        }

        // Keyword match (high weight)
        for keyword in &doc.keywords {
            let kw_lower = keyword.to_lowercase();
            if kw_lower == query_lower {
                score += 8.0;
                highlights.push(format!("Keyword: {}", keyword));
            } else if kw_lower.contains(&query_lower) || query_lower.contains(&kw_lower) {
                score += 4.0;
                highlights.push(format!("Keyword: {}", keyword));
            } else {
                let kw_sim = levenshtein_similarity(&query_lower, &kw_lower);
                if kw_sim > 0.7 {
                    score += kw_sim * 3.0;
                }
            }
        }

        // Path match
        let path_lower = doc.path.to_lowercase();
        if path_lower.contains(&query_lower) {
            score += 2.0;
            highlights.push(format!("Path: {}", doc.path));
        }

        // Content match (TF-IDF style)
        let content_score = term_frequency_score(&query_terms, &doc.content);
        if content_score > 0.0 {
            score += content_score;
            // Find snippet (safe for UTF-8 multi-byte characters)
            let content_lower = doc.content.to_lowercase();
            for term in &query_terms {
                if let Some(pos) = content_lower.find(term) {
                    // Find safe char boundaries
                    let start = doc.content
                        .char_indices()
                        .map(|(i, _)| i)
                        .take_while(|&i| i <= pos.saturating_sub(30))
                        .last()
                        .unwrap_or(0);
                    let end = doc.content
                        .char_indices()
                        .map(|(i, _)| i)
                        .find(|&i| i >= (pos + term.len() + 30).min(doc.content.len()))
                        .unwrap_or(doc.content.len());
                    let snippet = &doc.content[start..end];
                    highlights.push(format!("...{}...", snippet.trim()));
                    break;
                }
            }
        }

        if score > 0.0 {
            results.push((idx, score, highlights));
        }
    }

    // Sort by score descending
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Normalize scores and convert to SearchResult
    let max_score = results.first().map(|(_, s, _)| *s).unwrap_or(1.0);

    results
        .into_iter()
        .take(config.max_results)
        .filter_map(|(idx, score, highlights)| {
            let normalized_score = score / max_score;
            if normalized_score < config.min_score {
                return None;
            }

            Some(SearchResult {
                document: documents[idx].clone(),
                score: normalized_score,
                match_type: MatchType::Fuzzy,
                highlights,
            })
        })
        .collect()
}

/// Calculate cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot / (norm_a * norm_b)
}

/// Generate a pseudo-embedding from query terms (term-based approximation)
/// This is used when we don't have a runtime model to embed the query
fn term_based_query_vector(query: &str, documents: &[EmbeddedDocument]) -> Vec<f32> {
    // This is a simplified approach that creates a sparse vector
    // based on keyword matching. Not as good as real embeddings,
    // but works without a model.

    let query_terms: std::collections::HashSet<_> = tokenize(query).into_iter().collect();

    // For each document, calculate a relevance score based on term overlap
    let mut doc_scores: Vec<f32> = Vec::with_capacity(documents.len());

    for doc in documents {
        let doc_terms: std::collections::HashSet<_> = doc
            .keywords
            .iter()
            .map(|k| k.to_lowercase())
            .chain(tokenize(&doc.title))
            .chain(tokenize(&doc.content))
            .collect();

        let intersection = query_terms.intersection(&doc_terms).count();
        let score = if query_terms.is_empty() {
            0.0
        } else {
            intersection as f32 / query_terms.len() as f32
        };

        doc_scores.push(score);
    }

    doc_scores
}

/// Perform semantic search using pre-computed embeddings
/// Note: This uses term-based approximation since we don't have a runtime model
pub fn semantic_search(
    query: &str,
    documents: &[EmbeddedDocument],
    config: &SearchConfig,
) -> Vec<SearchResult> {
    // Check if documents have vectors
    let has_vectors = documents.iter().any(|d| d.vector.is_some());

    if !has_vectors {
        // Fall back to term-based similarity
        return term_based_semantic_search(query, documents, config);
    }

    // Use pre-computed vectors with term-based query approximation
    let query_scores = term_based_query_vector(query, documents);

    let mut results: Vec<(usize, f32)> = Vec::new();

    for (idx, doc) in documents.iter().enumerate() {
        if let Some(ref _vector) = doc.vector {
            // Use the term-based score as our semantic score
            // (In a full implementation, we'd embed the query and use cosine similarity)
            let score = query_scores.get(idx).copied().unwrap_or(0.0);

            if score > 0.0 {
                results.push((idx, score));
            }
        }
    }

    // Sort by score descending
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Normalize and convert
    let max_score = results.first().map(|(_, s)| *s).unwrap_or(1.0);

    results
        .into_iter()
        .take(config.max_results)
        .filter_map(|(idx, score)| {
            let normalized_score = if max_score > 0.0 {
                score / max_score
            } else {
                0.0
            };

            if normalized_score < config.min_score {
                return None;
            }

            Some(SearchResult {
                document: documents[idx].clone(),
                score: normalized_score,
                match_type: MatchType::Semantic,
                highlights: vec![],
            })
        })
        .collect()
}

/// Term-based semantic search (fallback when no vectors available)
fn term_based_semantic_search(
    query: &str,
    documents: &[EmbeddedDocument],
    config: &SearchConfig,
) -> Vec<SearchResult> {
    let query_terms: std::collections::HashSet<_> = tokenize(query).into_iter().collect();

    let mut results: Vec<(usize, f32)> = Vec::new();

    for (idx, doc) in documents.iter().enumerate() {
        let doc_terms: std::collections::HashSet<_> = doc
            .keywords
            .iter()
            .map(|k| k.to_lowercase())
            .chain(tokenize(&doc.title))
            .collect();

        // Jaccard similarity
        let intersection = query_terms.intersection(&doc_terms).count();
        let union = query_terms.union(&doc_terms).count();

        let score = if union > 0 {
            intersection as f32 / union as f32
        } else {
            0.0
        };

        if score > 0.0 {
            results.push((idx, score));
        }
    }

    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let max_score = results.first().map(|(_, s)| *s).unwrap_or(1.0);

    results
        .into_iter()
        .take(config.max_results)
        .filter_map(|(idx, score)| {
            let normalized_score = score / max_score;
            if normalized_score < config.min_score {
                return None;
            }

            Some(SearchResult {
                document: documents[idx].clone(),
                score: normalized_score,
                match_type: MatchType::Semantic,
                highlights: vec![],
            })
        })
        .collect()
}

/// Reciprocal Rank Fusion to combine fuzzy and semantic results
fn reciprocal_rank_fusion(
    fuzzy_results: &[SearchResult],
    semantic_results: &[SearchResult],
    k: f32,
) -> HashMap<String, f32> {
    let mut scores: HashMap<String, f32> = HashMap::new();

    // Add fuzzy results
    for (rank, result) in fuzzy_results.iter().enumerate() {
        let rrf_score = 1.0 / (k + rank as f32 + 1.0);
        *scores.entry(result.document.id.clone()).or_insert(0.0) += rrf_score;
    }

    // Add semantic results
    for (rank, result) in semantic_results.iter().enumerate() {
        let rrf_score = 1.0 / (k + rank as f32 + 1.0);
        *scores.entry(result.document.id.clone()).or_insert(0.0) += rrf_score;
    }

    scores
}

/// Perform hybrid search combining fuzzy and semantic
pub fn hybrid_search(
    query: &str,
    documents: &[EmbeddedDocument],
    config: &SearchConfig,
) -> Vec<SearchResult> {
    match config.mode {
        SearchMode::Fuzzy => return fuzzy_search(query, documents, config),
        SearchMode::Semantic => return semantic_search(query, documents, config),
        SearchMode::Hybrid => {}
    }

    // Get results from both methods
    let fuzzy_results = fuzzy_search(query, documents, config);
    let semantic_results = semantic_search(query, documents, config);

    // Combine using Reciprocal Rank Fusion
    let combined_scores = reciprocal_rank_fusion(&fuzzy_results, &semantic_results, 60.0);

    // Create document lookup
    let doc_map: HashMap<String, &EmbeddedDocument> =
        documents.iter().map(|d| (d.id.clone(), d)).collect();

    let fuzzy_map: HashMap<String, &SearchResult> = fuzzy_results
        .iter()
        .map(|r| (r.document.id.clone(), r))
        .collect();

    let semantic_map: HashMap<String, &SearchResult> = semantic_results
        .iter()
        .map(|r| (r.document.id.clone(), r))
        .collect();

    // Sort by combined score
    let mut sorted_ids: Vec<_> = combined_scores.iter().collect();
    sorted_ids.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Build final results
    let max_score = sorted_ids.first().map(|(_, s)| **s).unwrap_or(1.0);

    sorted_ids
        .into_iter()
        .take(config.max_results)
        .filter_map(|(id, score)| {
            let doc = doc_map.get(id)?;
            let normalized_score = score / max_score;

            if normalized_score < config.min_score {
                return None;
            }

            // Combine highlights from both methods
            let mut highlights = Vec::new();
            if let Some(fuzzy) = fuzzy_map.get(id) {
                highlights.extend(fuzzy.highlights.clone());
            }
            if let Some(semantic) = semantic_map.get(id) {
                highlights.extend(semantic.highlights.clone());
            }

            Some(SearchResult {
                document: (*doc).clone(),
                score: normalized_score,
                match_type: MatchType::Hybrid,
                highlights,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_docs() -> Vec<EmbeddedDocument> {
        vec![
            EmbeddedDocument {
                id: "doc-0".to_string(),
                path: "docs/network.md".to_string(),
                title: "Network Scanning".to_string(),
                section: None,
                category: "network".to_string(),
                keywords: vec!["port".to_string(), "scan".to_string(), "tcp".to_string()],
                content: "Port scanning is used to discover open ports on a target host."
                    .to_string(),
                vector: None,
            },
            EmbeddedDocument {
                id: "doc-1".to_string(),
                path: "docs/dns.md".to_string(),
                title: "DNS Reconnaissance".to_string(),
                section: None,
                category: "dns".to_string(),
                keywords: vec!["dns".to_string(), "lookup".to_string(), "record".to_string()],
                content: "DNS reconnaissance involves querying DNS servers for information."
                    .to_string(),
                vector: None,
            },
        ]
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
        assert_eq!(levenshtein_distance("hello", "hallo"), 1);
        assert_eq!(levenshtein_distance("hello", ""), 5);
        assert_eq!(levenshtein_distance("", "hello"), 5);
    }

    #[test]
    fn test_ngram_similarity() {
        let sim = ngram_similarity("hello", "hello", 2);
        assert!((sim - 1.0).abs() < 0.001);

        let sim2 = ngram_similarity("hello", "world", 2);
        assert!(sim2 < 0.5);
    }

    #[test]
    fn test_fuzzy_search() {
        let docs = create_test_docs();
        let config = SearchConfig::default();

        let results = fuzzy_search("port scan", &docs, &config);
        assert!(!results.is_empty());
        assert_eq!(results[0].document.title, "Network Scanning");
    }

    #[test]
    fn test_hybrid_search() {
        let docs = create_test_docs();
        let config = SearchConfig::default();

        let results = hybrid_search("dns lookup", &docs, &config);
        assert!(!results.is_empty());
        assert_eq!(results[0].document.title, "DNS Reconnaissance");
    }
}
