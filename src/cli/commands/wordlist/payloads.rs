fn wordlist_category_name(category: WordlistCategory) -> &'static str {
  match category {
    WordlistCategory::Passwords => "passwords",
    WordlistCategory::Subdomains => "subdomains",
    WordlistCategory::Directories => "directories",
    WordlistCategory::Usernames => "usernames",
    WordlistCategory::Vhosts => "vhosts",
    WordlistCategory::Mixed => "mixed",
  }
}

fn wordlist_info_to_json(
  info: &crate::wordlists::manager::WordlistInfo,
) -> crate::serde_json::Value {
  json!({
      "name": info.name.clone(),
      "source": info.source.clone(),
      "line_count": info.line_count,
      "size_kb": info.size_kb
  })
}

fn wordlist_list_payload(filtered: &[&crate::wordlists::manager::WordlistInfo]) -> Value {
  let wordlists_json: Vec<Value> = filtered.iter().map(|w| wordlist_info_to_json(w)).collect();
  json!({
    "total": filtered.len(),
    "wordlists": wordlists_json
  })
}

fn wordlist_collection_info_payload(
  name: &str,
  lines: usize,
  size_bytes: usize,
  size_kb: usize,
  source: &str,
  wordlist: &[String],
) -> Value {
  let preview: Vec<String> = wordlist.iter().take(10).cloned().collect();
  json!({
    "name": name,
    "lines": lines,
    "size_bytes": size_bytes,
    "size_kb": size_kb,
    "source": source,
    "preview": preview
  })
}

fn wordlist_collection_error_payload(name: &str, error: &str) -> Value {
  json!({
    "success": false,
    "error": error,
    "name": name
  })
}

fn wordlist_status_payload(
  cache_directory: &str,
  directory_exists: bool,
  cache_size_bytes: u64,
  cache_size_mb: u64,
  embedded: usize,
  cached: usize,
) -> Value {
  json!({
    "cache_directory": cache_directory,
    "directory_exists": directory_exists,
    "cache_size_bytes": cache_size_bytes,
    "cache_size_mb": cache_size_mb,
    "counts": json!({
      "embedded": embedded,
      "cached": cached,
      "total": embedded + cached
    })
  })
}

fn wordlist_category_error_payload(category: &str) -> Value {
  json!({
    "success": false,
    "error": "unknown_category",
    "category": category
  })
}

fn wordlist_sources_payload(filtered: &[crate::wordlists::downloader::WordlistSource]) -> Value {
  let sources_json: Vec<Value> = filtered.iter().map(wordlist_source_to_json).collect();
  json!({
    "total": filtered.len(),
    "sources": sources_json
  })
}

fn wordlist_search_payload(
  query: &str,
  results: &[crate::wordlists::downloader::WordlistSource],
) -> Value {
  let results_json: Vec<Value> = results.iter().map(wordlist_source_to_json).collect();
  json!({
    "query": query,
    "total": results.len(),
    "results": results_json
  })
}

fn wordlist_source_to_json(
  source: &crate::wordlists::downloader::WordlistSource,
) -> crate::serde_json::Value {
  json!({
      "name": source.name,
      "category": wordlist_category_name(source.category),
      "size_hint": source.size_hint,
      "description": source.description
  })
}

fn checkpoint_info_to_json(
  checkpoint: &crate::modules::web::fuzzer::resume::CheckpointInfo,
) -> crate::serde_json::Value {
  json!({
      "scan_id": checkpoint.scan_id.to_string(),
      "target": checkpoint.target_url.clone(),
      "progress": checkpoint.progress_percent,
      "requests": checkpoint.requests_made,
      "elapsed": checkpoint.elapsed_string()
  })
}

fn wordlist_file_error_payload(path: &str, error: &str) -> Value {
  json!({
    "success": false,
    "error": error,
    "path": path
  })
}

fn wordlist_file_info_payload(
  path: &str,
  stats: &crate::modules::wordlist::analysis::WordlistStats,
  lines: &[String],
) -> Value {
  let preview: Vec<String> = lines.iter().take(10).cloned().collect();
  json!({
    "path": path,
    "line_count": stats.line_count,
    "unique_count": stats.unique_count,
    "avg_length": stats.avg_length,
    "min_length": stats.min_length,
    "max_length": stats.max_length,
    "charset": stats.charset.clone(),
    "preview": preview
  })
}

fn wordlist_resolve_payload(
  context: &crate::modules::wordlist::WordlistContext,
  size: &crate::modules::wordlist::WordlistSize,
  recommendations: &[&str],
) -> Value {
  let wordlists: Vec<String> = recommendations
    .iter()
    .map(|name| (*name).to_string())
    .collect();
  json!({
    "context": format!("{:?}", context),
    "size": format!("{:?}", size),
    "wordlists": wordlists
  })
}

fn wordlist_learn_payload(top_n: usize) -> Value {
  json!({
    "learned_words": [],
    "total": 0,
    "top": top_n,
    "note": "No learned words available. Run a scan with --learn-words to collect vocabulary."
  })
}

fn wordlist_extract_empty_payload() -> Value {
  json!({
    "words": [],
    "total": 0
  })
}

fn wordlist_extract_payload(
  source: &str,
  total_extracted: usize,
  scores: &[crate::modules::wordlist::tfidf::ScoredWord],
) -> Value {
  let words_json: Vec<Value> = scores
    .iter()
    .map(|word| {
      json!({
        "word": word.word.clone(),
        "score": word.tfidf
      })
    })
    .collect();
  json!({
    "source": source,
    "total_extracted": total_extracted,
    "words": words_json
  })
}

fn wordlist_checkpoints_payload(
  checkpoints: &[crate::modules::web::fuzzer::resume::CheckpointInfo],
) -> Value {
  let checkpoints_json: Vec<Value> = checkpoints.iter().map(checkpoint_info_to_json).collect();
  json!({
    "checkpoints": checkpoints_json
  })
}
