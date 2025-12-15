/// Response Filters for Web Fuzzing
///
/// Implements task 2.1.7-2.1.11:
/// - Response size filter (-fs)
/// - Response code filter (-fc)
/// - Word count filter (-fw)
/// - Line count filter (-fl)
/// - Regex filter (-fr)
///
/// Filters can include or exclude results based on response characteristics.
use super::FuzzResult;

/// Filter action result
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterAction {
    /// Include this result (show it)
    Include,
    /// Exclude this result (filter it out)
    Exclude,
    /// No match, continue to next filter
    None,
}

/// Response filter types
#[derive(Debug, Clone)]
pub enum ResponseFilter {
    /// Filter by HTTP status code
    /// - StatusCode(200) - include only 200
    /// - StatusCode(404) with exclude - filter out 404
    StatusCode { codes: Vec<u16>, exclude: bool },

    /// Filter by response size in bytes
    /// - Size { min: Some(100), max: Some(1000) } - between 100-1000 bytes
    /// - Size { min: None, max: Some(0) } - only empty responses
    Size {
        min: Option<usize>,
        max: Option<usize>,
        exclude: bool,
    },

    /// Filter by word count
    Words {
        min: Option<usize>,
        max: Option<usize>,
        exclude: bool,
    },

    /// Filter by line count
    Lines {
        min: Option<usize>,
        max: Option<usize>,
        exclude: bool,
    },

    /// Filter by regex pattern on response body
    Regex { pattern: String, exclude: bool },

    /// Filter by response time
    Time {
        min_ms: Option<u64>,
        max_ms: Option<u64>,
        exclude: bool,
    },

    /// Filter by content type
    ContentType { types: Vec<String>, exclude: bool },

    /// Simple match by status code (include only this code)
    MatchStatus(u16),

    /// Simple filter by status code (exclude this code)
    FilterStatus(u16),
}

impl ResponseFilter {
    /// Create a status code filter (include matching)
    pub fn status_include(codes: Vec<u16>) -> Self {
        ResponseFilter::StatusCode {
            codes,
            exclude: false,
        }
    }

    /// Create a status code filter (exclude matching)
    pub fn status_exclude(codes: Vec<u16>) -> Self {
        ResponseFilter::StatusCode {
            codes,
            exclude: true,
        }
    }

    /// Create a size filter (exclude matching)
    pub fn size_exclude(size: usize) -> Self {
        ResponseFilter::Size {
            min: Some(size),
            max: Some(size),
            exclude: true,
        }
    }

    /// Create a size range filter
    pub fn size_range(min: Option<usize>, max: Option<usize>, exclude: bool) -> Self {
        ResponseFilter::Size { min, max, exclude }
    }

    /// Create a word count filter (exclude matching)
    pub fn words_exclude(count: usize) -> Self {
        ResponseFilter::Words {
            min: Some(count),
            max: Some(count),
            exclude: true,
        }
    }

    /// Create a line count filter (exclude matching)
    pub fn lines_exclude(count: usize) -> Self {
        ResponseFilter::Lines {
            min: Some(count),
            max: Some(count),
            exclude: true,
        }
    }

    /// Create a regex filter
    pub fn regex(pattern: &str, exclude: bool) -> Self {
        ResponseFilter::Regex {
            pattern: pattern.to_string(),
            exclude,
        }
    }

    /// Check if a result matches this filter
    pub fn matches(&self, result: &FuzzResult) -> FilterAction {
        match self {
            ResponseFilter::StatusCode { codes, exclude } => {
                let matches = codes.contains(&result.status_code);
                if matches {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::Size { min, max, exclude } => {
                let in_range = Self::in_range(result.size, *min, *max);
                if in_range {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::Words { min, max, exclude } => {
                let in_range = Self::in_range(result.words, *min, *max);
                if in_range {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::Lines { min, max, exclude } => {
                let in_range = Self::in_range(result.lines, *min, *max);
                if in_range {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::Regex { pattern, exclude } => {
                // Simple pattern matching (not full regex)
                // For full regex, would need a regex engine
                let matches = Self::simple_pattern_match(pattern, &result.url)
                    || Self::simple_pattern_match(pattern, &result.payload);

                if matches {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::Time {
                min_ms,
                max_ms,
                exclude,
            } => {
                let duration_ms = result.duration.as_millis() as u64;
                let min = min_ms.unwrap_or(0);
                let max = max_ms.unwrap_or(u64::MAX);

                if duration_ms >= min && duration_ms <= max {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::ContentType { types, exclude } => {
                let matches = if let Some(ref ct) = result.content_type {
                    types
                        .iter()
                        .any(|t| ct.to_lowercase().contains(&t.to_lowercase()))
                } else {
                    false
                };

                if matches {
                    if *exclude {
                        FilterAction::Exclude
                    } else {
                        FilterAction::Include
                    }
                } else {
                    FilterAction::None
                }
            }

            ResponseFilter::MatchStatus(code) => {
                if result.status_code == *code {
                    FilterAction::Include
                } else {
                    FilterAction::Exclude
                }
            }

            ResponseFilter::FilterStatus(code) => {
                if result.status_code == *code {
                    FilterAction::Exclude
                } else {
                    FilterAction::None
                }
            }
        }
    }

    fn in_range(value: usize, min: Option<usize>, max: Option<usize>) -> bool {
        let min_ok = min.map(|m| value >= m).unwrap_or(true);
        let max_ok = max.map(|m| value <= m).unwrap_or(true);
        min_ok && max_ok
    }

    /// Simple pattern matching (supports * wildcard)
    fn simple_pattern_match(pattern: &str, text: &str) -> bool {
        if pattern.is_empty() {
            return true;
        }

        let pattern = pattern.to_lowercase();
        let text = text.to_lowercase();

        if !pattern.contains('*') {
            return text.contains(&pattern);
        }

        // Split by * and check if parts appear in order
        let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();

        if parts.is_empty() {
            return true;
        }

        let mut pos = 0;
        for part in parts {
            if let Some(found_pos) = text[pos..].find(part) {
                pos += found_pos + part.len();
            } else {
                return false;
            }
        }

        true
    }
}

/// Parse filter string from command line
/// Format: -fc 404,403 -fs 0 -fw 10 -fl 5 -fr "error"
pub fn parse_filter_args(args: &[String]) -> Vec<ResponseFilter> {
    let mut filters = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        match arg.as_str() {
            "-fc" | "--filter-code" => {
                if i + 1 < args.len() {
                    let codes: Vec<u16> = args[i + 1]
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                    if !codes.is_empty() {
                        filters.push(ResponseFilter::status_exclude(codes));
                    }
                    i += 1;
                }
            }

            "-fs" | "--filter-size" => {
                if i + 1 < args.len() {
                    if let Ok(size) = args[i + 1].trim().parse::<usize>() {
                        filters.push(ResponseFilter::size_exclude(size));
                    }
                    i += 1;
                }
            }

            "-fw" | "--filter-words" => {
                if i + 1 < args.len() {
                    if let Ok(count) = args[i + 1].trim().parse::<usize>() {
                        filters.push(ResponseFilter::words_exclude(count));
                    }
                    i += 1;
                }
            }

            "-fl" | "--filter-lines" => {
                if i + 1 < args.len() {
                    if let Ok(count) = args[i + 1].trim().parse::<usize>() {
                        filters.push(ResponseFilter::lines_exclude(count));
                    }
                    i += 1;
                }
            }

            "-fr" | "--filter-regex" => {
                if i + 1 < args.len() {
                    filters.push(ResponseFilter::regex(&args[i + 1], true));
                    i += 1;
                }
            }

            "-mc" | "--match-code" => {
                if i + 1 < args.len() {
                    let codes: Vec<u16> = args[i + 1]
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                    if !codes.is_empty() {
                        filters.push(ResponseFilter::status_include(codes));
                    }
                    i += 1;
                }
            }

            _ => {}
        }

        i += 1;
    }

    filters
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_result(status: u16, size: usize, words: usize, lines: usize) -> FuzzResult {
        FuzzResult {
            payload: "test".into(),
            url: "http://example.com/test".into(),
            status_code: status,
            size,
            words,
            lines,
            duration: Duration::from_millis(100),
            filtered: false,
            redirect: None,
            content_type: Some("text/html".into()),
        }
    }

    #[test]
    fn test_status_filter() {
        let result = make_result(404, 100, 10, 5);

        let filter = ResponseFilter::status_exclude(vec![404]);
        assert_eq!(filter.matches(&result), FilterAction::Exclude);

        let filter = ResponseFilter::status_exclude(vec![500]);
        assert_eq!(filter.matches(&result), FilterAction::None);
    }

    #[test]
    fn test_size_filter() {
        let result = make_result(200, 1000, 10, 5);

        let filter = ResponseFilter::size_exclude(1000);
        assert_eq!(filter.matches(&result), FilterAction::Exclude);

        let filter = ResponseFilter::size_exclude(500);
        assert_eq!(filter.matches(&result), FilterAction::None);
    }

    #[test]
    fn test_simple_pattern() {
        assert!(ResponseFilter::simple_pattern_match("error", "error page"));
        assert!(ResponseFilter::simple_pattern_match(
            "not*found",
            "not found"
        ));
        assert!(ResponseFilter::simple_pattern_match("*", "anything"));
        assert!(!ResponseFilter::simple_pattern_match("admin", "error page"));
    }
}
