//! Helper utilities for MITRE ATT&CK commands
//!
//! Common functions used across the intel_mitre submodules.

/// Wrap text to specified width
pub fn wrap_text(s: &str, width: usize) -> String {
    let mut result = String::new();
    let mut current_line = String::new();

    for word in s.split_whitespace() {
        if current_line.len() + word.len() + 1 > width {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&current_line);
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&current_line);
    }

    result
}
