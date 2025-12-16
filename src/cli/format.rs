#![allow(dead_code)]

/// Output formatting system - supports multiple output formats
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum OutputFormat {
    /// Human-readable colorized output (default)
    #[default]
    Human,
    /// JSON output for automation/scripting
    Json,
    /// YAML output for configuration
    Yaml,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "human" | "h" => Some(OutputFormat::Human),
            "json" | "j" => Some(OutputFormat::Json),
            "yaml" | "yml" | "y" => Some(OutputFormat::Yaml),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            OutputFormat::Human => "human",
            OutputFormat::Json => "json",
            OutputFormat::Yaml => "yaml",
        }
    }
}

/// JSON output builder
pub struct JsonOutput {
    data: HashMap<String, serde_json::Value>,
}

impl JsonOutput {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn add_string(&mut self, key: &str, value: String) {
        self.data
            .insert(key.to_string(), serde_json::Value::String(value));
    }

    pub fn add_array(&mut self, key: &str, values: Vec<String>) {
        let json_values: Vec<serde_json::Value> =
            values.into_iter().map(serde_json::Value::String).collect();
        self.data
            .insert(key.to_string(), serde_json::Value::Array(json_values));
    }

    pub fn add_number(&mut self, key: &str, value: usize) {
        self.data
            .insert(key.to_string(), serde_json::Value::Number(value.into()));
    }

    pub fn add_bool(&mut self, key: &str, value: bool) {
        self.data
            .insert(key.to_string(), serde_json::Value::Bool(value));
    }

    pub fn add_object(&mut self, key: &str, object: HashMap<String, String>) {
        let json_obj: serde_json::Map<String, serde_json::Value> = object
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        self.data
            .insert(key.to_string(), serde_json::Value::Object(json_obj));
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self.data).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn print(&self) {
        println!("{}", self.to_string());
    }
}

impl Default for JsonOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// CSV output builder
pub struct CsvOutput {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl CsvOutput {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            headers,
            rows: Vec::new(),
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    pub fn to_string(&self) -> String {
        let mut output = String::new();

        // Headers
        output.push_str(&self.headers.join(","));
        output.push('\n');

        // Rows
        for row in &self.rows {
            let escaped_row: Vec<String> = row
                .iter()
                .map(|cell| {
                    if cell.contains(',') || cell.contains('"') || cell.contains('\n') {
                        format!("\"{}\"", cell.replace('"', "\"\""))
                    } else {
                        cell.clone()
                    }
                })
                .collect();
            output.push_str(&escaped_row.join(","));
            output.push('\n');
        }

        output
    }

    pub fn print(&self) {
        print!("{}", self.to_string());
    }
}

// Simple JSON serialization helpers (zero-dependency)
pub mod serde_json {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub enum Value {
        String(String),
        Number(usize),
        Bool(bool),
        Array(Vec<Value>),
        Object(Map<String, Value>),
        Null,
    }

    pub type Map<K, V> = HashMap<K, V>;

    impl Value {
        fn to_json_string(&self) -> String {
            match self {
                Value::String(s) => format!("\"{}\"", escape_json_string(s)),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Array(arr) => {
                    let items: Vec<String> = arr.iter().map(|v| v.to_json_string()).collect();
                    format!("[{}]", items.join(","))
                }
                Value::Object(obj) => {
                    let items: Vec<String> = obj
                        .iter()
                        .map(|(k, v)| {
                            format!("\"{}\":{}", escape_json_string(k), v.to_json_string())
                        })
                        .collect();
                    format!("{{{}}}", items.join(","))
                }
                Value::Null => "null".to_string(),
            }
        }
    }

    fn escape_json_string(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    pub fn to_string_pretty(data: &HashMap<String, Value>) -> Result<String, String> {
        let mut result = String::from("{\n");
        let len = data.len();

        for (i, (key, value)) in data.iter().enumerate() {
            result.push_str(&format!(
                "  \"{}\": {}",
                escape_json_string(key),
                value.to_json_string()
            ));
            if i < len - 1 {
                result.push(',');
            }
            result.push('\n');
        }

        result.push('}');
        Ok(result)
    }
}

/// Simple JSON/YAML formatters using only println! (zero dependencies)
pub mod simple {
    /// Escape a string for JSON output
    pub fn escape_json(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    /// Print JSON object start
    pub fn json_start() {
        println!("{{");
    }

    /// Print JSON object end
    pub fn json_end() {
        println!("}}");
    }

    /// Print a JSON field (string)
    pub fn json_field_str(key: &str, value: &str, trailing_comma: bool) {
        let comma = if trailing_comma { "," } else { "" };
        println!("  \"{}\": \"{}\"{}", key, escape_json(value), comma);
    }

    /// Print a JSON field (number)
    pub fn json_field_num(key: &str, value: impl std::fmt::Display, trailing_comma: bool) {
        let comma = if trailing_comma { "," } else { "" };
        println!("  \"{}\": {}{}", key, value, comma);
    }

    /// Print a JSON field (boolean)
    pub fn json_field_bool(key: &str, value: bool, trailing_comma: bool) {
        let comma = if trailing_comma { "," } else { "" };
        println!("  \"{}\": {}{}", key, value, comma);
    }

    /// Print a JSON field (null)
    pub fn json_field_null(key: &str, trailing_comma: bool) {
        let comma = if trailing_comma { "," } else { "" };
        println!("  \"{}\": null{}", key, comma);
    }

    /// Print JSON array start
    pub fn json_array_start(key: &str) {
        println!("  \"{}\": [", key);
    }

    /// Print JSON array end
    pub fn json_array_end(trailing_comma: bool) {
        let comma = if trailing_comma { "," } else { "" };
        println!("  ]{}", comma);
    }

    /// Print YAML field (string)
    pub fn yaml_field_str(key: &str, value: &str, indent: usize) {
        let spaces = "  ".repeat(indent);
        println!("{}{}: {}", spaces, key, value);
    }

    /// Print YAML field (number)
    pub fn yaml_field_num(key: &str, value: impl std::fmt::Display, indent: usize) {
        let spaces = "  ".repeat(indent);
        println!("{}{}: {}", spaces, key, value);
    }

    /// Print YAML array item
    pub fn yaml_array_item(value: &str, indent: usize) {
        let spaces = "  ".repeat(indent);
        println!("{}  - {}", spaces, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_output() {
        let mut json = JsonOutput::new();
        json.add_string("name", "test".to_string());
        json.add_number("count", 42);
        json.add_bool("active", true);

        let output = json.to_string();
        assert!(output.contains("name"));
        assert!(output.contains("test"));
    }

    #[test]
    fn test_csv_output() {
        let mut csv = CsvOutput::new(vec!["Name".to_string(), "Age".to_string()]);
        csv.add_row(vec!["Alice".to_string(), "30".to_string()]);
        csv.add_row(vec!["Bob".to_string(), "25".to_string()]);

        let output = csv.to_string();
        assert!(output.contains("Name,Age"));
        assert!(output.contains("Alice,30"));
    }

    #[test]
    fn test_csv_escaping() {
        let mut csv = CsvOutput::new(vec!["Field".to_string()]);
        csv.add_row(vec!["Value with, comma".to_string()]);

        let output = csv.to_string();
        assert!(output.contains("\"Value with, comma\""));
    }

    #[test]
    fn test_simple_json_escape() {
        let result = simple::escape_json("test\"value\nline2");
        assert_eq!(result, "test\\\"value\\nline2");
    }
}
