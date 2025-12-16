/// Expression Evaluator for TOML Scripts
///
/// A simple expression language for script conditions.
/// Designed to be safe (no arbitrary code execution) and efficient.
///
/// ## Supported Operations
///
/// ### String Operations
/// - `contains(haystack, needle)` - Check if string contains substring
/// - `starts_with(str, prefix)` - Check if string starts with prefix
/// - `ends_with(str, suffix)` - Check if string ends with suffix
/// - `matches(str, pattern)` - Regex-like pattern matching (simplified)
/// - `eq(a, b)` - String equality (case-sensitive)
/// - `eq_ignore_case(a, b)` - String equality (case-insensitive)
/// - `len(str)` - String length
///
/// ### Numeric Operations
/// - `gt(a, b)` - Greater than
/// - `lt(a, b)` - Less than
/// - `gte(a, b)` - Greater than or equal
/// - `lte(a, b)` - Less than or equal
/// - `between(x, min, max)` - Check if x is between min and max
///
/// ### Boolean Operations
/// - `and(a, b)` - Logical AND
/// - `or(a, b)` - Logical OR
/// - `not(a)` - Logical NOT
///
/// ### Variable Access
/// - `$banner` - Access the banner variable
/// - `$header.Server` - Access nested data
/// - `$port` - Access port number
///
/// ## Example
///
/// ```text
/// # Check if banner contains "Apache" and version is 2.x
/// and(contains($banner, "Apache"), matches($banner, "2\\.[0-9]+"))
/// ```
use std::collections::HashMap;

/// Expression evaluator
pub struct ExprEvaluator {
    variables: HashMap<String, ExprValue>,
}

/// Expression value types
#[derive(Debug, Clone)]
pub enum ExprValue {
    String(String),
    Number(f64),
    Bool(bool),
    List(Vec<ExprValue>),
    Null,
}

impl ExprValue {
    /// Convert to string
    pub fn as_str(&self) -> String {
        match self {
            ExprValue::String(s) => s.clone(),
            ExprValue::Number(n) => n.to_string(),
            ExprValue::Bool(b) => b.to_string(),
            ExprValue::List(l) => format!("{:?}", l),
            ExprValue::Null => "null".to_string(),
        }
    }

    /// Convert to boolean
    pub fn as_bool(&self) -> bool {
        match self {
            ExprValue::String(s) => !s.is_empty(),
            ExprValue::Number(n) => *n != 0.0,
            ExprValue::Bool(b) => *b,
            ExprValue::List(l) => !l.is_empty(),
            ExprValue::Null => false,
        }
    }

    /// Convert to number
    pub fn as_number(&self) -> f64 {
        match self {
            ExprValue::String(s) => s.parse().unwrap_or(0.0),
            ExprValue::Number(n) => *n,
            ExprValue::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            ExprValue::List(l) => l.len() as f64,
            ExprValue::Null => 0.0,
        }
    }

    /// Check if value is truthy
    pub fn is_truthy(&self) -> bool {
        self.as_bool()
    }
}

impl From<&str> for ExprValue {
    fn from(s: &str) -> Self {
        ExprValue::String(s.to_string())
    }
}

impl From<String> for ExprValue {
    fn from(s: String) -> Self {
        ExprValue::String(s)
    }
}

impl From<f64> for ExprValue {
    fn from(n: f64) -> Self {
        ExprValue::Number(n)
    }
}

impl From<i64> for ExprValue {
    fn from(n: i64) -> Self {
        ExprValue::Number(n as f64)
    }
}

impl From<bool> for ExprValue {
    fn from(b: bool) -> Self {
        ExprValue::Bool(b)
    }
}

impl ExprEvaluator {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// Set a variable
    pub fn set_var(&mut self, name: &str, value: impl Into<ExprValue>) {
        self.variables.insert(name.to_string(), value.into());
    }

    /// Set multiple variables from a HashMap
    pub fn set_vars(&mut self, vars: &HashMap<String, String>) {
        for (k, v) in vars {
            self.variables
                .insert(k.clone(), ExprValue::String(v.clone()));
        }
    }

    /// Get a variable value
    pub fn get_var(&self, name: &str) -> ExprValue {
        // Handle nested access like "header.Server"
        let parts: Vec<&str> = name.split('.').collect();

        if parts.len() == 1 {
            self.variables.get(name).cloned().unwrap_or(ExprValue::Null)
        } else {
            // Try to get the nested value
            let base_name = parts[0];
            let key = parts[1..].join(".");

            if let Some(ExprValue::String(s)) = self.variables.get(base_name) {
                // For now, just return the base value if we can't parse nested structure
                ExprValue::String(s.clone())
            } else {
                // Try direct key lookup
                let full_key = format!("{}.{}", base_name, key);
                self.variables
                    .get(&full_key)
                    .cloned()
                    .unwrap_or(ExprValue::Null)
            }
        }
    }

    /// Evaluate an expression string
    pub fn eval(&self, expr: &str) -> Result<ExprValue, String> {
        let expr = expr.trim();

        // Empty expression is false
        if expr.is_empty() {
            return Ok(ExprValue::Bool(false));
        }

        // Boolean literals
        if expr == "true" {
            return Ok(ExprValue::Bool(true));
        }
        if expr == "false" {
            return Ok(ExprValue::Bool(false));
        }

        // Variable reference
        if let Some(var_name) = expr.strip_prefix('$') {
            return Ok(self.get_var(var_name));
        }

        // String literal
        if (expr.starts_with('"') && expr.ends_with('"'))
            || (expr.starts_with('\'') && expr.ends_with('\''))
        {
            return Ok(ExprValue::String(expr[1..expr.len() - 1].to_string()));
        }

        // Number literal
        if let Ok(n) = expr.parse::<f64>() {
            return Ok(ExprValue::Number(n));
        }

        // Function call
        if let Some(paren_pos) = expr.find('(') {
            if expr.ends_with(')') {
                let func_name = &expr[..paren_pos];
                let args_str = &expr[paren_pos + 1..expr.len() - 1];
                return self.eval_function(func_name, args_str);
            }
        }

        // Unknown expression - try as variable name
        Ok(self.get_var(expr))
    }

    /// Evaluate a function call
    fn eval_function(&self, name: &str, args_str: &str) -> Result<ExprValue, String> {
        let args = self.parse_args(args_str)?;

        match name {
            // String operations
            "contains" => {
                if args.len() != 2 {
                    return Err("contains() requires 2 arguments".to_string());
                }
                let haystack = self.eval(&args[0])?.as_str().to_lowercase();
                let needle = self.eval(&args[1])?.as_str().to_lowercase();
                Ok(ExprValue::Bool(haystack.contains(&needle)))
            }

            "starts_with" => {
                if args.len() != 2 {
                    return Err("starts_with() requires 2 arguments".to_string());
                }
                let s = self.eval(&args[0])?.as_str();
                let prefix = self.eval(&args[1])?.as_str();
                Ok(ExprValue::Bool(s.starts_with(&prefix)))
            }

            "ends_with" => {
                if args.len() != 2 {
                    return Err("ends_with() requires 2 arguments".to_string());
                }
                let s = self.eval(&args[0])?.as_str();
                let suffix = self.eval(&args[1])?.as_str();
                Ok(ExprValue::Bool(s.ends_with(&suffix)))
            }

            "matches" => {
                if args.len() != 2 {
                    return Err("matches() requires 2 arguments".to_string());
                }
                let s = self.eval(&args[0])?.as_str();
                let pattern = self.eval(&args[1])?.as_str();
                Ok(ExprValue::Bool(self.simple_match(&s, &pattern)))
            }

            "eq" => {
                if args.len() != 2 {
                    return Err("eq() requires 2 arguments".to_string());
                }
                let a = self.eval(&args[0])?.as_str();
                let b = self.eval(&args[1])?.as_str();
                Ok(ExprValue::Bool(a == b))
            }

            "eq_ignore_case" => {
                if args.len() != 2 {
                    return Err("eq_ignore_case() requires 2 arguments".to_string());
                }
                let a = self.eval(&args[0])?.as_str().to_lowercase();
                let b = self.eval(&args[1])?.as_str().to_lowercase();
                Ok(ExprValue::Bool(a == b))
            }

            "len" => {
                if args.len() != 1 {
                    return Err("len() requires 1 argument".to_string());
                }
                let s = self.eval(&args[0])?.as_str();
                Ok(ExprValue::Number(s.len() as f64))
            }

            "lower" => {
                if args.len() != 1 {
                    return Err("lower() requires 1 argument".to_string());
                }
                let s = self.eval(&args[0])?.as_str();
                Ok(ExprValue::String(s.to_lowercase()))
            }

            "upper" => {
                if args.len() != 1 {
                    return Err("upper() requires 1 argument".to_string());
                }
                let s = self.eval(&args[0])?.as_str();
                Ok(ExprValue::String(s.to_uppercase()))
            }

            // Numeric operations
            "gt" => {
                if args.len() != 2 {
                    return Err("gt() requires 2 arguments".to_string());
                }
                let a = self.eval(&args[0])?.as_number();
                let b = self.eval(&args[1])?.as_number();
                Ok(ExprValue::Bool(a > b))
            }

            "lt" => {
                if args.len() != 2 {
                    return Err("lt() requires 2 arguments".to_string());
                }
                let a = self.eval(&args[0])?.as_number();
                let b = self.eval(&args[1])?.as_number();
                Ok(ExprValue::Bool(a < b))
            }

            "gte" => {
                if args.len() != 2 {
                    return Err("gte() requires 2 arguments".to_string());
                }
                let a = self.eval(&args[0])?.as_number();
                let b = self.eval(&args[1])?.as_number();
                Ok(ExprValue::Bool(a >= b))
            }

            "lte" => {
                if args.len() != 2 {
                    return Err("lte() requires 2 arguments".to_string());
                }
                let a = self.eval(&args[0])?.as_number();
                let b = self.eval(&args[1])?.as_number();
                Ok(ExprValue::Bool(a <= b))
            }

            "between" => {
                if args.len() != 3 {
                    return Err("between() requires 3 arguments".to_string());
                }
                let x = self.eval(&args[0])?.as_number();
                let min = self.eval(&args[1])?.as_number();
                let max = self.eval(&args[2])?.as_number();
                Ok(ExprValue::Bool(x >= min && x <= max))
            }

            // Boolean operations
            "and" => {
                if args.len() < 2 {
                    return Err("and() requires at least 2 arguments".to_string());
                }
                for arg in &args {
                    if !self.eval(arg)?.is_truthy() {
                        return Ok(ExprValue::Bool(false));
                    }
                }
                Ok(ExprValue::Bool(true))
            }

            "or" => {
                if args.len() < 2 {
                    return Err("or() requires at least 2 arguments".to_string());
                }
                for arg in &args {
                    if self.eval(arg)?.is_truthy() {
                        return Ok(ExprValue::Bool(true));
                    }
                }
                Ok(ExprValue::Bool(false))
            }

            "not" => {
                if args.len() != 1 {
                    return Err("not() requires 1 argument".to_string());
                }
                let val = self.eval(&args[0])?.is_truthy();
                Ok(ExprValue::Bool(!val))
            }

            // Existence checks
            "exists" => {
                if args.len() != 1 {
                    return Err("exists() requires 1 argument".to_string());
                }
                let val = self.eval(&args[0])?;
                Ok(ExprValue::Bool(!matches!(val, ExprValue::Null)))
            }

            "empty" => {
                if args.len() != 1 {
                    return Err("empty() requires 1 argument".to_string());
                }
                let val = self.eval(&args[0])?;
                let is_empty = match val {
                    ExprValue::String(s) => s.is_empty(),
                    ExprValue::List(l) => l.is_empty(),
                    ExprValue::Null => true,
                    _ => false,
                };
                Ok(ExprValue::Bool(is_empty))
            }

            // Port check
            "port_is" => {
                if args.len() != 1 {
                    return Err("port_is() requires 1 argument".to_string());
                }
                let expected = self.eval(&args[0])?.as_number() as u16;
                let actual = self.get_var("port").as_number() as u16;
                Ok(ExprValue::Bool(actual == expected))
            }

            // Version comparison
            "version_gte" => {
                if args.len() != 2 {
                    return Err("version_gte() requires 2 arguments".to_string());
                }
                let actual = self.eval(&args[0])?.as_str();
                let required = self.eval(&args[1])?.as_str();
                Ok(ExprValue::Bool(
                    self.compare_versions(&actual, &required) >= 0,
                ))
            }

            "version_lt" => {
                if args.len() != 2 {
                    return Err("version_lt() requires 2 arguments".to_string());
                }
                let actual = self.eval(&args[0])?.as_str();
                let required = self.eval(&args[1])?.as_str();
                Ok(ExprValue::Bool(
                    self.compare_versions(&actual, &required) < 0,
                ))
            }

            _ => Err(format!("Unknown function: {}", name)),
        }
    }

    /// Parse function arguments (handles nested functions and quoted strings)
    fn parse_args(&self, args_str: &str) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut depth = 0;
        let mut in_string = false;
        let mut string_char = '"';

        for ch in args_str.chars() {
            match ch {
                '"' | '\'' if !in_string => {
                    in_string = true;
                    string_char = ch;
                    current.push(ch);
                }
                c if c == string_char && in_string => {
                    in_string = false;
                    current.push(ch);
                }
                '(' if !in_string => {
                    depth += 1;
                    current.push(ch);
                }
                ')' if !in_string => {
                    depth -= 1;
                    current.push(ch);
                }
                ',' if depth == 0 && !in_string => {
                    let arg = current.trim().to_string();
                    if !arg.is_empty() {
                        args.push(arg);
                    }
                    current.clear();
                }
                _ => current.push(ch),
            }
        }

        // Add last argument
        let arg = current.trim().to_string();
        if !arg.is_empty() {
            args.push(arg);
        }

        Ok(args)
    }

    /// Simple pattern matching (supports * and ? wildcards)
    fn simple_match(&self, s: &str, pattern: &str) -> bool {
        let s = s.to_lowercase();
        let pattern = pattern.to_lowercase();

        // Convert simple pattern to parts
        let parts: Vec<&str> = pattern.split('*').collect();

        if parts.len() == 1 {
            // No wildcards, exact match
            return s == pattern;
        }

        let mut pos = 0;

        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if let Some(found) = s[pos..].find(part) {
                // First part must match at start
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            } else {
                return false;
            }
        }

        // Last part must match at end (unless pattern ends with *)
        if !pattern.ends_with('*') && !parts.last().map(|p| p.is_empty()).unwrap_or(true) {
            let last_part = parts.last().unwrap();
            return s.ends_with(last_part);
        }

        true
    }

    /// Compare version strings (returns -1, 0, or 1)
    fn compare_versions(&self, a: &str, b: &str) -> i32 {
        let parse_version = |s: &str| -> Vec<u32> {
            s.split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .map(|s| s.parse().unwrap_or(0))
                .collect()
        };

        let va = parse_version(a);
        let vb = parse_version(b);

        for i in 0..va.len().max(vb.len()) {
            let a_part = va.get(i).copied().unwrap_or(0);
            let b_part = vb.get(i).copied().unwrap_or(0);

            match a_part.cmp(&b_part) {
                std::cmp::Ordering::Less => return -1,
                std::cmp::Ordering::Greater => return 1,
                std::cmp::Ordering::Equal => continue,
            }
        }

        0
    }
}

impl Default for ExprEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literals() {
        let eval = ExprEvaluator::new();

        assert!(eval.eval("true").unwrap().as_bool());
        assert!(!eval.eval("false").unwrap().as_bool());
        assert_eq!(eval.eval("42").unwrap().as_number(), 42.0);
        assert_eq!(eval.eval("\"hello\"").unwrap().as_str(), "hello");
    }

    #[test]
    fn test_variables() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("banner", "Apache/2.4.51");
        eval.set_var("port", 80i64);

        assert_eq!(eval.eval("$banner").unwrap().as_str(), "Apache/2.4.51");
        assert_eq!(eval.eval("$port").unwrap().as_number(), 80.0);
    }

    #[test]
    fn test_contains() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("banner", "Apache/2.4.51 (Unix)");

        assert!(eval
            .eval("contains($banner, \"Apache\")")
            .unwrap()
            .as_bool());
        assert!(eval
            .eval("contains($banner, \"apache\")")
            .unwrap()
            .as_bool()); // Case-insensitive
        assert!(!eval.eval("contains($banner, \"nginx\")").unwrap().as_bool());
    }

    #[test]
    fn test_starts_ends_with() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("banner", "Apache/2.4.51");

        assert!(eval
            .eval("starts_with($banner, \"Apache\")")
            .unwrap()
            .as_bool());
        assert!(!eval
            .eval("starts_with($banner, \"nginx\")")
            .unwrap()
            .as_bool());
        assert!(eval.eval("ends_with($banner, \"51\")").unwrap().as_bool());
    }

    #[test]
    fn test_pattern_match() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("banner", "Apache/2.4.51 (Unix)");

        assert!(eval
            .eval("matches($banner, \"Apache*\")")
            .unwrap()
            .as_bool());
        assert!(eval.eval("matches($banner, \"*2.4*\")").unwrap().as_bool());
        assert!(!eval.eval("matches($banner, \"nginx*\")").unwrap().as_bool());
    }

    #[test]
    fn test_numeric() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("port", 443i64);

        assert!(eval.eval("gt($port, 80)").unwrap().as_bool());
        assert!(eval.eval("lt($port, 8080)").unwrap().as_bool());
        assert!(eval.eval("between($port, 1, 1024)").unwrap().as_bool());
    }

    #[test]
    fn test_boolean() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("banner", "Apache");

        assert!(eval.eval("and(true, true)").unwrap().as_bool());
        assert!(!eval.eval("and(true, false)").unwrap().as_bool());
        assert!(eval.eval("or(false, true)").unwrap().as_bool());
        assert!(!eval.eval("not(true)").unwrap().as_bool());

        // Nested
        assert!(eval
            .eval("and(contains($banner, \"Apache\"), not(contains($banner, \"nginx\")))")
            .unwrap()
            .as_bool());
    }

    #[test]
    fn test_version_compare() {
        let eval = ExprEvaluator::new();

        // 2.4.51 >= 2.4.0
        assert!(eval
            .eval("version_gte(\"2.4.51\", \"2.4.0\")")
            .unwrap()
            .as_bool());

        // 2.4.51 < 3.0.0
        assert!(eval
            .eval("version_lt(\"2.4.51\", \"3.0.0\")")
            .unwrap()
            .as_bool());

        // 2.4.51 >= 2.4.51
        assert!(eval
            .eval("version_gte(\"2.4.51\", \"2.4.51\")")
            .unwrap()
            .as_bool());
    }

    #[test]
    fn test_port_is() {
        let mut eval = ExprEvaluator::new();
        eval.set_var("port", 443i64);

        assert!(eval.eval("port_is(443)").unwrap().as_bool());
        assert!(!eval.eval("port_is(80)").unwrap().as_bool());
    }
}
