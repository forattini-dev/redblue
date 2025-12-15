use crate::playbooks::PlaybookContext;
use chrono::Local;
use std::collections::HashMap;
use std::env;

/// Template engine for playbook variable substitution
pub struct TemplateEngine;

impl Default for TemplateEngine {
    fn default() -> Self {
        Self
    }
}

impl TemplateEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Render a string by substituting variables from the context
    /// Supports {{ variable }} syntax
    pub fn render(&self, template: &str, context: &PlaybookContext) -> String {
        let mut result = String::with_capacity(template.len());
        let mut chars = template.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '{' {
                if let Some(&next_c) = chars.peek() {
                    if next_c == '{' {
                        // Found '{{', parse variable
                        chars.next(); // Consume second '{'

                        let mut var_name = String::new();
                        let mut closed = false;

                        while let Some(vc) = chars.next() {
                            if vc == '}' {
                                if let Some(&next_vc) = chars.peek() {
                                    if next_vc == '}' {
                                        chars.next(); // Consume second '}'
                                        closed = true;
                                        break;
                                    }
                                }
                                var_name.push(vc);
                            } else {
                                var_name.push(vc);
                            }
                        }

                        if closed {
                            let var_name = var_name.trim();
                            // Substitute variable
                            if let Some(val) = self.lookup_variable(var_name, context) {
                                result.push_str(&val);
                            } else {
                                // Keep original if not found: {{ var }}
                                result.push_str("{{ ");
                                result.push_str(var_name);
                                result.push_str(" }}");
                            }
                            continue;
                        } else {
                            // Unclosed, treat as literal
                            result.push_str("{{");
                            result.push_str(&var_name);
                            continue;
                        }
                    }
                }
            }
            result.push(c);
        }
        result
    }

    fn lookup_variable(&self, var_name: &str, context: &PlaybookContext) -> Option<String> {
        // 1. Check user arguments
        if let Some(val) = context.args.get(var_name) {
            return Some(val.clone());
        }

        // 2. Check gathered data
        if let Some(val) = context.gathered_data.get(var_name) {
            return Some(val.clone());
        }

        // 3. Check built-in variables
        match var_name {
            "target" => Some(context.target.clone()),
            "session_id" => Some(context.session_id.clone()),
            "timestamp" => Some(Local::now().to_rfc3339()),
            s if s.starts_with("env:") => {
                let env_var = &s[4..];
                env::var(env_var).ok()
            }
            // Add more built-ins as needed
            _ => None,
        }
    }

    /// Render a list of strings
    pub fn render_list(&self, list: &[String], context: &PlaybookContext) -> Vec<String> {
        list.iter().map(|s| self.render(s, context)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_substitution() {
        let engine = TemplateEngine::new();
        let mut ctx = PlaybookContext::new("192.168.1.1");
        ctx.set_arg("port", "8080");
        ctx.store_data("username", "admin");

        assert_eq!(
            engine.render("Target is {{ target }}", &ctx),
            "Target is 192.168.1.1"
        );
        assert_eq!(engine.render("Port is {{ port }}", &ctx), "Port is 8080");
        assert_eq!(
            engine.render("User is {{ username }}", &ctx),
            "User is admin"
        );
        assert_eq!(
            engine.render("Unknown {{ foo }}", &ctx),
            "Unknown {{ foo }}"
        );
    }

    #[test]
    fn test_advanced_variables() {
        let engine = TemplateEngine::new();
        let ctx = PlaybookContext::new("127.0.0.1");

        // Test session_id
        let rendered_session = engine.render("Session: {{ session_id }}", &ctx);
        assert!(rendered_session.starts_with("Session: "));
        assert_ne!(rendered_session, "Session: {{ session_id }}");

        // Test timestamp
        let rendered_time = engine.render("Time: {{ timestamp }}", &ctx);
        assert!(rendered_time.starts_with("Time: 20")); // Assuming year 20xx

        // Test env var
        env::set_var("REDBLUE_TEST_VAR", "secret_value");
        assert_eq!(
            engine.render("Env: {{ env:REDBLUE_TEST_VAR }}", &ctx),
            "Env: secret_value"
        );

        // Test missing env var
        assert_eq!(
            engine.render("Missing: {{ env:NON_EXISTENT_VAR }}", &ctx),
            "Missing: {{ env:NON_EXISTENT_VAR }}"
        );
    }
}
