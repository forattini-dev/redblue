use std::collections::HashMap;

pub struct ServiceCategorizer;

impl ServiceCategorizer {
    pub fn categorize(html: &str, headers: &HashMap<String, String>) -> Vec<String> {
        let mut categories = Vec::new();
        let html_lower = html.to_lowercase();

        // Login detection
        if html_lower.contains("login")
            || html_lower.contains("sign in")
            || html_lower.contains("username")
            || html_lower.contains("password")
        {
            categories.push("Login Page".to_string());
        }

        // Admin panels
        if html_lower.contains("admin") || html_lower.contains("dashboard") {
            categories.push("Admin Panel".to_string());
        }

        // Error pages
        if html_lower.contains("404 not found") || html_lower.contains("page not found") {
            categories.push("Error Page".to_string());
        }

        // Directory listing
        if html_lower.contains("index of /") {
            categories.push("Directory Listing".to_string());
        }

        // Server headers
        if let Some(server) = headers.get("server").or_else(|| headers.get("Server")) {
            let s = server.to_lowercase();
            if s.contains("apache") {
                categories.push("Apache".to_string());
            }
            if s.contains("nginx") {
                categories.push("Nginx".to_string());
            }
            if s.contains("iis") {
                categories.push("IIS".to_string());
            }
            if s.contains("jetty") {
                categories.push("Jetty".to_string());
            }
            if s.contains("tomcat") {
                categories.push("Tomcat".to_string());
            }
        }

        // Technology signatures (simple text search)
        if html_lower.contains("wordpress") {
            categories.push("WordPress".to_string());
        }
        if html_lower.contains("drupal") {
            categories.push("Drupal".to_string());
        }
        if html_lower.contains("joomla") {
            categories.push("Joomla".to_string());
        }
        if html_lower.contains("django") {
            categories.push("Django".to_string());
        }
        if html_lower.contains("laravel") {
            categories.push("Laravel".to_string());
        }
        if html_lower.contains("react") {
            categories.push("React".to_string());
        }
        if html_lower.contains("vue") {
            categories.push("Vue.js".to_string());
        }
        if html_lower.contains("bootstrap") {
            categories.push("Bootstrap".to_string());
        }
        if html_lower.contains("jquery") {
            categories.push("jQuery".to_string());
        }

        categories.sort();
        categories.dedup();
        categories
    }
}
