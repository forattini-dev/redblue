#[cfg(test)]
mod tests {
    use redblue::modules::collection::categorization::ServiceCategorizer;
    use std::collections::HashMap;

    #[test]
    fn test_categorization() {
        let html = "<html><head><title>Login</title></head><body>Login to Dashboard</body></html>";
        let headers = HashMap::new();
        let cats = ServiceCategorizer::categorize(html, &headers);
        assert!(cats.contains(&"Login Page".to_string()));
    }

    // Note: Actual screenshot tests require a running Chrome instance or mock.
    // We will skip live browser tests here and focus on the logic we added.
}
