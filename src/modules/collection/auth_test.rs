use crate::modules::collection::creds::{DefaultCredential, DefaultCreds, DEFAULTS};
use crate::modules::collection::login::LoginForm;
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse};
use std::collections::HashMap;

pub struct CredentialTester {
    client: HttpClient,
}

impl CredentialTester {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    /// Test default credentials against a found login form
    pub fn test_defaults(
        &mut self,
        target_url: &str,
        form: &LoginForm,
        app_hint: Option<&str>,
    ) -> Vec<&'static DefaultCredential> {
        let mut working = Vec::new();

        let creds_to_try = if let Some(app) = app_hint {
            DefaultCreds::find_for_app(app)
        } else {
            // Try common generic ones if no app hint?
            // Or just try top 5
            DEFAULTS.iter().take(5).collect()
        };

        for cred in creds_to_try {
            if self.try_login(target_url, form, cred) {
                working.push(cred);
                // Stop after finding one? Or find all?
                // Usually one is enough for proof.
                break;
            }
        }

        working
    }

    fn try_login(&mut self, base_url: &str, form: &LoginForm, cred: &DefaultCredential) -> bool {
        // Construct request
        let action_url = if form.action.is_empty() {
            base_url.to_string()
        } else {
            // Should resolve relative URL using our DOM utils, but we don't have access to Document here easily.
            // Assuming absolute or relative to base.
            // For now, simple append if starts with /
            if form.action.starts_with("http") {
                form.action.clone()
            } else if form.action.starts_with('/') {
                // Extract origin from base_url
                let origin = base_url.split('/').take(3).collect::<Vec<_>>().join("/");
                format!("{}{}", origin, form.action)
            } else {
                format!("{}/{}", base_url.trim_end_matches('/'), form.action)
            }
        };

        let mut body_params = HashMap::new();
        body_params.insert(form.user_field.clone(), cred.user.to_string());
        body_params.insert(form.pass_field.clone(), cred.pass.to_string());

        if let Some((name, val)) = &form.csrf_token {
            body_params.insert(name.clone(), val.clone());
        }

        let mut request = if form.method == "POST" {
            let body = Self::encode_form_data(&body_params);
            let mut req = HttpRequest::post(&action_url).with_body(body.into_bytes());
            req.headers.insert(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            );
            req
        } else {
            // GET
            let query = Self::encode_form_data(&body_params);
            let url = if action_url.contains('?') {
                format!("{}&{}", action_url, query)
            } else {
                format!("{}?{}", action_url, query)
            };
            HttpRequest::get(&url)
        };

        // Add User-Agent
        request
            .headers
            .insert("User-Agent".to_string(), "redblue/1.0".to_string());

        if let Ok(response) = self.client.send(&request) {
            return self.check_success(&response);
        }

        false
    }

    fn encode_form_data(params: &HashMap<String, String>) -> String {
        params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v)) // Should urlencode
            .collect::<Vec<_>>()
            .join("&")
    }

    fn check_success(&self, response: &HttpResponse) -> bool {
        // Heuristics for login success
        // 1. 3xx Redirect (often to dashboard)
        if response.status_code >= 300 && response.status_code < 400 {
            return true;
        }

        // 2. 200 OK but body size/content changed significantly?
        // Hard to tell without baseline.

        // 3. Check for failure keywords in body
        let body = String::from_utf8_lossy(&response.body).to_lowercase();
        if body.contains("invalid password")
            || body.contains("login failed")
            || body.contains("incorrect")
            || body.contains("bad credentials")
        {
            return false;
        }

        // If 200 and no failure text, maybe success?
        // False positives likely.
        // Better to rely on redirects or "Welcome" / "Logout" text.
        if body.contains("logout") || body.contains("sign out") || body.contains("dashboard") {
            return true;
        }

        false
    }
}
