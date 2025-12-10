use crate::modules::web::dom::{Document, Element};

#[derive(Debug, Clone)]
pub struct LoginForm {
    pub action: String,
    pub method: String,
    pub user_field: String,
    pub pass_field: String,
    pub csrf_token: Option<(String, String)>, // name, value
}

pub struct LoginDetector;

impl LoginDetector {
    /// Detects login forms in a document
    pub fn detect(doc: &Document) -> Vec<LoginForm> {
        let mut forms = Vec::new();
        
        // Find all forms
        for elem in doc.get_elements_by_tag("form") {
            if let Some(form) = Self::analyze_form(doc, elem) {
                forms.push(form);
            }
        }
        
        forms
    }
    
    fn analyze_form(doc: &Document, form: &Element) -> Option<LoginForm> {
        // Must have a password field
        let mut user_field = None;
        let mut pass_field = None;
        let mut csrf_token = None;
        
        // Traverse children to find inputs
        // Note: DOM structure might be nested. Need deep traversal or query selector.
        // Our Document has `get_elements_by_tag` but that's global.
        // We need inputs *inside* this form.
        // We can use the element indices.
        
        let inputs = Self::find_inputs_in_form(doc, form);
        
        for input in inputs {
            let type_attr = input.attr("type").map(|s| s.as_str()).unwrap_or("text");
            let name_attr = input.attr("name").map(|s| s.as_str()).unwrap_or("");
            
            if name_attr.is_empty() { continue; }
            
            match type_attr {
                "password" => {
                    pass_field = Some(name_attr.to_string());
                }
                "text" | "email" => {
                    // Heuristics for user field
                    let lower = name_attr.to_lowercase();
                    if lower.contains("user") || lower.contains("email") || lower.contains("login") || lower.contains("id") {
                        if user_field.is_none() {
                            user_field = Some(name_attr.to_string());
                        }
                    }
                }
                "hidden" => {
                    // Heuristics for CSRF
                    let lower = name_attr.to_lowercase();
                    if lower.contains("csrf") || lower.contains("token") || lower.contains("nonce") {
                        let value = input.attr("value").cloned().unwrap_or_default();
                        csrf_token = Some((name_attr.to_string(), value));
                    }
                }
                _ => {}
            }
        }
        
        // If we found a password field but no obvious user field, pick the first visible text field found before it?
        // For now, if we have a password field, we assume it's a login form (or password change).
        // If we lack a user field, it might be a lock screen.
        
        if let Some(pass) = pass_field {
            // Default user field if not found but we have password?
            // Some forms use 'username' or 'email'.
            let user = user_field.unwrap_or_else(|| "username".to_string());
            
            let action = form.attr("action").cloned().unwrap_or_default();
            let method = form.attr("method").cloned().unwrap_or_else(|| "GET".to_string());
            
            return Some(LoginForm {
                action,
                method: method.to_uppercase(),
                user_field: user,
                pass_field: pass,
                csrf_token,
            });
        }
        
        None
    }
    
    fn find_inputs_in_form<'a>(doc: &'a Document, form: &Element) -> Vec<&'a Element> {
        let mut inputs = Vec::new();
        Self::collect_inputs(doc, form, &mut inputs);
        inputs
    }
    
    fn collect_inputs<'a>(doc: &'a Document, elem: &Element, inputs: &mut Vec<&'a Element>) {
        for child in &elem.children {
            if let Some(idx) = child.as_element_ref() {
                if let Some(child_elem) = doc.get_element(idx) {
                    if child_elem.tag == "input" {
                        inputs.push(child_elem);
                    }
                    // Recurse
                    Self::collect_inputs(doc, child_elem, inputs);
                }
            }
        }
    }
}
