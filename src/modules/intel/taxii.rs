use crate::serde_json::{JsonDecode, Value};

use crate::protocols::http::{HttpClient, HttpRequest};

const DEFAULT_TAXII_URL: &str = "https://cti-taxii.mitre.org/taxii/";

#[derive(Debug)]
pub struct TaxiiClient {
    base_url: String,
    client: HttpClient,
    api_root: String,
}

impl Default for TaxiiClient {
    fn default() -> Self {
        Self::new(DEFAULT_TAXII_URL)
    }
}

impl TaxiiClient {
    pub fn new(base_url: &str) -> Self {
        let client = HttpClient::new();
        // Discovery is usually at /taxii/, but api roots are separate.
        // MITRE ATT&CK is at /taxii/ (discovery) -> "enterprise-attack" api root.
        // For now, we assume standard MITRE setup or allow config.
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            api_root: "enterprise-attack".to_string(), // Default to enterprise
        }
    }

    pub fn with_api_root(mut self, root: &str) -> Self {
        self.api_root = root.to_string();
        self
    }

    fn build_url(&self, path: &str) -> String {
        format!(
            "{}/{}/{}",
            self.base_url,
            self.api_root,
            path.trim_start_matches('/')
        )
    }

    pub fn list_collections(&self) -> Result<Vec<Collection>, String> {
        let url = self.build_url("collections/");
        let request =
            HttpRequest::get(&url).with_header("Accept", "application/taxii+json;version=2.1");

        let response = self.client.send(&request)?;

        if !response.is_success() {
            return Err(format!(
                "TAXII request failed: {} {}",
                response.status_code, response.status_text
            ));
        }

        let body = response.body_as_string();
        let collections_resp: CollectionsResponse = crate::serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse collections: {}", e))?;

        Ok(collections_resp.collections)
    }

    pub fn get_objects(
        &self,
        collection_id: &str,
        object_type: Option<&str>,
        added_after: Option<&str>,
    ) -> Result<Envelope, String> {
        let mut url = self.build_url(&format!("collections/{}/objects/", collection_id));

        // Add query params
        let mut params = Vec::new();
        if let Some(t) = object_type {
            params.push(format!("match[type]={}", t));
        }
        if let Some(da) = added_after {
            params.push(format!("added_after={}", da));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let request =
            HttpRequest::get(&url).with_header("Accept", "application/taxii+json;version=2.1");

        let response = self.client.send(&request)?;

        if !response.is_success() {
            return Err(format!(
                "TAXII request failed: {} {}",
                response.status_code, response.status_text
            ));
        }

        let body = response.body_as_string();
        let envelope: Envelope = crate::serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse envelope: {}", e))?;

        Ok(envelope)
    }
}

// TAXII Data Models

#[derive(Debug)]
pub struct CollectionsResponse {
    pub collections: Vec<Collection>,
}

#[derive(Debug)]
pub struct Collection {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct Envelope {
    pub more: Option<bool>,
    pub next: Option<String>,
    pub objects: Option<Vec<Value>>, // Raw STIX objects
}

impl JsonDecode for CollectionsResponse {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        let collections = Vec::<Collection>::from_json_value(
            map.get("collections").cloned().unwrap_or(Value::Null),
        )?;
        Ok(Self { collections })
    }
}

impl JsonDecode for Collection {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            id: String::from_json_value(map.get("id").cloned().unwrap_or(Value::Null))?,
            title: String::from_json_value(map.get("title").cloned().unwrap_or(Value::Null))?,
            description: Option::<String>::from_json_value(
                map.get("description").cloned().unwrap_or(Value::Null),
            )?,
            can_read: bool::from_json_value(map.get("can_read").cloned().unwrap_or(Value::Null))?,
            can_write: bool::from_json_value(map.get("can_write").cloned().unwrap_or(Value::Null))?,
            media_types: Option::<Vec<String>>::from_json_value(
                map.get("media_types").cloned().unwrap_or(Value::Null),
            )?,
        })
    }
}

impl JsonDecode for Envelope {
    fn from_json_value(value: Value) -> Result<Self, String> {
        let map = match value {
            Value::Object(map) => map,
            _ => return Err("expected object".to_string()),
        };
        Ok(Self {
            more: Option::<bool>::from_json_value(map.get("more").cloned().unwrap_or(Value::Null))?,
            next: Option::<String>::from_json_value(
                map.get("next").cloned().unwrap_or(Value::Null),
            )?,
            objects: Option::<Vec<Value>>::from_json_value(
                map.get("objects").cloned().unwrap_or(Value::Null),
            )?,
        })
    }
}
