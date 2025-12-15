use serde::Deserialize;
use std::collections::HashMap;

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
        let collections_resp: CollectionsResponse = serde_json::from_str(&body)
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
        let envelope: Envelope =
            serde_json::from_str(&body).map_err(|e| format!("Failed to parse envelope: {}", e))?;

        Ok(envelope)
    }
}

// TAXII Data Models

#[derive(Debug, Deserialize)]
pub struct CollectionsResponse {
    pub collections: Vec<Collection>,
}

#[derive(Debug, Deserialize)]
pub struct Collection {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub more: Option<bool>,
    pub next: Option<String>,
    pub objects: Option<Vec<serde_json::Value>>, // Raw STIX objects
}
