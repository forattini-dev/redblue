use serde::Serialize;

#[derive(Serialize)]
pub struct Bundle {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub objects: Vec<Object>,
}

impl Bundle {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            type_: "bundle".to_string(),
            id: id.into(),
            objects: Vec::new(),
        }
    }

    pub fn add_object(&mut self, object: Object) {
        self.objects.push(object);
    }
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum Object {
    #[serde(rename = "indicator")]
    Indicator(Indicator),
    #[serde(rename = "identity")]
    Identity(Identity),
}

#[derive(Serialize)]
pub struct Identity {
    pub spec_version: String,
    pub id: String,
    pub created: String,
    pub modified: String,
    pub name: String,
    pub identity_class: String,
}

#[derive(Serialize)]
pub struct Indicator {
    pub spec_version: String,
    pub id: String,
    pub created: String,
    pub modified: String,
    pub name: String,
    pub description: Option<String>,
    pub indicator_types: Vec<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub labels: Vec<String>,
    pub confidence: u8,
}
