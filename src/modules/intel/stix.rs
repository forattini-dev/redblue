use crate::serde_json::{JsonEncode, Map, Value};

#[derive(Debug, Clone)]
pub struct Bundle {
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

#[derive(Debug, Clone)]
pub enum Object {
    Indicator(Indicator),
    Identity(Identity),
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub spec_version: String,
    pub id: String,
    pub created: String,
    pub modified: String,
    pub name: String,
    pub identity_class: String,
}

#[derive(Debug, Clone)]
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

impl JsonEncode for Bundle {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("type".to_string(), self.type_.to_json_value());
        map.insert("id".to_string(), self.id.to_json_value());
        map.insert("objects".to_string(), self.objects.to_json_value());
        Value::Object(map)
    }
}

impl JsonEncode for Object {
    fn to_json_value(&self) -> Value {
        match self {
            Object::Indicator(indicator) => {
                let mut map = match indicator.to_json_value() {
                    Value::Object(map) => map,
                    _ => Map::new(),
                };
                map.insert("type".to_string(), "indicator".to_json_value());
                Value::Object(map)
            }
            Object::Identity(identity) => {
                let mut map = match identity.to_json_value() {
                    Value::Object(map) => map,
                    _ => Map::new(),
                };
                map.insert("type".to_string(), "identity".to_json_value());
                Value::Object(map)
            }
        }
    }
}

impl JsonEncode for Identity {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "spec_version".to_string(),
            self.spec_version.to_json_value(),
        );
        map.insert("id".to_string(), self.id.to_json_value());
        map.insert("created".to_string(), self.created.to_json_value());
        map.insert("modified".to_string(), self.modified.to_json_value());
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert(
            "identity_class".to_string(),
            self.identity_class.to_json_value(),
        );
        Value::Object(map)
    }
}

impl JsonEncode for Indicator {
    fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "spec_version".to_string(),
            self.spec_version.to_json_value(),
        );
        map.insert("id".to_string(), self.id.to_json_value());
        map.insert("created".to_string(), self.created.to_json_value());
        map.insert("modified".to_string(), self.modified.to_json_value());
        map.insert("name".to_string(), self.name.to_json_value());
        map.insert("description".to_string(), self.description.to_json_value());
        map.insert(
            "indicator_types".to_string(),
            self.indicator_types.to_json_value(),
        );
        map.insert("pattern".to_string(), self.pattern.to_json_value());
        map.insert(
            "pattern_type".to_string(),
            self.pattern_type.to_json_value(),
        );
        map.insert("valid_from".to_string(), self.valid_from.to_json_value());
        map.insert("labels".to_string(), self.labels.to_json_value());
        map.insert("confidence".to_string(), self.confidence.to_json_value());
        Value::Object(map)
    }
}
