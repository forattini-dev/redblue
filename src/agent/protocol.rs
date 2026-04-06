use crate::serde_json::{JsonDecode, JsonEncode, Map, Value};

pub const BEACON_MAGIC: u32 = 0x52424C55; // "RBLU"
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
  Beacon = 1,
  Response = 2,
  Command = 3,
  KeyExchange = 4,
}

#[derive(Debug, Clone)]
pub struct BeaconMessage {
  pub magic: u32,
  pub version: u8,
  pub msg_type: MessageType,
  pub flags: u16,
  pub session_id: u64,
  pub timestamp: u64,
  pub nonce: Option<[u8; 12]>,     // ChaCha20 Nonce
  pub dh_public: Option<[u8; 32]>, // Ratchet DH Public Key
  pub pn: Option<u32>,             // Ratchet Previous Chain Length
  pub n: Option<u32>,              // Ratchet Message Number
  pub payload: Vec<u8>,            // Encrypted payload
  pub tag: [u8; 16],               // Poly1305 auth tag
}

impl BeaconMessage {
  pub fn new(
    msg_type: MessageType,
    session_id: u64,
    nonce: Option<[u8; 12]>,
    dh_public: Option<[u8; 32]>,
    pn: Option<u32>,
    n: Option<u32>,
    payload: Vec<u8>,
    tag: [u8; 16],
  ) -> Self {
    Self {
      magic: BEACON_MAGIC,
      version: PROTOCOL_VERSION,
      msg_type,
      flags: 0,
      session_id,
      timestamp: std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs(),
      nonce,
      dh_public,
      pn,
      n,
      payload,
      tag,
    }
  }
}

// Internal command structure (inside the encrypted payload)
#[derive(Debug, Clone)]
pub struct AgentCommand {
  pub id: String,
  pub action: String,
  pub args: Vec<String>,
}

// Internal response structure (inside the encrypted payload)
#[derive(Debug, Clone)]
pub struct AgentResponse {
  pub command_id: String,
  pub success: bool,
  pub output: String,
  pub error: Option<String>,
}

impl MessageType {
  fn as_str(&self) -> &'static str {
    match self {
      MessageType::Beacon => "Beacon",
      MessageType::Response => "Response",
      MessageType::Command => "Command",
      MessageType::KeyExchange => "KeyExchange",
    }
  }

  fn from_str(value: &str) -> Option<Self> {
    match value {
      "Beacon" => Some(MessageType::Beacon),
      "Response" => Some(MessageType::Response),
      "Command" => Some(MessageType::Command),
      "KeyExchange" => Some(MessageType::KeyExchange),
      _ => None,
    }
  }
}

fn get_required<T: JsonDecode>(map: &Map<String, Value>, key: &str) -> Result<T, String> {
  map
    .get(key)
    .cloned()
    .ok_or_else(|| format!("Missing field '{}'", key))
    .and_then(T::from_json_value)
}

fn get_optional<T: JsonDecode>(map: &Map<String, Value>, key: &str) -> Result<Option<T>, String> {
  match map.get(key) {
    None | Some(Value::Null) => Ok(None),
    Some(value) => Ok(Some(T::from_json_value(value.clone())?)),
  }
}

impl JsonEncode for MessageType {
  fn to_json_value(&self) -> Value {
    Value::String(self.as_str().to_string())
  }
}

impl JsonDecode for MessageType {
  fn from_json_value(value: Value) -> Result<Self, String> {
    match value {
      Value::String(s) => {
        MessageType::from_str(&s).ok_or_else(|| "Invalid message type".to_string())
      }
      Value::Number(n) => match n as u8 {
        1 => Ok(MessageType::Beacon),
        2 => Ok(MessageType::Response),
        3 => Ok(MessageType::Command),
        4 => Ok(MessageType::KeyExchange),
        _ => Err("Invalid message type".to_string()),
      },
      _ => Err("Expected message type string".to_string()),
    }
  }
}

impl JsonEncode for BeaconMessage {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("magic".to_string(), self.magic.to_json_value());
    map.insert("version".to_string(), self.version.to_json_value());
    map.insert("msg_type".to_string(), self.msg_type.to_json_value());
    map.insert("flags".to_string(), self.flags.to_json_value());
    map.insert("session_id".to_string(), self.session_id.to_json_value());
    map.insert("timestamp".to_string(), self.timestamp.to_json_value());
    map.insert("nonce".to_string(), self.nonce.to_json_value());
    map.insert("dh_public".to_string(), self.dh_public.to_json_value());
    map.insert("pn".to_string(), self.pn.to_json_value());
    map.insert("n".to_string(), self.n.to_json_value());
    map.insert("payload".to_string(), self.payload.to_json_value());
    map.insert("tag".to_string(), self.tag.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for BeaconMessage {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("Expected object".to_string()),
    };

    Ok(Self {
      magic: get_required(&map, "magic")?,
      version: get_required(&map, "version")?,
      msg_type: get_required(&map, "msg_type")?,
      flags: get_required(&map, "flags")?,
      session_id: get_required(&map, "session_id")?,
      timestamp: get_required(&map, "timestamp")?,
      nonce: get_optional(&map, "nonce")?,
      dh_public: get_optional(&map, "dh_public")?,
      pn: get_optional(&map, "pn")?,
      n: get_optional(&map, "n")?,
      payload: get_required(&map, "payload")?,
      tag: get_required(&map, "tag")?,
    })
  }
}

impl JsonEncode for AgentCommand {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("id".to_string(), self.id.to_json_value());
    map.insert("action".to_string(), self.action.to_json_value());
    map.insert("args".to_string(), self.args.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for AgentCommand {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("Expected object".to_string()),
    };

    Ok(Self {
      id: get_required(&map, "id")?,
      action: get_required(&map, "action")?,
      args: get_required(&map, "args")?,
    })
  }
}

impl JsonEncode for AgentResponse {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("command_id".to_string(), self.command_id.to_json_value());
    map.insert("success".to_string(), self.success.to_json_value());
    map.insert("output".to_string(), self.output.to_json_value());
    map.insert("error".to_string(), self.error.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for AgentResponse {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("Expected object".to_string()),
    };

    Ok(Self {
      command_id: get_required(&map, "command_id")?,
      success: get_required(&map, "success")?,
      output: get_required(&map, "output")?,
      error: get_optional(&map, "error")?,
    })
  }
}
