//! JSON-RPC protocol handling for MCP server

use crate::mcp::types::ToolField;
use crate::utils::json::JsonValue;
use std::io::{self, BufRead, Write};

/// Read a JSON-RPC payload from a reader
pub fn read_payload<R: BufRead>(reader: &mut R) -> Result<Option<String>, String> {
    let mut content_length: Option<usize> = None;
    let mut header = String::new();

    loop {
        header.clear();
        let bytes = reader
            .read_line(&mut header)
            .map_err(|e| format!("failed to read header: {}", e))?;
        if bytes == 0 {
            return Ok(None);
        }

        let trimmed = header.trim_end_matches(|c| matches!(c, '\n' | '\r'));
        if trimmed.is_empty() {
            break;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let value = trimmed["Content-Length:".len()..].trim();
            let length = value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length header".to_string())?;
            content_length = Some(length);
        }
    }

    let length = content_length.ok_or_else(|| "missing Content-Length header".to_string())?;
    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .map_err(|e| format!("failed to read payload: {}", e))?;

    let to_consume = match reader.fill_buf() {
        Ok(buf) => {
            if buf.starts_with(b"\r\n") {
                Some(2)
            } else if buf.starts_with(b"\n") {
                Some(1)
            } else {
                None
            }
        }
        Err(_) => None,
    };

    if let Some(count) = to_consume {
        reader.consume(count);
    }

    String::from_utf8(buffer)
        .map(Some)
        .map_err(|_| "payload is not UTF-8".to_string())
}

/// Write a JSON-RPC message to stdout
pub fn write_message(payload: JsonValue) -> Result<(), String> {
    let body = payload.to_json_string();
    let mut stdout = io::stdout().lock();
    write!(
        &mut stdout,
        "Content-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    )
    .map_err(|e| format!("failed to write response: {}", e))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush stdout: {}", e))
}

/// Build a JSON-RPC result message
pub fn build_result_message(id: Option<JsonValue>, result: JsonValue) -> JsonValue {
    let mut entries = Vec::new();
    entries.push(("jsonrpc".to_string(), JsonValue::String("2.0".to_string())));
    if let Some(identifier) = id {
        entries.push(("id".to_string(), identifier));
    } else {
        entries.push(("id".to_string(), JsonValue::Null));
    }
    entries.push(("result".to_string(), result));
    JsonValue::Object(entries)
}

/// Build a JSON-RPC error message
pub fn build_error_message(id: Option<JsonValue>, code: i64, message: &str) -> JsonValue {
    let mut entries = Vec::new();
    entries.push(("jsonrpc".to_string(), JsonValue::String("2.0".to_string())));
    if let Some(identifier) = id {
        entries.push(("id".to_string(), identifier));
    } else {
        entries.push(("id".to_string(), JsonValue::Null));
    }
    let error = JsonValue::object(vec![
        ("code".to_string(), JsonValue::Number(code as f64)),
        (
            "message".to_string(),
            JsonValue::String(message.to_string()),
        ),
    ]);
    entries.push(("error".to_string(), error));
    JsonValue::Object(entries)
}

/// Build JSON schema for tool input fields
pub fn build_input_schema(fields: &[ToolField]) -> JsonValue {
    let mut properties = Vec::new();
    let mut required = Vec::new();

    for field in fields {
        let mut descriptor = Vec::new();
        descriptor.push((
            "type".to_string(),
            JsonValue::String(field.field_type.to_string()),
        ));
        if !field.description.is_empty() {
            descriptor.push((
                "description".to_string(),
                JsonValue::String(field.description.to_string()),
            ));
        }
        properties.push((field.name.to_string(), JsonValue::Object(descriptor)));
        if field.required {
            required.push(JsonValue::String(field.name.to_string()));
        }
    }

    JsonValue::object(vec![
        ("type".to_string(), JsonValue::String("object".to_string())),
        ("properties".to_string(), JsonValue::Object(properties)),
        ("required".to_string(), JsonValue::Array(required)),
        ("additionalProperties".to_string(), JsonValue::Bool(false)),
    ])
}
