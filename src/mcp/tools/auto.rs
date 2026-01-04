//! Auto MCP Tools
//!
//! Autonomous reconnaissance and vulnerability scanning with LLM guidance.

use crate::mcp::orchestrator::StepResult;
use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register auto/orchestrator tools with the server
pub fn register_auto_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.auto.recon",
            description: "Start autonomous reconnaissance on a target.",
            fields: &[ToolField {
                name: "target",
                field_type: "string",
                description: "Target domain or IP to recon.",
                required: true,
            }],
            handler: tool_auto_recon,
        },
        ToolDefinition {
            name: "rb.auto.vulnscan",
            description: "Start autonomous vulnerability scan.",
            fields: &[ToolField {
                name: "target",
                field_type: "string",
                description: "Target to scan for vulnerabilities.",
                required: true,
            }],
            handler: tool_auto_vulnscan,
        },
        ToolDefinition {
            name: "rb.auto.step",
            description: "Execute one step of the autonomous operation.",
            fields: &[ToolField {
                name: "operation_id",
                field_type: "string",
                description: "Operation ID from auto.recon or auto.vulnscan.",
                required: true,
            }],
            handler: tool_auto_step,
        },
        ToolDefinition {
            name: "rb.auto.status",
            description: "Get status of an autonomous operation.",
            fields: &[ToolField {
                name: "operation_id",
                field_type: "string",
                description: "Operation ID to check.",
                required: true,
            }],
            handler: tool_auto_status,
        },
        ToolDefinition {
            name: "rb.auto.stop",
            description: "Stop an autonomous operation.",
            fields: &[ToolField {
                name: "operation_id",
                field_type: "string",
                description: "Operation ID to stop.",
                required: true,
            }],
            handler: tool_auto_stop,
        },
    ]
}

fn tool_auto_recon(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let op_id = server.orchestrator.start_recon(target);

    let text = format!("Started autonomous recon on {}", target);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("operation_id".to_string(), JsonValue::String(op_id)),
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "status".to_string(),
                JsonValue::String("started".to_string()),
            ),
        ]),
    })
}

fn tool_auto_vulnscan(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: target")?;

    let op_id = server.orchestrator.start_vuln_scan(target);

    let text = format!("Started autonomous vulnerability scan on {}", target);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("operation_id".to_string(), JsonValue::String(op_id)),
            ("target".to_string(), JsonValue::String(target.to_string())),
            (
                "status".to_string(),
                JsonValue::String("started".to_string()),
            ),
        ]),
    })
}

fn tool_auto_step(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let op_id = args
        .get("operation_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: operation_id")?;

    let step_result = server
        .orchestrator
        .step(op_id)
        .map_err(|e| format!("Step failed: {}", e))?;

    // Convert StepResult enum to structured response
    let (text, data) = match step_result {
        StepResult::Progress { message, findings } => {
            let text = format!("Progress: {}", message);
            let data = JsonValue::object(vec![
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
                (
                    "status".to_string(),
                    JsonValue::String("progress".to_string()),
                ),
                ("message".to_string(), JsonValue::String(message)),
                ("findings".to_string(), JsonValue::Number(findings as f64)),
                ("is_complete".to_string(), JsonValue::Bool(false)),
            ]);
            (text, data)
        }
        StepResult::NeedsGuidance { request } => {
            let text = "Operation needs LLM guidance".to_string();
            let data = JsonValue::object(vec![
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
                (
                    "status".to_string(),
                    JsonValue::String("needs_guidance".to_string()),
                ),
                (
                    "has_request".to_string(),
                    JsonValue::Bool(request.is_some()),
                ),
                ("is_complete".to_string(), JsonValue::Bool(false)),
            ]);
            (text, data)
        }
        StepResult::PausedForReview { reason } => {
            let text = format!("Paused for review: {}", reason);
            let data = JsonValue::object(vec![
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
                (
                    "status".to_string(),
                    JsonValue::String("paused_for_review".to_string()),
                ),
                ("reason".to_string(), JsonValue::String(reason)),
                ("is_complete".to_string(), JsonValue::Bool(false)),
            ]);
            (text, data)
        }
        StepResult::Paused => {
            let text = "Operation is paused".to_string();
            let data = JsonValue::object(vec![
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
                (
                    "status".to_string(),
                    JsonValue::String("paused".to_string()),
                ),
                ("is_complete".to_string(), JsonValue::Bool(false)),
            ]);
            (text, data)
        }
        StepResult::Completed { findings, actions } => {
            let text = format!(
                "Operation completed: {} findings, {} actions",
                findings, actions
            );
            let data = JsonValue::object(vec![
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
                (
                    "status".to_string(),
                    JsonValue::String("completed".to_string()),
                ),
                ("findings".to_string(), JsonValue::Number(findings as f64)),
                ("actions".to_string(), JsonValue::Number(actions as f64)),
                ("is_complete".to_string(), JsonValue::Bool(true)),
            ]);
            (text, data)
        }
    };

    Ok(ToolResult { text, data })
}

fn tool_auto_status(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let op_id = args
        .get("operation_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: operation_id")?;

    let status = server
        .orchestrator
        .get_status(op_id)
        .ok_or_else(|| format!("Operation not found: {}", op_id))?;

    let text = format!(
        "Operation {}: {} (iteration {}/{})",
        op_id, status.state, status.iteration, status.max_iterations
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "operation_id".to_string(),
                JsonValue::String(op_id.to_string()),
            ),
            ("state".to_string(), JsonValue::String(status.state)),
            (
                "iteration".to_string(),
                JsonValue::Number(status.iteration as f64),
            ),
            (
                "max_iterations".to_string(),
                JsonValue::Number(status.max_iterations as f64),
            ),
            (
                "findings".to_string(),
                JsonValue::Number(status.findings as f64),
            ),
            (
                "actions".to_string(),
                JsonValue::Number(status.actions as f64),
            ),
        ]),
    })
}

fn tool_auto_stop(server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let op_id = args
        .get("operation_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: operation_id")?;

    server
        .orchestrator
        .stop(op_id)
        .map_err(|e| format!("Failed to stop operation: {}", e))?;

    let text = format!("Stopped operation {}", op_id);

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "operation_id".to_string(),
                JsonValue::String(op_id.to_string()),
            ),
            (
                "status".to_string(),
                JsonValue::String("stopped".to_string()),
            ),
        ]),
    })
}
