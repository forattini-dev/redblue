use crate::utils::json::JsonValue;

pub struct SarifFormatter;

impl SarifFormatter {
    pub fn format(findings: &[crate::modules::recon::secrets::SecretFinding]) -> String {
        let mut results = Vec::new();

        for finding in findings {
            let mut properties = Vec::new();
            properties.push((
                "severity".to_string(),
                JsonValue::String(finding.severity.to_string()),
            ));
            properties.push((
                "secret_type".to_string(),
                JsonValue::String(finding.secret_type.clone()),
            ));

            let location = if let Some(line) = finding.line {
                JsonValue::Object(vec![(
                    "physicalLocation".to_string(),
                    JsonValue::Object(vec![(
                        "region".to_string(),
                        JsonValue::Object(vec![(
                            "startLine".to_string(),
                            JsonValue::Number(line as f64),
                        )]),
                    )]),
                )])
            } else {
                JsonValue::Null
            };

            let result_obj = JsonValue::Object(vec![
                (
                    "ruleId".to_string(),
                    JsonValue::String(finding.pattern_name.clone()),
                ),
                (
                    "message".to_string(),
                    JsonValue::Object(vec![(
                        "text".to_string(),
                        JsonValue::String(format!("Found secret: {}", finding.secret_type)),
                    )]),
                ),
                ("locations".to_string(), JsonValue::Array(vec![location])),
                ("properties".to_string(), JsonValue::Object(properties)),
            ]);

            results.push(result_obj);
        }

        let run = JsonValue::Object(vec![
            (
                "tool".to_string(),
                JsonValue::Object(vec![(
                    "driver".to_string(),
                    JsonValue::Object(vec![
                        ("name".to_string(), JsonValue::String("redblue".to_string())),
                        (
                            "version".to_string(),
                            JsonValue::String("0.1.0".to_string()),
                        ),
                    ]),
                )]),
            ),
            ("results".to_string(), JsonValue::Array(results)),
        ]);

        let sarif = JsonValue::Object(vec![
            (
                "version".to_string(),
                JsonValue::String("2.1.0".to_string()),
            ),
            (
                "$schema".to_string(),
                JsonValue::String(
                    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
                        .to_string(),
                ),
            ),
            ("runs".to_string(), JsonValue::Array(vec![run])),
        ]);

        sarif.to_json_string()
    }
}
