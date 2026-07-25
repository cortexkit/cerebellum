//! Digest-pinned, canonical computer action vocabulary validation.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;

pub const COMPUTER_ACTION_VOCABULARY_SCHEMA_ID: &str = "ck-computer-action-vocabulary/v1";
pub const COMPUTER_ACTION_VOCABULARY_REVISION: &str = "computer_action_vocabulary-v1";
pub const COMPUTER_ACTION_VOCABULARY_ARTIFACT: &[u8] =
    include_bytes!("../../resources/computer_action_vocabulary-v1.json");
const IMPLEMENTATION_SOURCE_LOCK: &[u8] =
    include_bytes!("../../../cerebellum/resources/implementation-source-lock.json");

/// This is filled with the checked-in artifact digest after the resource is
/// frozen. Keeping the value in the source-lock, rather than another lock file,
/// makes the browser and computer artifacts share one release authority.
pub const COMPUTER_ACTION_VOCABULARY_SHA256: &str =
    "e450e91850eb00b0269a2a3e5307b7c976a10cfba4bbd4f1532b34d5c013f83c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VocabularyValidationError {
    Json(String),
    NonCanonicalJson,
    NonIntegerNumber(String),
    WrongSchemaId,
    WrongRevision,
    WrongTopLevelKeys,
    WrongRowCount(usize),
    WrongRowSet,
    WrongRowKeys(String),
    ClosedSchema(String),
    RowBinding(String),
    NumericInvariant(String),
    DigestMismatch { expected: String, actual: String },
    MissingManifestDigest,
    MissingSourceLockDigest,
    MissingComputedArtifactDigest,
    SourceLockInvalid,
}

impl fmt::Display for VocabularyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VocabularyValidationError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VocabularyDigestInputs {
    pub manifest_digest: Option<String>,
    pub source_lock_digest: Option<String>,
    pub computed_artifact_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedVocabulary {
    pub schema_id: String,
    pub revision: String,
    pub row_count: usize,
    pub sha256: String,
}

const ROW_IDS: [&str; 8] = [
    "computer.click",
    "computer.type",
    "computer.keys",
    "computer.scroll",
    "computer.move",
    "computer.drag",
    "computer.screenshot",
    "computer.wait",
];

/// RFC 8785 canonical bytes for the artifact. The artifact intentionally uses
/// only integer JSON numbers; floats, exponent notation, and negative zero are
/// rejected instead of relying on a platform's number formatter.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, VocabularyValidationError> {
    let mut output = Vec::new();
    write_canonical(value, &mut output, "$")?;
    Ok(output)
}

fn write_canonical(
    value: &Value,
    output: &mut Vec<u8>,
    path: &str,
) -> Result<(), VocabularyValidationError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(VocabularyValidationError::NonIntegerNumber(
                    path.to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| VocabularyValidationError::Json(error.to_string()))?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output, &format!("{path}[{index}]"))?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| {
                left.encode_utf16()
                    .cmp(right.encode_utf16())
                    .then(Ordering::Equal)
            });
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|error| VocabularyValidationError::Json(error.to_string()))?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical(value, output, &format!("{path}.{key}"))?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub fn computed_vocabulary_sha256() -> String {
    hex(&Sha256::digest(COMPUTER_ACTION_VOCABULARY_ARTIFACT))
}

pub fn implementation_source_lock_digest() -> Option<String> {
    serde_json::from_slice::<Value>(IMPLEMENTATION_SOURCE_LOCK)
        .ok()
        .and_then(|value| {
            value
                .get("computer_action_vocabulary_sha256")?
                .as_str()
                .map(str::to_owned)
        })
}

pub fn validate_vocabulary_digests(
    inputs: &VocabularyDigestInputs,
) -> Result<(), VocabularyValidationError> {
    let actual = computed_vocabulary_sha256();
    let Some(manifest) = inputs.manifest_digest.as_deref() else {
        return Err(VocabularyValidationError::MissingManifestDigest);
    };
    let Some(source) = inputs.source_lock_digest.as_deref() else {
        return Err(VocabularyValidationError::MissingSourceLockDigest);
    };
    let Some(computed) = inputs.computed_artifact_digest.as_deref() else {
        return Err(VocabularyValidationError::MissingComputedArtifactDigest);
    };
    if manifest != actual
        || computed != actual
        || implementation_source_lock_digest().as_deref() != Some(actual.as_str())
        || source != actual
    {
        return Err(VocabularyValidationError::DigestMismatch {
            expected: actual,
            actual: format!("manifest={manifest};source={source};computed={computed}"),
        });
    }
    Ok(())
}

pub fn validate_vocabulary() -> Result<ValidatedVocabulary, VocabularyValidationError> {
    validate_vocabulary_bytes(COMPUTER_ACTION_VOCABULARY_ARTIFACT)
}

pub fn validate_vocabulary_bytes(
    bytes: &[u8],
) -> Result<ValidatedVocabulary, VocabularyValidationError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| VocabularyValidationError::Json(error.to_string()))?;
    let canonical = canonical_json_bytes(&value)?;
    if canonical != bytes {
        return Err(VocabularyValidationError::NonCanonicalJson);
    }
    validate_value(&value)?;
    let object = value
        .as_object()
        .ok_or(VocabularyValidationError::WrongTopLevelKeys)?;
    Ok(ValidatedVocabulary {
        schema_id: object["schema_id"].as_str().unwrap().to_string(),
        revision: object["revision"].as_str().unwrap().to_string(),
        row_count: object["rows"].as_array().unwrap().len(),
        sha256: hex(&Sha256::digest(bytes)),
    })
}

fn validate_value(value: &Value) -> Result<(), VocabularyValidationError> {
    let object = value
        .as_object()
        .ok_or(VocabularyValidationError::WrongTopLevelKeys)?;
    if object.keys().map(String::as_str).collect::<Vec<_>>() != ["revision", "rows", "schema_id"] {
        return Err(VocabularyValidationError::WrongTopLevelKeys);
    }
    if object["schema_id"] != COMPUTER_ACTION_VOCABULARY_SCHEMA_ID {
        return Err(VocabularyValidationError::WrongSchemaId);
    }
    if object["revision"] != COMPUTER_ACTION_VOCABULARY_REVISION {
        return Err(VocabularyValidationError::WrongRevision);
    }
    let rows = object["rows"]
        .as_array()
        .ok_or(VocabularyValidationError::WrongRowSet)?;
    if rows.len() != 8 {
        return Err(VocabularyValidationError::WrongRowCount(rows.len()));
    }
    let ids: Vec<_> = rows
        .iter()
        .filter_map(|row| row.get("capability_id").and_then(Value::as_str))
        .collect();
    if ids != ROW_IDS {
        return Err(VocabularyValidationError::WrongRowSet);
    }
    for row in rows {
        validate_row(row)?;
    }
    Ok(())
}

fn validate_row(row: &Value) -> Result<(), VocabularyValidationError> {
    let object = row
        .as_object()
        .ok_or_else(|| VocabularyValidationError::WrongRowKeys("row is not an object".into()))?;
    let expected = [
        "action_kind",
        "action_kind_overrides",
        "attendance_requirement",
        "audit_obligation",
        "capability_id",
        "dispatch_modes",
        "effect_observation",
        "eligible_grounding_paths",
        "maximum_accessibility_tree_settle_interval_ms",
        "maximum_attendance_check_to_dispatch_interval_ms",
        "maximum_attendance_lease_age_ms",
        "maximum_focus_check_to_post_interval_ms",
        "maximum_fronting_bracket_interval_ms",
        "maximum_grounding_evidence_age_ms",
        "maximum_identity_check_to_dispatch_interval_ms",
        "maximum_seize_detection_latency_ms",
        "pixel_fallback_eligible",
        "request_schema",
        "required_permission_services",
        "result_schema",
        "retry_class",
        "review_requirement",
        "semantic_path",
        "synthetic_paths",
    ];
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    if keys != expected_sorted {
        return Err(VocabularyValidationError::WrongRowKeys(
            object
                .get("capability_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
        ));
    }
    let id = object["capability_id"].as_str().unwrap_or("");
    let action = object["action_kind"].as_str().unwrap_or("");
    let retry = object["retry_class"].as_str().unwrap_or("");
    let expected_action = if id == "computer.drag" {
        "mutate_durable"
    } else if id == "computer.screenshot" || id == "computer.wait" {
        "observe"
    } else {
        "compose"
    };
    if action != expected_action
        || object["action_kind_overrides"]
            != if id == "computer.keys" {
                serde_json::json!({"durable_chord":"mutate_durable"})
            } else {
                serde_json::json!({})
            }
    {
        return Err(VocabularyValidationError::RowBinding(format!(
            "action kind for {id}"
        )));
    }
    let expected_retry = match id {
        "computer.click" | "computer.type" | "computer.keys" | "computer.drag" => {
            "never_automatic_retry"
        }
        "computer.scroll" => "reconcile_before_retry",
        _ => "idempotent",
    };
    if retry != expected_retry {
        return Err(VocabularyValidationError::RowBinding(format!(
            "retry class for {id}"
        )));
    }
    for field in ["request_schema", "result_schema"] {
        validate_closed_schema(&object[field], &format!("{id}.{field}"))?;
    }
    let effect = object["effect_observation"].as_object().ok_or_else(|| {
        VocabularyValidationError::RowBinding(format!("effect observation for {id}"))
    })?;
    for required in ["deadline_ms", "failure_reasons", "methods", "statuses"] {
        if !effect.contains_key(required) {
            return Err(VocabularyValidationError::RowBinding(format!(
                "{id}.effect_observation.{required}"
            )));
        }
    }
    if effect["statuses"]
        != serde_json::json!([
            "effect_observed",
            "no_effect_observed",
            "effect_indeterminate"
        ])
    {
        return Err(VocabularyValidationError::RowBinding(format!(
            "effect statuses for {id}"
        )));
    }
    if id == "computer.move" && object["dispatch_modes"] != serde_json::json!(["observed"]) {
        return Err(VocabularyValidationError::RowBinding(
            "computer.move dispatch mode".into(),
        ));
    }
    if id == "computer.drag" && object["pixel_fallback_eligible"] != false {
        return Err(VocabularyValidationError::RowBinding(
            "computer.drag pixel fallback".into(),
        ));
    }
    if id == "computer.type" && object["pixel_fallback_eligible"] != false {
        return Err(VocabularyValidationError::RowBinding(
            "computer.type pixel fallback".into(),
        ));
    }
    validate_numeric_invariants(id, object)
}

fn validate_closed_schema(value: &Value, path: &str) -> Result<(), VocabularyValidationError> {
    let object = value
        .as_object()
        .ok_or_else(|| VocabularyValidationError::ClosedSchema(path.into()))?;
    if object.get("type").and_then(Value::as_str) != Some("object")
        || object.get("additionalProperties") != Some(&Value::Bool(false))
        || object
            .get("properties")
            .and_then(Value::as_object)
            .is_none()
        || object.get("required").and_then(Value::as_array).is_none()
    {
        return Err(VocabularyValidationError::ClosedSchema(path.into()));
    }
    for (name, schema) in object["properties"].as_object().unwrap() {
        validate_schema_node(schema, &format!("{path}.{name}"))?;
    }
    Ok(())
}

fn validate_schema_node(value: &Value, path: &str) -> Result<(), VocabularyValidationError> {
    let Some(object) = value.as_object() else {
        return Err(VocabularyValidationError::ClosedSchema(path.into()));
    };
    if object.get("type").and_then(Value::as_str) == Some("object") {
        if object.get("additionalProperties") != Some(&Value::Bool(false))
            || object
                .get("properties")
                .and_then(Value::as_object)
                .is_none()
        {
            return Err(VocabularyValidationError::ClosedSchema(path.into()));
        }
        for (name, schema) in object["properties"].as_object().unwrap() {
            validate_schema_node(schema, &format!("{path}.{name}"))?;
        }
    }
    if let Some(items) = object.get("items") {
        validate_schema_node(items, &format!("{path}[]"))?;
    }
    Ok(())
}

fn validate_numeric_invariants(
    id: &str,
    row: &serde_json::Map<String, Value>,
) -> Result<(), VocabularyValidationError> {
    let positive = [
        "maximum_accessibility_tree_settle_interval_ms",
        "maximum_attendance_check_to_dispatch_interval_ms",
        "maximum_attendance_lease_age_ms",
        "maximum_focus_check_to_post_interval_ms",
        "maximum_fronting_bracket_interval_ms",
        "maximum_grounding_evidence_age_ms",
        "maximum_identity_check_to_dispatch_interval_ms",
        "maximum_seize_detection_latency_ms",
    ];
    for key in positive {
        if let Some(value) = row[key].as_u64() {
            if value == 0 {
                return Err(VocabularyValidationError::NumericInvariant(format!(
                    "{id}.{key}"
                )));
            }
        }
    }
    let deadline = row["effect_observation"]
        .get("deadline_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if deadline == 0 || deadline > if id == "computer.wait" { 30_000 } else { 2_000 } {
        return Err(VocabularyValidationError::NumericInvariant(format!(
            "{id}.effect_observation.deadline_ms"
        )));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}
