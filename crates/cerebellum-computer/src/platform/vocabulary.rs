//! Digest-pinned, canonical computer action vocabulary validation.

use super::PermissionService;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

// TWO INDEPENDENT AXES, and they carry different version numbers on purpose.
//
//   schema_id — the document FORMAT contract: which keys a row has and what
//               they mean. A reader that understands /v1 can parse any /v1
//               artifact.
//   revision  — the vocabulary CONTENT version: which capabilities exist and
//               what each one accepts.
//
// Changing what a capability accepts bumps the REVISION only, which is why the
// two numbers differ: revisions 2 through 12 changed nested request and result
// schemas or action annotations inside rows whose shape was unchanged, and
// kept format /v1. Revision 13 is the first to change which keys a row has --
// rows no longer carry action_kind or action_kind_overrides, because consent
// is granted per application rather than per class of action -- so it moved
// the format to /v2. A reviewer read the mismatch as a mistake before finding
// both fields in the artifact, so it is stated here rather than re-derived.
pub const COMPUTER_ACTION_VOCABULARY_SCHEMA_ID: &str = "ck-computer-action-vocabulary/v2";
pub const COMPUTER_ACTION_VOCABULARY_REVISION: &str = "computer_action_vocabulary-v23";
pub const COMPUTER_ACTION_VOCABULARY_ARTIFACT: &[u8] =
    include_bytes!("../../resources/computer_action_vocabulary-v23.json");
const IMPLEMENTATION_SOURCE_LOCK: &[u8] =
    include_bytes!("../../../cerebellum/resources/implementation-source-lock.json");

/// This is filled with the checked-in artifact digest after the resource is
/// frozen. Keeping the value in the source-lock, rather than another lock file,
/// makes the browser and computer artifacts share one release authority.
pub const COMPUTER_ACTION_VOCABULARY_SHA256: &str =
    "68fde428a263087692960d589de54117da77be4940fd5879085814f4620f53f7";

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

/// Why a capability result could not be certified against its frozen schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityResultValidationError {
    /// The capability id is absent from the frozen vocabulary.
    UnknownCapability(String),
    /// The embedded result-schema table cannot be interpreted safely.
    MalformedArtifact(String),
    /// The reply itself violates the named capability's result schema.
    ReplyViolations {
        capability_id: String,
        violations: Vec<CapabilityResultViolation>,
    },
}

impl fmt::Display for CapabilityResultValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for CapabilityResultValidationError {}

/// The precise result-schema rule a reply violated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityResultViolation {
    ExpectedType { path: String, expected: String },
    MissingRequiredProperty { path: String, property: String },
    UndeclaredProperty { path: String },
    EnumMismatch { path: String },
}

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

/// Every capability row the frozen artifact carries, in artifact order.
///
/// The one list other closed per-id tables are checked against: the
/// declaration set, the dispatch rows and the grounding policy each name these
/// ids and no others.
pub const COMPUTER_CAPABILITY_ROW_IDS: [&str; 12] = [
    "computer.read_state",
    "computer.press_element",
    "computer.press_point",
    "computer.write_text",
    "computer.type",
    "computer.keys",
    "computer.takeover_move",
    "computer.takeover_drag",
    "computer.takeover_scroll",
    "computer.wait",
    "computer.list_apps",
    "computer.open_app",
];

/// Rows whose target is an element named through the accessibility tree.
/// Pressing and writing through accessibility posts no event, so these rows
/// may require no post-event or input-monitoring grant and declare no
/// synthetic path; a row that did would be withheld on machines that can
/// serve it, and would carry a path nothing takes.
const ELEMENT_ADDRESSED_ROW_IDS: [&str; 4] = [
    "computer.read_state",
    "computer.press_element",
    "computer.press_point",
    "computer.write_text",
];

/// Rows that drive the one real system pointer, which only the global event
/// stream carries.
const TAKEOVER_ROW_IDS: [&str; 3] = [
    "computer.takeover_move",
    "computer.takeover_drag",
    "computer.takeover_scroll",
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
    if rows.len() != COMPUTER_CAPABILITY_ROW_IDS.len() {
        return Err(VocabularyValidationError::WrongRowCount(rows.len()));
    }
    let ids: Vec<_> = rows
        .iter()
        .filter_map(|row| row.get("capability_id").and_then(Value::as_str))
        .collect();
    if ids != COMPUTER_CAPABILITY_ROW_IDS {
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
    // Image reads have their own bound; keyboard rows keep the posting bound.
    if object["capability_id"] == "computer.read_state" {
        expected_sorted.push("maximum_fronting_read_interval_ms");
    }
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
    let retry = object["retry_class"].as_str().unwrap_or("");
    // Named per id with no default, so a row added to the artifact without a
    // decision here fails validation instead of inheriting a retry class.
    let expected_retry = match id {
        "computer.read_state" | "computer.wait" | "computer.list_apps" => "idempotent",
        "computer.open_app"
        | "computer.press_element"
        | "computer.press_point"
        | "computer.write_text"
        | "computer.type"
        | "computer.keys"
        | "computer.takeover_move"
        | "computer.takeover_drag"
        | "computer.takeover_scroll" => "never_automatic_retry",
        _ => {
            return Err(VocabularyValidationError::RowBinding(format!(
                "no retry class is bound for {id}"
            )))
        }
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
    // The pointer rows reach an application only through the global event
    // stream, so observed mode is the only mode they have.
    if TAKEOVER_ROW_IDS.contains(&id)
        && (object["dispatch_modes"] != serde_json::json!(["observed"])
            || object["synthetic_paths"] != serde_json::json!(["global"]))
    {
        return Err(VocabularyValidationError::RowBinding(format!(
            "{id} delivery must be global and observed only"
        )));
    }
    if ELEMENT_ADDRESSED_ROW_IDS.contains(&id) {
        let services = object["required_permission_services"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if object["dispatch_modes"] != serde_json::json!(["background"])
            || object["synthetic_paths"] != serde_json::json!([])
            || services
                .iter()
                .any(|service| matches!(service.as_str(), Some("post_event" | "input_monitoring")))
        {
            return Err(VocabularyValidationError::RowBinding(format!(
                "{id} posts no event and needs no event grant"
            )));
        }
    }
    // Typing into a field identified by pixels rather than by identity is how
    // a credential field gets typed into without being classified as one, and
    // no row added with the accessibility-first actions falls back to pixels.
    if (id == "computer.type"
        || ELEMENT_ADDRESSED_ROW_IDS.contains(&id)
        || TAKEOVER_ROW_IDS.contains(&id))
        && object["pixel_fallback_eligible"] != false
    {
        return Err(VocabularyValidationError::RowBinding(format!(
            "{id} pixel fallback"
        )));
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
    if id == "computer.read_state"
        && !row["maximum_fronting_read_interval_ms"]
            .as_u64()
            .is_some_and(|bound| bound > 0 && bound <= 500)
    {
        return Err(VocabularyValidationError::NumericInvariant(format!(
            "{id}.maximum_fronting_read_interval_ms"
        )));
    }
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
    if deadline == 0
        || deadline
            > if id == "computer.open_app" {
                120_000
            } else if id == "computer.wait" {
                30_000
            } else {
                2_000
            }
    {
        return Err(VocabularyValidationError::NumericInvariant(format!(
            "{id}.effect_observation.deadline_ms"
        )));
    }
    Ok(())
}

fn validate_runtime_result_schema(
    schema: &Value,
    path: &str,
) -> Result<(), CapabilityResultValidationError> {
    let object = schema.as_object().ok_or_else(|| {
        CapabilityResultValidationError::MalformedArtifact(format!(
            "{path} result schema is not an object"
        ))
    })?;
    for keyword in object.keys() {
        if !matches!(
            keyword.as_str(),
            "additionalProperties"
                | "description"
                | "enum"
                | "items"
                | "properties"
                | "required"
                | "type"
        ) {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path} uses unsupported result-schema keyword {keyword}"
            )));
        }
    }

    let schema_type = object.get("type").and_then(Value::as_str).ok_or_else(|| {
        CapabilityResultValidationError::MalformedArtifact(format!(
            "{path} result schema has no string type"
        ))
    })?;
    if !matches!(
        schema_type,
        "array" | "boolean" | "integer" | "null" | "number" | "object" | "string"
    ) {
        return Err(CapabilityResultValidationError::MalformedArtifact(format!(
            "{path} has unsupported result type {schema_type}"
        )));
    }
    for keyword in object.keys() {
        let applicable = match schema_type {
            "object" => matches!(
                keyword.as_str(),
                "additionalProperties"
                    | "description"
                    | "enum"
                    | "properties"
                    | "required"
                    | "type"
            ),
            "array" => matches!(keyword.as_str(), "description" | "enum" | "items" | "type"),
            _ => matches!(keyword.as_str(), "description" | "enum" | "type"),
        };
        if !applicable {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.{keyword} does not apply to result type {schema_type}"
            )));
        }
    }

    if object
        .get("description")
        .is_some_and(|description| !description.is_string())
    {
        return Err(CapabilityResultValidationError::MalformedArtifact(format!(
            "{path}.description is not a string"
        )));
    }

    if let Some(choices) = object.get("enum") {
        let choices = choices.as_array().ok_or_else(|| {
            CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.enum is not an array"
            ))
        })?;
        if choices.is_empty()
            || choices
                .iter()
                .any(|choice| !value_has_type(choice, schema_type))
        {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.enum is empty or disagrees with its type"
            )));
        }
    }

    match schema_type {
        "object" => {
            let properties = object
                .get("properties")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.properties is not an object"
                    ))
                })?;
            if object.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path} is not closed"
                )));
            }
            let required = object
                .get("required")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.required is not an array"
                    ))
                })?;
            for required_name in required {
                let required_name = required_name.as_str().ok_or_else(|| {
                    CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.required contains a non-string"
                    ))
                })?;
                if !properties.contains_key(required_name) {
                    return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.required names undeclared property {required_name}"
                    )));
                }
            }
            for (name, property_schema) in properties {
                validate_runtime_result_schema(property_schema, &format!("{path}.{name}"))?;
            }
        }
        "array" => {
            // REQUIRED, not optional. An array with no `items` is a hole in the
            // closed-schema guarantee rather than a schema with nothing to say:
            // enforcement walks elements only when it has a schema for them, so
            // an undeclared array passes every element unchecked while the row
            // reads as closed. `computer.screenshot.windows` was exactly that
            // until v12 -- the one array a caller reads after asking for
            // target_windows, with its element shape unvalidated.
            //
            // The browser plane has always required it. Two validators for one
            // rule is how they came to disagree, and the weaker one guarded the
            // artifact with the hole.
            let items = object.get("items").ok_or_else(|| {
                CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path}.items is missing"
                ))
            })?;
            validate_runtime_result_schema(items, &format!("{path}[]"))?;
        }
        _ => {}
    }
    Ok(())
}

fn value_has_type(value: &Value, schema_type: &str) -> bool {
    match schema_type {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn parse_result_schema_table(
    bytes: &[u8],
) -> Result<BTreeMap<String, Value>, CapabilityResultValidationError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| CapabilityResultValidationError::MalformedArtifact(error.to_string()))?;
    validate_value(&value).map_err(|error| {
        CapabilityResultValidationError::MalformedArtifact(format!(
            "vocabulary validation failed: {error}"
        ))
    })?;
    let rows = value["rows"].as_array().ok_or_else(|| {
        CapabilityResultValidationError::MalformedArtifact("missing rows array".into())
    })?;
    let mut table = BTreeMap::new();
    for row in rows {
        let capability_id = row["capability_id"].as_str().ok_or_else(|| {
            CapabilityResultValidationError::MalformedArtifact("row missing capability_id".into())
        })?;
        let schema = row.get("result_schema").ok_or_else(|| {
            CapabilityResultValidationError::MalformedArtifact(format!(
                "{capability_id} missing result_schema"
            ))
        })?;
        validate_runtime_result_schema(schema, &format!("{capability_id}.result_schema"))?;
        if table
            .insert(capability_id.to_string(), schema.clone())
            .is_some()
        {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "duplicate result schema for {capability_id}"
            )));
        }
    }
    Ok(table)
}

fn result_schema_table() -> Result<&'static BTreeMap<String, Value>, CapabilityResultValidationError>
{
    static TABLE: OnceLock<Result<BTreeMap<String, Value>, CapabilityResultValidationError>> =
        OnceLock::new();
    match TABLE.get_or_init(|| parse_result_schema_table(COMPUTER_ACTION_VOCABULARY_ARTIFACT)) {
        Ok(table) => Ok(table),
        Err(error) => Err(error.clone()),
    }
}

/// One of a frozen row's millisecond bounds, such as
/// `maximum_fronting_bracket_interval_ms`, read from the artifact itself so a
/// served path is held to the number the vocabulary publishes rather than to
/// a copy of it. `None` when the row or field is absent or null.
pub fn frozen_row_bound_ms(capability_id: &str, field: &str) -> Option<u64> {
    static ROWS: OnceLock<Option<Value>> = OnceLock::new();
    ROWS.get_or_init(|| serde_json::from_slice(COMPUTER_ACTION_VOCABULARY_ARTIFACT).ok())
        .as_ref()?
        .get("rows")?
        .as_array()?
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(capability_id))?
        .get(field)?
        .as_u64()
}

/// A frozen row's effect-observation deadline: how long the vocabulary allows
/// for an action's effect to be observed. Read from the artifact itself, so a
/// served path is held to the number the vocabulary publishes rather than to a
/// copy of it. `None` when absent or null.
pub fn frozen_row_effect_deadline_ms(capability_id: &str) -> Option<u64> {
    static ROWS: OnceLock<Option<Value>> = OnceLock::new();
    ROWS.get_or_init(|| serde_json::from_slice(COMPUTER_ACTION_VOCABULARY_ARTIFACT).ok())
        .as_ref()?
        .get("rows")?
        .as_array()?
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(capability_id))?
        .get("effect_observation")?
        .get("deadline_ms")?
        .as_u64()
}

fn collect_result_violations(
    schema: &Value,
    result: &Value,
    path: &str,
    violations: &mut Vec<CapabilityResultViolation>,
) {
    let object = schema
        .as_object()
        .expect("cached result schemas were validated while loading");
    let schema_type = object["type"]
        .as_str()
        .expect("cached result schema types were validated while loading");
    if !value_has_type(result, schema_type) {
        violations.push(CapabilityResultViolation::ExpectedType {
            path: path.to_string(),
            expected: schema_type.to_string(),
        });
        return;
    }
    if object
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|choices| !choices.contains(result))
    {
        violations.push(CapabilityResultViolation::EnumMismatch {
            path: path.to_string(),
        });
    }

    match schema_type {
        "object" => {
            let result = result
                .as_object()
                .expect("the result type was checked above");
            let properties = object["properties"]
                .as_object()
                .expect("cached object schemas have properties");
            for required_name in object["required"]
                .as_array()
                .expect("cached object schemas have required lists")
            {
                let required_name = required_name
                    .as_str()
                    .expect("cached required names are strings");
                if !result.contains_key(required_name) {
                    violations.push(CapabilityResultViolation::MissingRequiredProperty {
                        path: path.to_string(),
                        property: required_name.to_string(),
                    });
                }
            }
            for (name, value) in result {
                let Some(property_schema) = properties.get(name) else {
                    violations.push(CapabilityResultViolation::UndeclaredProperty {
                        path: format!("{path}.{name}"),
                    });
                    continue;
                };
                collect_result_violations(
                    property_schema,
                    value,
                    &format!("{path}.{name}"),
                    violations,
                );
            }
        }
        "array" => {
            let items = object
                .get("items")
                .expect("cached array schemas have items");
            for (index, value) in result
                .as_array()
                .expect("the result type was checked above")
                .iter()
                .enumerate()
            {
                collect_result_violations(items, value, &format!("{path}[{index}]"), violations);
            }
        }
        _ => {}
    }
}

/// Check a served capability reply against the digest-pinned result schema.
///
/// The artifact is parsed and checked once per process. Each call then walks the
/// reply once, without cloning it. An unknown capability or an unsupported
/// schema keyword fails
/// closed rather than silently weakening the contract.
pub fn validate_capability_result(
    capability_id: &str,
    result: &Value,
) -> Result<(), CapabilityResultValidationError> {
    let table = result_schema_table()?;
    let schema = table.get(capability_id).ok_or_else(|| {
        CapabilityResultValidationError::UnknownCapability(capability_id.to_string())
    })?;
    let mut violations = Vec::new();
    collect_result_violations(schema, result, "$", &mut violations);
    violations.sort();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CapabilityResultValidationError::ReplyViolations {
            capability_id: capability_id.to_string(),
            violations,
        })
    }
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

/// Why a capability's required permissions could not be read from the frozen
/// vocabulary. A shorter list is never a valid answer: dropping a service is
/// how a real OS requirement becomes invisible to probes and to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VocabularyPermissionError {
    /// The capability id is not one of the frozen rows.
    UnknownCapability(String),
    /// A row named a service the `PermissionService` enum does not have.
    UnrecognizedService(String),
    /// The embedded artifact could not be interpreted as the expected table.
    MalformedArtifact(String),
}

impl fmt::Display for VocabularyPermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VocabularyPermissionError {}

fn parse_permission_service(name: &str) -> Result<PermissionService, VocabularyPermissionError> {
    match name {
        "accessibility" => Ok(PermissionService::Accessibility),
        "post_event" => Ok(PermissionService::PostEvent),
        "input_monitoring" => Ok(PermissionService::InputMonitoring),
        "screen_recording" => Ok(PermissionService::ScreenRecording),
        // RawHidObservation exists on the enum for probe results but is not a
        // vocabulary-row requirement today; an unknown string must still refuse
        // rather than map onto it by guess.
        other => Err(VocabularyPermissionError::UnrecognizedService(
            other.to_string(),
        )),
    }
}

/// Build the capability → required-services table from vocabulary bytes.
///
/// Every string in `required_permission_services` must map to a known
/// `PermissionService`. Skipping an unknown name would shrink the list and
/// hide a real OS requirement — the same class of defect as hard-coding a
/// shorter set in the driver.
fn parse_permission_table(
    bytes: &[u8],
) -> Result<BTreeMap<String, Vec<PermissionService>>, VocabularyPermissionError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| VocabularyPermissionError::MalformedArtifact(error.to_string()))?;
    let rows = value
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| VocabularyPermissionError::MalformedArtifact("missing rows array".into()))?;
    let mut table = BTreeMap::new();
    for row in rows {
        let id = row
            .get("capability_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                VocabularyPermissionError::MalformedArtifact("row missing capability_id".into())
            })?
            .to_string();
        let services = row
            .get("required_permission_services")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                VocabularyPermissionError::MalformedArtifact(format!(
                    "{id} missing required_permission_services",
                ))
            })?;
        let mut parsed = Vec::with_capacity(services.len());
        for service in services {
            let name = service.as_str().ok_or_else(|| {
                VocabularyPermissionError::MalformedArtifact(format!(
                    "{id} has a non-string permission service",
                ))
            })?;
            parsed.push(parse_permission_service(name)?);
        }
        table.insert(id, parsed);
    }
    Ok(table)
}

fn permission_table(
) -> Result<&'static BTreeMap<String, Vec<PermissionService>>, VocabularyPermissionError> {
    static TABLE: OnceLock<
        Result<BTreeMap<String, Vec<PermissionService>>, VocabularyPermissionError>,
    > = OnceLock::new();
    match TABLE.get_or_init(|| parse_permission_table(COMPUTER_ACTION_VOCABULARY_ARTIFACT)) {
        Ok(table) => Ok(table),
        Err(error) => Err(error.clone()),
    }
}

/// Required OS permission services for a frozen capability, taken from the
/// digest-locked vocabulary rather than restated beside the driver.
///
/// Unknown capability ids and unrecognised service names both refuse: there is
/// no default set to fall back to, because inventing one is how the driver and
/// the contract drift apart.
pub fn required_permission_services(
    capability_id: &str,
) -> Result<Vec<PermissionService>, VocabularyPermissionError> {
    let table = permission_table()?;
    table
        .get(capability_id)
        .cloned()
        .ok_or_else(|| VocabularyPermissionError::UnknownCapability(capability_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_fronting_bound_is_a_positive_integer_at_most_half_a_second() {
        let vocabulary: Value =
            serde_json::from_slice(COMPUTER_ACTION_VOCABULARY_ARTIFACT).unwrap();
        let mut row = vocabulary["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["capability_id"] == "computer.read_state")
            .unwrap()
            .clone();
        assert_eq!(
            validate_numeric_invariants("computer.read_state", row.as_object().unwrap()),
            Ok(())
        );
        assert_eq!(
            frozen_row_bound_ms("computer.read_state", "maximum_fronting_read_interval_ms"),
            Some(300)
        );
        assert_eq!(
            frozen_row_bound_ms("computer.keys", "maximum_fronting_bracket_interval_ms"),
            Some(100)
        );
        for invalid in [
            serde_json::json!(0),
            serde_json::json!(501),
            serde_json::json!(-1),
            serde_json::json!(300.5),
            serde_json::json!("300"),
            Value::Null,
        ] {
            row["maximum_fronting_read_interval_ms"] = invalid;
            assert_eq!(
                validate_numeric_invariants("computer.read_state", row.as_object().unwrap()),
                Err(VocabularyValidationError::NumericInvariant(
                    "computer.read_state.maximum_fronting_read_interval_ms".into()
                ))
            );
        }
    }

    #[test]
    fn a_reply_with_a_field_its_closed_result_schema_does_not_declare_is_caught() {
        let reply = serde_json::json!({
            "outcome": "predicate_satisfied",
            "evidence": "duration elapsed",
            "settle_path": "poll_with_deadline",
            "waited_ms": 25,
        });

        assert_eq!(
            validate_capability_result("computer.wait", &reply),
            Err(CapabilityResultValidationError::ReplyViolations {
                capability_id: "computer.wait".into(),
                violations: vec![CapabilityResultViolation::UndeclaredProperty {
                    path: "$.waited_ms".into(),
                }],
            })
        );
    }

    #[test]
    fn a_reply_conforming_to_its_frozen_result_schema_passes() {
        let reply = serde_json::json!({
            "outcome": "predicate_satisfied",
            "evidence": "duration elapsed",
            "settle_path": "poll_with_deadline",
        });

        assert_eq!(validate_capability_result("computer.wait", &reply), Ok(()));
    }

    #[test]
    fn a_keystroke_refusal_naming_its_application_conforms_to_the_v13_result_schema() {
        let reply = serde_json::json!({
            "outcome": "ambiguous",
            "containment_rung": "pid_structural",
            "effect_status": "effect_indeterminate",
            "target_fronted": false,
            "bundle_identity": "com.example.App",
            "instances": [{"pid": 1, "window_count": 2}, {"pid": 3, "window_count": 1}],
            "remedy": "quit all but one instance, then retry",
        });

        assert_eq!(validate_capability_result("computer.type", &reply), Ok(()));
    }

    #[test]
    fn frozen_rows_require_exactly_the_services_the_vocabulary_lists() {
        let accessibility_only = vec![PermissionService::Accessibility];
        let keystroke = vec![
            PermissionService::Accessibility,
            PermissionService::PostEvent,
            PermissionService::InputMonitoring,
        ];
        for (id, expected) in [
            ("computer.read_state", accessibility_only.clone()),
            ("computer.press_element", accessibility_only.clone()),
            ("computer.press_point", accessibility_only.clone()),
            ("computer.write_text", accessibility_only),
            ("computer.type", keystroke.clone()),
            ("computer.keys", keystroke.clone()),
            (
                "computer.takeover_move",
                vec![PermissionService::InputMonitoring],
            ),
            (
                "computer.takeover_drag",
                vec![
                    PermissionService::PostEvent,
                    PermissionService::InputMonitoring,
                ],
            ),
            ("computer.takeover_scroll", keystroke),
            ("computer.wait", Vec::new()),
            ("computer.list_apps", Vec::new()),
            ("computer.open_app", Vec::new()),
        ] {
            assert_eq!(
                required_permission_services(id).expect("a frozen row"),
                expected,
                "{id}"
            );
        }
    }

    #[test]
    fn a_retired_capability_has_no_permission_list() {
        for id in [
            "computer.click",
            "computer.screenshot",
            "computer.move",
            "computer.drag",
            "computer.scroll",
        ] {
            assert_eq!(
                required_permission_services(id),
                Err(VocabularyPermissionError::UnknownCapability(id.into()))
            );
        }
    }

    #[test]
    fn an_unknown_capability_has_no_permission_list() {
        assert_eq!(
            required_permission_services("computer.nope"),
            Err(VocabularyPermissionError::UnknownCapability(
                "computer.nope".into(),
            ))
        );
    }

    #[test]
    fn an_unrecognized_permission_service_is_refused() {
        let bytes = br#"{"rows":[{"capability_id":"computer.wait","required_permission_services":["telepathy"]}]}"#;
        assert_eq!(
            parse_permission_table(bytes),
            Err(VocabularyPermissionError::UnrecognizedService(
                "telepathy".into(),
            ))
        );
    }
}
