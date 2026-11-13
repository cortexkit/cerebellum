//! Closed JSON Schema objects and their byte-aware validation.
//!
//! JSON Schema's string lengths count characters. The `x-maxUtf8Bytes` and
//! `x-maxSerializedBytes` annotations express the stricter wire byte limits;
//! the validators here enforce them as well as the ordinary schema keywords.

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::{
    caps,
    ids::MAX_ID_BYTES,
    items::ItemKind,
    scope::MAX_BOUND_IDS,
    tokens::{ArgsKind, Operation, Platform, Token},
    ValidationError,
};

pub const MAX_WINDOW_MS: i64 = 92 * 24 * 60 * 60 * 1000;
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 200;

#[derive(Clone, Debug, Serialize)]
pub struct TokenSchema {
    pub token: Token,
    pub scope_key: &'static str,
    pub scope_schema: Value,
    pub ops: Vec<OpSchema>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpSchema {
    pub name: &'static str,
    pub args_schema: Value,
    pub result_schema: Value,
}

/// Static description only; the caller attaches the source's availability.
pub fn token_schemas(platform: Platform) -> Vec<TokenSchema> {
    platform
        .tokens()
        .iter()
        .map(|&token| TokenSchema {
            token,
            scope_key: token.info().scope_key,
            scope_schema: scope_schema(token),
            ops: token
                .info()
                .ops
                .iter()
                .map(|op| OpSchema {
                    name: op.name,
                    args_schema: args_schema(op),
                    result_schema: result_schema(op),
                })
                .collect(),
        })
        .collect()
}

fn object(properties: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let properties: Map<String, Value> = properties
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false})
}

fn array(items: Value, max: usize) -> Value {
    json!({"type": "array", "items": items, "maxItems": max})
}

fn nullable(value: Value) -> Value {
    json!({"anyOf": [value, {"type": "null"}]})
}
fn integer() -> Value {
    json!({"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX})
}
fn id() -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": MAX_ID_BYTES, "x-maxUtf8Bytes": MAX_ID_BYTES})
}
fn text(cap: usize) -> Value {
    json!({"type": "string", "maxLength": cap, "x-maxSerializedBytes": cap})
}
fn free_text() -> Value {
    nullable(text(caps::FREE_TEXT_BYTES))
}
fn enumeration(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}
fn date() -> Value {
    nullable(json!({"type": "string", "format": "date", "minLength": 10, "maxLength": 10}))
}

pub fn scope_schema(token: Token) -> Value {
    let key = token.info().scope_key;
    let mut ids = array(id(), MAX_BOUND_IDS);
    ids["minItems"] = json!(1);
    ids["uniqueItems"] = json!(true);
    object(vec![(key, ids)], &[key])
}

pub fn args_schema(op: &Operation) -> Value {
    let mut fields = Vec::new();
    let mut required = Vec::new();
    if op.is_list {
        fields.push(("limit", json!({"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": DEFAULT_LIMIT})));
        fields.push(("cursor", json!({"type": "string"})));
    }
    match op.args_kind {
        ArgsKind::Empty => {}
        ArgsKind::Window => {
            fields.extend([("from_ms", integer()), ("to_ms", integer())]);
            required.extend(["from_ms", "to_ms"]);
        }
        ArgsKind::Get => {
            fields.push(("id", id()));
            required.push("id");
        }
        ArgsKind::Reminders => {
            fields.push((
                "include_completed",
                json!({"type": "boolean", "default": false}),
            ));
        }
        ArgsKind::Contacts => {
            fields.push((
                "query",
                json!({"type": "string", "minLength": 1, "maxLength": 128, "x-maxUtf8Bytes": 128}),
            ));
        }
        ArgsKind::Conversation | ArgsKind::Mailbox => {
            let key = if op.args_kind == ArgsKind::Conversation {
                "conversation"
            } else {
                "mailbox"
            };
            fields.extend([(key, id()), ("since_ms", integer())]);
            required.push(key);
        }
    }
    let mut schema = object(fields, &required);
    if op.args_kind == ArgsKind::Window {
        schema["x-maxWindowMs"] = json!(MAX_WINDOW_MS);
    }
    schema
}

pub fn item_schema(kind: ItemKind) -> Value {
    let address = || {
        object(
            vec![
                ("name", nullable(text(caps::ENTRY_BYTES))),
                ("address", text(caps::ENTRY_BYTES)),
            ],
            &["name", "address"],
        )
    };
    let labeled = || {
        object(
            vec![
                ("label", nullable(text(caps::ENTRY_BYTES))),
                ("value", text(caps::ENTRY_BYTES)),
            ],
            &["label", "value"],
        )
    };
    let mut fields = Vec::new();
    for &name in kind.members() {
        let schema = match name {
            "id" | "calendar" | "list" | "conversation" | "mailbox" => id(),
            "title" | "account" | "given_name" | "family_name" | "organization" | "location"
            | "notes" | "subject" | "text" => free_text(),
            "start_ms" | "end_ms" | "due_ms" | "completed_ms" | "last_message_ms" | "sent_ms"
            | "date_ms" => nullable(integer()),
            "all_day" | "recurring" | "completed" | "from_me" | "read" | "flagged" => {
                nullable(json!({"type": "boolean"}))
            }
            "start_date" | "end_date" => date(),
            "kind" => enumeration(&["group", "account"]),
            "groups" => array(id(), MAX_BOUND_IDS),
            "emails" | "phones" => array(labeled(), caps::LABELED_ENTRIES),
            "participants" => array(text(caps::ENTRY_BYTES), caps::ADDRESS_ENTRIES),
            "sender" => nullable(text(caps::ENTRY_BYTES)),
            "from" => nullable(address()),
            "to" | "cc" => array(address(), caps::ADDRESS_ENTRIES),
            "text_state" => enumeration(&["ok", "absent", "undecodable"]),
            "body" => nullable(text(caps::BODY_BYTES)),
            "body_state" => enumeration(&["ok", "no_plain_text", "not_downloaded", "undecodable"]),
            "truncated" => {
                let mut schema = array(
                    enumeration(shortenable_members(kind)),
                    shortenable_members(kind).len(),
                );
                schema["uniqueItems"] = json!(true);
                schema
            }
            _ => unreachable!("unmapped item member"),
        };
        fields.push((name, schema));
    }
    object(fields, kind.members())
}

pub fn shortenable_members(kind: ItemKind) -> &'static [&'static str] {
    match kind {
        ItemKind::Container | ItemKind::Group => &["title"],
        ItemKind::Mailbox => &["title", "account"],
        ItemKind::Event => &["title", "location", "notes"],
        ItemKind::Reminder => &["title", "notes"],
        ItemKind::Contact => &[
            "given_name",
            "family_name",
            "organization",
            "emails",
            "phones",
        ],
        ItemKind::Conversation => &["title", "participants"],
        ItemKind::Message => &["sender", "text"],
        ItemKind::MailSummary => &["from", "to", "cc", "subject"],
        ItemKind::MailMessage => &["from", "to", "cc", "subject", "body"],
    }
}

pub fn result_schema(op: &Operation) -> Value {
    if op.is_list {
        object(
            vec![
                (
                    "items",
                    json!({"type": "array", "items": item_schema(op.item_kind)}),
                ),
                ("next_cursor", json!({"type": "string"})),
            ],
            &["items"],
        )
    } else {
        object(vec![("item", item_schema(op.item_kind))], &["item"])
    }
}

#[derive(Clone, PartialEq)]
pub struct ValidatedArgs(Value);

impl ValidatedArgs {
    pub fn as_json(&self) -> &Value {
        &self.0
    }
    pub fn into_json(self) -> Value {
        self.0
    }
    pub fn limit(&self) -> Option<usize> {
        self.0
            .get("limit")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
    }
    pub fn cursor(&self) -> Option<&str> {
        self.0.get("cursor").and_then(Value::as_str)
    }
    pub fn include_completed(&self) -> bool {
        self.0
            .get("include_completed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

/// Validate argument types, limits and event windows, then apply declared defaults.
/// A cursor's digest binds the token, operation, other normalized args and bound
/// id set. The page builder checks that digest; here a cursor is only a string.
pub fn validate_args(
    token: Token,
    op: &str,
    args: &Value,
) -> Result<ValidatedArgs, ValidationError> {
    let op = token
        .operation(op)
        .ok_or_else(|| ValidationError::new("op", "unknown operation for token"))?;
    let schema = args_schema(op);
    validate_shape(&schema, args, "args")?;
    if op.args_kind == ArgsKind::Window {
        let from = args["from_ms"].as_i64().expect("validated integer");
        let to = args["to_ms"].as_i64().expect("validated integer");
        let window = i128::from(to) - i128::from(from);
        if window <= 0 || window > i128::from(MAX_WINDOW_MS) {
            return Err(ValidationError::new(
                "from_ms/to_ms",
                "window must be positive and at most 92 days",
            ));
        }
    }
    let mut args = args.clone();
    for (key, definition) in schema["properties"].as_object().expect("schema properties") {
        if let Some(default) = definition.get("default") {
            args.as_object_mut()
                .expect("validated object")
                .entry(key.clone())
                .or_insert_with(|| default.clone());
        }
    }
    Ok(ValidatedArgs(args))
}

/// Checks the subset of JSON Schema emitted above, including byte annotations.
pub(crate) fn validate_shape(
    schema: &Value,
    value: &Value,
    field: &str,
) -> Result<(), ValidationError> {
    let bad = |problem| ValidationError::new(field, problem);
    if let Some(variants) = schema.get("anyOf").and_then(Value::as_array) {
        return if variants
            .iter()
            .any(|variant| validate_shape(variant, value, field).is_ok())
        {
            Ok(())
        } else {
            Err(bad("no matching nullable shape"))
        };
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(value) {
            return Err(bad("not a declared value"));
        }
    }
    let correct_type = match schema["type"].as_str() {
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("string") => value.is_string(),
        Some("integer") => value.as_i64().is_some(),
        Some("boolean") => value.is_boolean(),
        Some("null") => value.is_null(),
        _ => false,
    };
    if !correct_type {
        return Err(bad("wrong JSON type"));
    }
    if let Some(object) = value.as_object() {
        let properties = schema["properties"]
            .as_object()
            .expect("object schema properties");
        if object.keys().any(|key| !properties.contains_key(key)) {
            return Err(bad("unknown member"));
        }
        for key in schema["required"].as_array().expect("required members") {
            if !object.contains_key(key.as_str().expect("required member name")) {
                return Err(bad("missing member"));
            }
        }
        for (key, value) in object {
            validate_shape(&properties[key], value, key)?;
        }
    }
    if let Some(array) = value.as_array() {
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|n| array.len() < n as usize)
            || schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|n| array.len() > n as usize)
        {
            return Err(bad("array length out of range"));
        }
        if schema["uniqueItems"] == true
            && array
                .iter()
                .enumerate()
                .any(|(i, item)| array[..i].contains(item))
        {
            return Err(bad("repeated entry"));
        }
        for item in array {
            validate_shape(&schema["items"], item, field)?;
        }
    }
    if let Some(string) = value.as_str() {
        let length = string.chars().count();
        for (key, size) in [
            ("maxLength", length),
            ("x-maxUtf8Bytes", string.len()),
            (
                "x-maxSerializedBytes",
                caps::serialized_string_bytes(string),
            ),
        ] {
            if schema
                .get(key)
                .and_then(Value::as_u64)
                .is_some_and(|n| size > n as usize)
            {
                return Err(bad("string over byte or character cap"));
            }
        }
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|n| length < n as usize)
        {
            return Err(bad("string too short"));
        }
        if schema["format"] == "date" && !crate::items::valid_date(string) {
            return Err(bad("invalid date"));
        }
    }
    if let Some(number) = value.as_i64() {
        if schema
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|min| number < min)
            || schema
                .get("maximum")
                .and_then(Value::as_i64)
                .is_some_and(|max| number > max)
        {
            return Err(bad("integer out of range"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{items::test_items, TOKENS};

    fn minimal(op: &Operation) -> Value {
        match op.args_kind {
            ArgsKind::Window => json!({"from_ms": 0, "to_ms": 1}),
            ArgsKind::Get => json!({"id": "id"}),
            ArgsKind::Conversation => json!({"conversation": "id"}),
            ArgsKind::Mailbox => json!({"mailbox": "id"}),
            _ => json!({}),
        }
    }

    #[test]
    fn every_operation_has_closed_schemas_and_only_lists_take_paging() {
        fn closed_objects(schema: &Value) {
            match schema {
                Value::Object(map) => {
                    if map.get("type") == Some(&json!("object")) {
                        assert_eq!(schema["additionalProperties"], false);
                    }
                    for value in map.values() {
                        closed_objects(value);
                    }
                }
                Value::Array(array) => {
                    for value in array {
                        closed_objects(value);
                    }
                }
                _ => {}
            }
        }
        for info in TOKENS {
            closed_objects(&scope_schema(info.token));
            for op in info.ops {
                closed_objects(&args_schema(op));
                closed_objects(&result_schema(op));
                let mut args = minimal(op);
                let normalized = validate_args(info.token, op.name, &args).unwrap();
                assert_eq!(normalized.limit(), op.is_list.then_some(100));
                args["unknown"] = json!(true);
                assert!(validate_args(info.token, op.name, &args).is_err());
                args.as_object_mut().unwrap().remove("unknown");
                args["cursor"] = json!("opaque");
                args["limit"] = json!(200);
                assert_eq!(
                    validate_args(info.token, op.name, &args).is_ok(),
                    op.is_list
                );
                args["cursor"] = Value::Null;
                assert!(validate_args(info.token, op.name, &args).is_err());
                assert!(validate_args(info.token, op.name, &Value::Null).is_err());
                for name in args_schema(op)["required"].as_array().unwrap() {
                    let mut missing = minimal(op);
                    missing
                        .as_object_mut()
                        .unwrap()
                        .remove(name.as_str().unwrap());
                    assert!(validate_args(info.token, op.name, &missing).is_err());
                }
            }
        }
        let schemas = token_schemas(Platform::Windows);
        assert_eq!(
            schemas.iter().map(|s| s.token).collect::<Vec<_>>(),
            Platform::Windows.tokens()
        );
        assert_eq!(
            schemas[3].ops.iter().map(|op| op.name).collect::<Vec<_>>(),
            ["mailboxes.list", "messages.list", "messages.get"]
        );
    }

    #[test]
    fn args_reject_bad_windows_limits_queries_and_identifiers() {
        for args in [
            json!({"from_ms": 1, "to_ms": 1}),
            json!({"from_ms": 2, "to_ms": 1}),
            json!({"from_ms": 0, "to_ms": MAX_WINDOW_MS + 1}),
            json!({"from_ms": i64::MIN, "to_ms": i64::MAX}),
            json!({"from_ms": 0.5, "to_ms": 1}),
            json!({"from_ms": "0", "to_ms": 1}),
        ] {
            assert!(validate_args(Token::Calendar, "events.list", &args).is_err());
        }
        assert!(validate_args(
            Token::Calendar,
            "events.list",
            &json!({"from_ms": -1, "to_ms": MAX_WINDOW_MS - 1})
        )
        .is_ok());
        for info in TOKENS {
            for op in info.ops {
                if op.is_list {
                    for limit in [
                        json!(0),
                        json!(201),
                        json!(-1),
                        json!(1.5),
                        json!("1"),
                        Value::Null,
                    ] {
                        let mut args = minimal(op);
                        args["limit"] = limit;
                        assert!(validate_args(info.token, op.name, &args).is_err());
                    }
                    let mut args = minimal(op);
                    args["limit"] = json!(1);
                    assert_eq!(
                        validate_args(info.token, op.name, &args).unwrap().limit(),
                        Some(1)
                    );
                }
                let key = match op.args_kind {
                    ArgsKind::Get => "id",
                    ArgsKind::Conversation => "conversation",
                    ArgsKind::Mailbox => "mailbox",
                    _ => continue,
                };
                for id in [
                    json!(""),
                    json!("a".repeat(2049)),
                    json!("é".repeat(1025)),
                    json!(42),
                    Value::Null,
                ] {
                    let mut args = minimal(op);
                    args[key] = id;
                    assert!(validate_args(info.token, op.name, &args).is_err());
                }
                let mut args = minimal(op);
                args[key] = json!("é".repeat(1024));
                assert!(validate_args(info.token, op.name, &args).is_ok());
            }
        }
        for query in ["".to_owned(), "a".repeat(129), "é".repeat(65)] {
            assert!(
                validate_args(Token::Contacts, "contacts.list", &json!({"query": query})).is_err()
            );
        }
        assert!(validate_args(
            Token::Contacts,
            "contacts.list",
            &json!({"query": "é".repeat(64)})
        )
        .is_ok());
        let args = validate_args(Token::Reminders, "reminders.list", &json!({})).unwrap();
        assert!(!args.include_completed());
        assert_eq!(
            args.as_json(),
            &json!({"limit": 100, "include_completed": false})
        );
        assert!(validate_args(
            Token::Reminders,
            "reminders.list",
            &json!({"include_completed": true})
        )
        .unwrap()
        .include_completed());
        assert!(validate_args(
            Token::Reminders,
            "reminders.list",
            &json!({"include_completed": 0})
        )
        .is_err());
    }

    #[test]
    fn result_schemas_reject_unknown_missing_and_wrong_shaped_members() {
        for item in test_items() {
            let kind = item.kind();
            let value = serde_json::to_value(&item).unwrap();
            validate_shape(&item_schema(kind), &value, "item").unwrap();
            for name in kind.members() {
                let mut missing = value.clone();
                missing.as_object_mut().unwrap().remove(*name);
                assert!(validate_shape(&item_schema(kind), &missing, "item").is_err());
            }
            let mut unknown = value.clone();
            unknown["extra"] = json!(true);
            assert!(validate_shape(&item_schema(kind), &unknown, "item").is_err());
            for info in TOKENS {
                for op in info.ops.iter().filter(|op| op.item_kind == kind) {
                    let mut result = if op.is_list {
                        json!({"items": [value]})
                    } else {
                        json!({"item": value})
                    };
                    validate_shape(&result_schema(op), &result, "result").unwrap();
                    result["image"] = Value::Null;
                    assert!(validate_shape(&result_schema(op), &result, "result").is_err());
                }
            }
        }
        let schema = item_schema(ItemKind::Contact);
        let mut contact = serde_json::to_value(
            test_items()
                .into_iter()
                .find(|item| item.kind() == ItemKind::Contact)
                .unwrap(),
        )
        .unwrap();
        contact["emails"] = json!([{"label": null, "value": "a@example.test", "extra": true}]);
        assert!(validate_shape(&schema, &contact, "item").is_err());
        contact["emails"] = Value::Null;
        assert!(validate_shape(&schema, &contact, "item").is_err());
        let mut mail = serde_json::to_value(
            test_items()
                .into_iter()
                .find(|item| item.kind() == ItemKind::MailMessage)
                .unwrap(),
        )
        .unwrap();
        mail["from"] = json!({"name": null, "address": "a@example.test", "extra": true});
        assert!(validate_shape(&item_schema(ItemKind::MailMessage), &mail, "item").is_err());
    }
}
