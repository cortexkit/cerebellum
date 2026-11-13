//! Stateless cursors shared by in-process sources and macOS source-helper processes.

use crate::{
    ids::validate_id,
    items::{Item, ItemKind},
    order::{compare_keys, sort_key, SortKey},
    validate_args, BoundScope, Token, ValidatedArgs, ValidationError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

// A maximally escaped 2048-byte id plus the digest and JSON envelope fits here.
const MAX_CURSOR_BYTES: usize = 32 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    digest: String,
    last: SortKey,
}

/// Contains a digest, never a copy of the scope or content-bearing args.
pub struct CursorContext {
    digest: String,
    kind: ItemKind,
}

impl CursorContext {
    /// `ability.call.key` is deliberately absent: it selects a named ability in
    /// core's installed flow record. On every call, the caller must check that
    /// record authorizes this token and scope under the supplied key. Two keys
    /// authorizing the same token and bound ids can therefore share a cursor.
    pub fn for_call(
        token: Token,
        op: &str,
        args: &ValidatedArgs,
        scope: &BoundScope,
    ) -> Result<Self, ValidationError> {
        if token != scope.token() {
            return Err(ValidationError::new("scope", "token does not match scope"));
        }
        let operation = token
            .operation(op)
            .filter(|op| op.is_list)
            .ok_or_else(|| ValidationError::new("op", "cursor requires a list operation"))?;
        let args = validate_args(token, op, args.as_json())?;
        let args: BTreeMap<_, _> = args
            .as_json()
            .as_object()
            .expect("validated args")
            .iter()
            .filter(|(key, _)| key.as_str() != "limit" && key.as_str() != "cursor")
            .collect();
        Ok(Self::new(
            token,
            "call",
            op,
            &args,
            scope.ids(),
            operation.item_kind,
        ))
    }

    pub fn for_choices(token: Token, key: &str) -> Result<Self, ValidationError> {
        if key != token.info().scope_key {
            return Err(ValidationError::new("key", "not the token scope key"));
        }
        Ok(Self::new(
            token,
            "scope_choices",
            key,
            &BTreeMap::new(),
            &BTreeSet::new(),
            ItemKind::Container,
        ))
    }

    fn new(
        token: Token,
        surface: &str,
        op_or_key: &str,
        args: &BTreeMap<&String, &Value>,
        ids: &BTreeSet<String>,
        kind: ItemKind,
    ) -> Self {
        let bytes =
            serde_json::to_vec(&("ability-cursor-v1", token, surface, op_or_key, args, ids))
                .expect("serializable cursor context");
        Self {
            digest: URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
            kind,
        }
    }

    /// Check during argument admission, before any source access. A successful
    /// check needs no cached page or live cursor registry.
    pub fn validate(&self, cursor: &str) -> Result<(), ValidationError> {
        self.decode(cursor).map(|_| ())
    }

    fn decode(&self, cursor: &str) -> Result<SortKey, ValidationError> {
        let invalid = || ValidationError::new("cursor", "invalid or mismatched cursor");
        if cursor.len() > MAX_CURSOR_BYTES {
            return Err(invalid());
        }
        let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
        let parsed: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if parsed.version != 1
            || parsed.digest != self.digest
            || validate_id("id", &parsed.last.id).is_err()
        {
            return Err(invalid());
        }
        if matches!(
            self.kind,
            ItemKind::Container | ItemKind::Group | ItemKind::Contact | ItemKind::Mailbox
        ) && parsed.last.time_ms.is_some()
        {
            return Err(invalid());
        }
        Ok(parsed.last)
    }

    pub fn mint(&self, last: &Item) -> Result<String, ValidationError> {
        if last.kind() != self.kind {
            return Err(ValidationError::new("item", "cursor item kind mismatch"));
        }
        self.encode(sort_key(last))
    }

    pub(crate) fn encode(&self, last: SortKey) -> Result<String, ValidationError> {
        validate_id("id", &last.id)?;
        let bytes = serde_json::to_vec(&Cursor {
            version: 1,
            digest: self.digest.clone(),
            last,
        })
        .expect("serializable cursor");
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub(crate) fn seek(&self, cursor: Option<&str>) -> Result<Option<SortKey>, ValidationError> {
        cursor.map(|cursor| self.decode(cursor)).transpose()
    }

    pub(crate) fn after(&self, key: &SortKey, last: &SortKey) -> bool {
        compare_keys(self.kind, key, last) == Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        items::{Container, Reminder},
        validate_scope,
    };
    use serde_json::json;

    #[test]
    fn cursor_binds_normalized_args_token_op_and_id_set_but_not_limit_or_pack_key() {
        let scope = validate_scope(Token::Reminders, &json!({"list": ["b", "a"]})).unwrap();
        let args = validate_args(Token::Reminders, "reminders.list", &json!({})).unwrap();
        let context =
            CursorContext::for_call(Token::Reminders, "reminders.list", &args, &scope).unwrap();
        let cursor = context
            .mint(&Item::Reminder(Reminder {
                id: "last".into(),
                due_ms: Some(42),
                ..Default::default()
            }))
            .unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&cursor).unwrap()).unwrap();
        assert_eq!(payload["last"], json!({"id": "last", "time_ms": 42}));
        let reordered = validate_scope(Token::Reminders, &json!({"list": ["a", "b"]})).unwrap();
        let explicit = validate_args(
            Token::Reminders,
            "reminders.list",
            &json!({"include_completed": false, "limit": 7, "cursor": cursor}),
        )
        .unwrap();
        CursorContext::for_call(Token::Reminders, "reminders.list", &explicit, &reordered)
            .unwrap()
            .validate(&cursor)
            .unwrap();
        let changed_args = validate_args(
            Token::Reminders,
            "reminders.list",
            &json!({"include_completed": true}),
        )
        .unwrap();
        assert!(
            CursorContext::for_call(Token::Reminders, "reminders.list", &changed_args, &scope)
                .unwrap()
                .validate(&cursor)
                .is_err()
        );
        let changed_scope = validate_scope(Token::Reminders, &json!({"list": ["a", "c"]})).unwrap();
        assert!(
            CursorContext::for_call(Token::Reminders, "reminders.list", &args, &changed_scope)
                .unwrap()
                .validate(&cursor)
                .is_err()
        );
        let other_op = validate_args(Token::Reminders, "lists.list", &json!({})).unwrap();
        assert!(
            CursorContext::for_call(Token::Reminders, "lists.list", &other_op, &scope)
                .unwrap()
                .validate(&cursor)
                .is_err()
        );
        let other_scope =
            validate_scope(Token::Calendar, &json!({"calendar": ["a", "b"]})).unwrap();
        let other_args = validate_args(Token::Calendar, "calendars.list", &json!({})).unwrap();
        assert!(CursorContext::for_call(
            Token::Calendar,
            "calendars.list",
            &other_args,
            &other_scope
        )
        .unwrap()
        .validate(&cursor)
        .is_err());
    }

    #[test]
    fn cursor_checks_query_window_conversation_mailbox_and_since_arguments() {
        for (token, op, original, changed) in [
            (
                Token::Contacts,
                "contacts.list",
                json!({"query": "a"}),
                json!({"query": "b"}),
            ),
            (
                Token::Calendar,
                "events.list",
                json!({"from_ms": 0, "to_ms": 10}),
                json!({"from_ms": 1, "to_ms": 10}),
            ),
            (
                Token::Calendar,
                "events.list",
                json!({"from_ms": 0, "to_ms": 10}),
                json!({"from_ms": 0, "to_ms": 11}),
            ),
            (
                Token::Messages,
                "messages.list",
                json!({"conversation": "a"}),
                json!({"conversation": "b"}),
            ),
            (
                Token::Mail,
                "messages.list",
                json!({"mailbox": "a"}),
                json!({"mailbox": "b"}),
            ),
            (
                Token::Mail,
                "messages.list",
                json!({"mailbox": "a"}),
                json!({"mailbox": "a", "since_ms": 0}),
            ),
        ] {
            let scope =
                validate_scope(token, &json!({token.info().scope_key: ["a", "b"]})).unwrap();
            let args = validate_args(token, op, &original).unwrap();
            let context = CursorContext::for_call(token, op, &args, &scope).unwrap();
            let cursor = context
                .encode(SortKey {
                    time_ms: None,
                    id: "last".into(),
                })
                .unwrap();
            let changed_args = validate_args(token, op, &changed).unwrap();
            assert!(CursorContext::for_call(token, op, &changed_args, &scope)
                .unwrap()
                .validate(&cursor)
                .is_err());
        }
    }

    #[test]
    fn choices_and_call_cursors_have_separate_contexts_and_reject_malformed_values() {
        let choice = CursorContext::for_choices(Token::Calendar, "calendar").unwrap();
        assert!(CursorContext::for_choices(Token::Calendar, "list").is_err());
        let cursor = choice
            .mint(&Item::Container(Container {
                id: "last".into(),
                ..Default::default()
            }))
            .unwrap();
        assert!(CursorContext::for_choices(Token::Reminders, "list")
            .unwrap()
            .validate(&cursor)
            .is_err());
        let scope = validate_scope(Token::Calendar, &json!({"calendar": ["a"]})).unwrap();
        let args = validate_args(Token::Calendar, "calendars.list", &json!({})).unwrap();
        assert!(
            CursorContext::for_call(Token::Calendar, "calendars.list", &args, &scope)
                .unwrap()
                .validate(&cursor)
                .is_err()
        );
        for malformed in [
            "",
            "not json",
            "====",
            "e30",
            &"a".repeat(MAX_CURSOR_BYTES + 1),
        ] {
            assert!(choice.validate(malformed).is_err());
        }
        for change in [
            json!({"version": 2}),
            json!({"digest": "wrong"}),
            json!({"extra": true}),
            json!({"last": {"id": "", "time_ms": null}}),
            json!({"last": {"id": "x", "time_ms": 1}}),
        ] {
            let mut value: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&cursor).unwrap()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(choice
                .validate(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap()))
                .is_err());
        }
    }
}
