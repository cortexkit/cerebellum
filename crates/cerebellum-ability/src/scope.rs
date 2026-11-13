use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::{schema, tokens::Token, ValidationError};

pub const MAX_BOUND_IDS: usize = 64;

#[derive(Clone, Eq, PartialEq)]
pub struct BoundScope {
    token: Token,
    ids: BTreeSet<String>,
}

impl std::fmt::Debug for BoundScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundScope")
            .field("token", &self.token)
            .field("id_count", &self.ids.len())
            .finish()
    }
}

impl BoundScope {
    pub fn token(&self) -> Token {
        self.token
    }
    pub fn ids(&self) -> &BTreeSet<String> {
        &self.ids
    }
    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.token == other.token && self.ids.is_subset(&other.ids)
    }
    pub fn as_json(&self) -> Value {
        json!({self.token.info().scope_key: self.ids})
    }
}

/// Validate the exact one-key JSON shape and return its ids as a set. The caller
/// must separately check that set against the person's binding for the request.
pub fn validate_scope(token: Token, value: &Value) -> Result<BoundScope, ValidationError> {
    schema::validate_shape(&schema::scope_schema(token), value, "scope")?;
    let ids = value[token.info().scope_key]
        .as_array()
        .expect("validated scope array")
        .iter()
        .map(|id| id.as_str().expect("validated id string").to_owned())
        .collect();
    Ok(BoundScope { token, ids })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TOKENS;

    #[test]
    fn every_scope_rejects_each_malformed_row_five_case() {
        for info in TOKENS {
            let key = info.scope_key;
            let invalid = [
                json!({"wrong": ["id"]}),
                json!({key: ["id"], "extra": []}),
                json!({key: "id"}),
                json!({key: []}),
                json!({key: (0..65).map(|i| i.to_string()).collect::<Vec<_>>()}),
                json!({key: [1]}),
                json!({key: [""]}),
                json!({key: ["id", "id"]}),
                json!({key: ["a".repeat(2049)]}),
                json!({key: ["é".repeat(1025)]}),
            ];
            for (case, value) in invalid.into_iter().enumerate() {
                assert!(
                    validate_scope(info.token, &value).is_err(),
                    "{} case {case}",
                    info.token.as_str()
                );
            }
            assert!(validate_scope(info.token, &Value::Null).is_err());
            let ids = (0..64)
                .map(|n| format!("{n:02}{}", "é".repeat(1023)))
                .collect::<Vec<_>>();
            assert_eq!(
                validate_scope(info.token, &json!({key: ids}))
                    .unwrap()
                    .ids()
                    .len(),
                64
            );
        }
    }

    #[test]
    fn bound_ids_are_a_set_but_never_union_across_tokens() {
        let scope = validate_scope(Token::Calendar, &json!({"calendar": ["é", "a"]})).unwrap();
        assert_eq!(scope.as_json(), json!({"calendar": ["a", "é"]}));
        let smaller = validate_scope(Token::Calendar, &json!({"calendar": ["a"]})).unwrap();
        assert!(smaller.is_subset_of(&scope));
        assert!(!scope.is_subset_of(&smaller));
        let other = validate_scope(Token::Reminders, &json!({"list": ["a", "é"]})).unwrap();
        assert!(!smaller.is_subset_of(&other));
        assert!(!format!("{scope:?}").contains('é'));
    }
}
