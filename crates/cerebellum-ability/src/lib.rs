//! Shared, host-independent contracts for read-only personal-data abilities.
//!
//! Source adapters supply data; this crate owns the wire shapes, validation,
//! ordering and caps. It never opens a store or chooses permissions.

pub mod caps;
pub mod ids;
pub mod items;
pub mod order;
pub mod schema;
pub mod scope;
pub mod tokens;

pub use items::{Item, ItemKind};
pub use schema::{validate_args, ValidatedArgs};
pub use scope::{validate_scope, BoundScope};
pub use tokens::{Operation, Platform, Token, TOKENS};

/// A local validation failure, deliberately containing no supplied values.
/// The caller maps it to the refusal for the phase in which it occurred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub field: String,
    pub problem: &'static str,
}

impl ValidationError {
    pub(crate) fn new(field: impl Into<String>, problem: &'static str) -> Self {
        Self {
            field: field.into(),
            problem,
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.problem)
    }
}

impl std::error::Error for ValidationError {}
