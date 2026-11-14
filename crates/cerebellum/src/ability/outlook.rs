//! The guard runs before forwarding any operation to an Outlook member source.

// The native factory is installed by the Windows COM adapter. Until then the
// host-neutral seam is exercised by fakes, without opening an operator's profile.
#![cfg_attr(not(test), allow(dead_code))]

pub(super) mod source;
pub(super) mod zones;

use super::{serving, Availability, Refusal, StatusSource};
use crate::outlook_guard::{GuardEnvironment, Guarded};
use cerebellum_ability::{BoundScope, Token, ValidatedArgs};

impl<S: GuardEnvironment + StatusSource> StatusSource for Guarded<S> {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        if let Some(reason) = self.decision().unavailable_reason() {
            return Ok(tokens
                .iter()
                .map(|&token| (token, Availability::unavailable(reason)))
                .collect());
        }
        self.0.status(tokens)
    }

    fn choices(&self, token: Token) -> Result<Vec<serving::ScopeChoice>, Refusal> {
        if let Some(reason) = self.decision().unavailable_reason() {
            return Err(Refusal::Unavailable(reason));
        }
        self.0.choices(token)
    }

    fn read(
        &self,
        token: Token,
        op: &str,
        args: &ValidatedArgs,
        scope: &BoundScope,
    ) -> Result<serving::SourceRead, Refusal> {
        if let Some(reason) = self.decision().unavailable_reason() {
            return Err(Refusal::Unavailable(reason));
        }
        self.0.read(token, op, args, scope)
    }
}
