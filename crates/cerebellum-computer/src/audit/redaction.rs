//! What the computer plane's audit journal may keep of an application's text.
//!
//! An accessibility snapshot carries a window's own words: a document title, a
//! button's label, the contents of a text field. Journaling that verbatim would
//! make an application's contents durable inside our audit record, which is the
//! opposite of what the record is for.
//!
//! THIS POLICY EXCLUDES RATHER THAN SCRUBS, and the distinction is the whole
//! design. Scrubbing means keeping the text and removing the sensitive parts,
//! which requires knowing which parts are sensitive.
//!
//! A PARTIAL SIGNAL EXISTS AND CANNOT CARRY THAT WEIGHT. macOS marks a password
//! field with the `AXSecureTextField` subrole, and a standard secure field
//! reports it without the application doing anything. But a custom control
//! reports it only if its author implemented it, and there is no signal at all
//! for text that is sensitive without being a password: a document, a message, a
//! recovery phrase typed into an ordinary field. So the signal is trustworthy
//! when PRESENT and says nothing when ABSENT, which is the wrong shape to build
//! a keep-by-default policy on. A scrubbing policy would keep everything it
//! failed to recognise, and its failures are silent by construction.
//!
//! The asymmetry does have a use, in the other direction: because this policy
//! withholds everything, a recognised secure field can only ever ADD a refusal,
//! never permit something. Anything built on that signal later inherits that
//! safety, which is why it belongs on top of exclusion rather than instead of
//! it.
//!
//! So free text is replaced outright. What survives is its SHAPE — that a value
//! was present and how long it was — which is what an auditor needs to see that
//! a field was read without learning what it said.
//!
//! TRUNCATION IS NOT REDACTION, and this policy exists partly to keep that
//! distinction enforced at a call site. A prefix of a secret is a secret: an API
//! key cut to forty bytes identifies the key, and a truncating policy would
//! satisfy every "is a redactor bound" check while making the material durable.

use cerebellum_core::journal::{RedactionUnavailable, Redactor};

/// What replaces an application's own text in the journal.
///
/// A fixed marker rather than an empty string, so a reader can tell a field that
/// was read and withheld from one that was absent or empty. Those are different
/// facts about what happened.
pub const WITHHELD_MARKER: &str = "[withheld]";

/// Replaces every application-supplied string with a description of its shape.
///
/// Available in the sense the journal means: it can always produce a value, so
/// binding it never blocks an action. What it produces never contains input.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExcludeApplicationText;

impl Redactor for ExcludeApplicationText {
    fn available(&self) -> bool {
        true
    }

    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable> {
        if input.is_empty() {
            return Ok(String::new());
        }

        // The byte length is reported rather than the character count, because
        // the journal's own size bounds are in bytes and an auditor comparing
        // the two should not have to convert between units.
        //
        // The length is the ONE thing that survives, and it is worth being
        // explicit that this is a deliberate leak of a single number: it tells
        // an auditor a field held something, and distinguishes a short label
        // from a long document title, without carrying any of the content. A
        // length alone cannot reconstruct a value; it can narrow a guess, which
        // is why nothing finer than a length is emitted.
        let described = format!("{WITHHELD_MARKER} {} bytes", input.len());

        // The marker itself must fit. A caller that allows less room than the
        // marker needs is asking for something this policy cannot honestly
        // provide, and a shortened marker is exactly the truncated-secret shape
        // this exists to avoid -- so it refuses rather than emitting a prefix.
        if described.len() > max_bytes {
            if WITHHELD_MARKER.len() <= max_bytes {
                return Ok(WITHHELD_MARKER.to_string());
            }
            return Err(RedactionUnavailable);
        }
        Ok(described)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No part of the input survives, at any length.
    ///
    /// The assertion is over the OUTPUT containing no fragment of the input,
    /// rather than over the output equalling a marker: a policy that emitted the
    /// marker plus a prefix would satisfy an equality check written loosely, and
    /// the prefix is the whole hazard.
    #[test]
    fn no_fragment_of_the_input_survives() {
        let policy = ExcludeApplicationText;
        let secret = "sk-live-4f9a2b7c1e8d";

        let output = policy.redact(secret, 512).expect("a value is produced");

        for length in 4..=secret.len() {
            let fragment = &secret[..length];
            assert!(
                !output.contains(fragment),
                "the output carries the first {length} bytes of the input: {output}"
            );
        }
        assert!(output.starts_with(WITHHELD_MARKER));
    }

    /// A withheld value is distinguishable from an absent one.
    ///
    /// An empty string means the field was empty; the marker means it held
    /// something that is not being recorded. Collapsing them would make an
    /// auditor unable to tell a blank field from a redacted one.
    #[test]
    fn an_empty_field_is_not_reported_as_withheld() {
        let policy = ExcludeApplicationText;
        assert_eq!(policy.redact("", 512).expect("a value"), "");
        assert_ne!(policy.redact("x", 512).expect("a value"), "");
    }

    /// The length is reported, so a reader can tell a label from a document.
    #[test]
    fn the_shape_of_the_value_survives() {
        let policy = ExcludeApplicationText;
        let output = policy.redact("hello world", 512).expect("a value");
        assert_eq!(output, format!("{WITHHELD_MARKER} 11 bytes"));
    }

    /// Two different inputs of the same length are indistinguishable.
    ///
    /// The property that makes this a redaction rather than an encoding: the
    /// output is a function of the length alone, so nothing about the content
    /// can be recovered from it.
    #[test]
    fn inputs_of_equal_length_produce_equal_output() {
        let policy = ExcludeApplicationText;
        assert_eq!(
            policy.redact("password123", 512).expect("a value"),
            policy.redact("hello world", 512).expect("a value")
        );
    }

    /// A budget too small for the marker refuses rather than emitting a prefix.
    ///
    /// The refusal is the point. Trimming the marker to fit would return a
    /// fragment, and a policy that returns fragments under pressure is one that
    /// returns fragments of secrets under pressure.
    #[test]
    fn a_budget_below_the_marker_refuses() {
        let policy = ExcludeApplicationText;
        assert_eq!(
            policy.redact("something", 3),
            Err(RedactionUnavailable),
            "a value was produced in less room than the marker needs"
        );
    }

    /// A budget that fits the marker but not the length keeps the marker.
    #[test]
    fn a_tight_budget_keeps_the_marker_without_the_length() {
        let policy = ExcludeApplicationText;
        let output = policy
            .redact("a much longer value than the budget", WITHHELD_MARKER.len())
            .expect("the marker fits");
        assert_eq!(output, WITHHELD_MARKER);
    }

    /// The policy is always able to answer, so binding it blocks nothing.
    ///
    /// A policy that cannot answer makes capture unavailable, so being always
    /// able to answer is what lets this be bound before any classifier exists.
    /// It withholds unconditionally, so availability costs nothing.
    #[test]
    fn the_policy_is_available() {
        assert!(ExcludeApplicationText.available());
    }
}
