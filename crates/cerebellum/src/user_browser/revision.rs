//! The revision handshake between cerebellum and the Chrome extension.

use serde_json::{json, Value};

use super::refusal;

/// The revision of the cerebellum-to-extension contract this build speaks.
/// The extension stamps its own revision (`EXTENSION_REVISION` in
/// `extension/revision.mjs`) on every completed reply and every refusal, and
/// both numbers must change together whenever a plan, reply or refusal shape
/// changes, or when an extension fix must reach the person's Chrome. The
/// manifest `version` is not used for this: the person's Chrome can keep
/// running an old unpacked copy that reports the same `version`, and replies
/// from such a copy must refuse with a reload remedy instead of failing to
/// decode.
pub(crate) const EXTENSION_REVISION: u64 = 6;

/// The oldest revision whose replies existing actions still decode.
pub(super) const MINIMUM_EXTENSION_REVISION: u64 = 4;

/// The oldest revision that can run native option selection.
pub(super) const NATIVE_SELECT_MIN_REVISION: u64 = 5;

const EXTENSION_OUTDATED_REMEDY: &str = "The CortexKit Chrome extension is out of date. Ask the person to reload it in chrome://extensions, then retry.";
const EXTENSION_NEWER_REMEDY: &str = "The CortexKit Chrome extension is newer than this cerebellum. Ask the person to load the extension copy installed with this cerebellum and reload it in chrome://extensions, or update cerebellum, then retry.";

/// The refusal for a reply whose extension revision cannot serve the
/// operation, naming the revision `required` for it. A missing revision means
/// an extension older than the handshake itself, so it counts as outdated.
/// Every reply from such an extension is untrusted for decoding, so nothing of
/// it is relayed except whether input was dispatched.
pub(super) fn extension_revision_mismatch(
    found: Option<u64>,
    input_dispatched: Option<bool>,
    required: u64,
) -> Value {
    let newer = found.is_some_and(|revision| revision > EXTENSION_REVISION);
    let mut reply = refusal(if newer {
        "extension_newer"
    } else {
        "extension_outdated"
    });
    reply["remedy"] = json!(if newer {
        EXTENSION_NEWER_REMEDY
    } else {
        EXTENSION_OUTDATED_REMEDY
    });
    reply["detail"] = json!({"extension_revision":found, "required_revision":required});
    reply["input_dispatched"] = json!(input_dispatched);
    reply
}
