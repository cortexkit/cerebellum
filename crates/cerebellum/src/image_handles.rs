//! Screenshot handles a codemode program can hand to Broca, and their bytes.
//!
//! A program's result is too small to carry a screenshot, so every screenshot
//! this module returns also gets a short handle. The program passes the handle
//! to Broca's model call, and Broca asks this module (`image.resolve`) for the
//! bytes. Nothing here reaches the disk, the journal or a call record: the
//! bytes a reply carried live in memory, keyed by their handle, and they go
//! when the handle expires or the conversation that captured them ends.
//!
//! A handle is minted only for a capture whose route carries a scope stamp,
//! because the resolver authorizes a fetch by scope and an unstamped capture
//! belongs to no scope anyone could name. A capture on an unstamped route
//! omits the field, and Broca's call then refuses with `image_unavailable`.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How long a handle resolves after its capture. Resolving never extends it.
pub(crate) const LIFETIME: Duration = Duration::from_secs(15 * 60);
/// The most handles one scope may hold at once.
pub(crate) const PER_SCOPE_LIMIT: usize = 8;
/// The most screenshot bytes all handles together may hold.
pub(crate) const TOTAL_BYTES_LIMIT: usize = 64 * 1024 * 1024;

/// The wire operation Broca calls.
pub(crate) const RESOLVE: &str = "image.resolve";
/// The mime types a handle may hold. The resolver's reply names one, and these
/// are the two snapshot encodings this module produces.
const MIME_TYPES: [&str; 2] = ["image/png", "image/jpeg"];
/// The refusal outcome for every handle that does not resolve. One word for
/// unknown, expired and other-scope handles, so a reply never says which.
pub(crate) const UNAVAILABLE: &str = "image_unavailable";

/// A handle: `ih` followed by 32 lowercase hex characters of 16 random bytes.
pub(crate) fn new_handle() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("image handle entropy unavailable");
    format!(
        "ih{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Whether `value` has the exact shape `new_handle` mints. Checked before any
/// lookup, so a malformed handle costs the same single map probe an unknown
/// well-formed one does.
fn is_handle(value: &str) -> bool {
    value.len() == 34
        && value.starts_with("ih")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A handle's bytes: decoded from the base64 the reply carried, wiped on drop.
struct Entry {
    bytes: Zeroizing<Vec<u8>>,
    mime: &'static str,
    sha256: String,
    scope_ref: String,
    conversation_key: String,
    expires_ms: u64,
}

/// Where a capture was made: the scope that may resolve it, the conversation
/// whose end drops it, and the wall-clock moment its 15 minutes start.
pub(crate) struct Capture {
    pub(crate) scope_ref: String,
    pub(crate) conversation_key: String,
    pub(crate) now_ms: u64,
}

#[derive(Default)]
struct Handles {
    entries: HashMap<String, Entry>,
    /// Handles in capture order, oldest first.
    order: VecDeque<String>,
    /// Handles held per scope.
    per_scope: BTreeMap<String, usize>,
    /// Screenshot bytes held by every handle together.
    bytes: usize,
}

impl Handles {
    fn remove(&mut self, handle: &str) -> Option<Entry> {
        let entry = self.entries.remove(handle)?;
        if let Some(index) = self.order.iter().position(|held| held == handle) {
            self.order.remove(index);
        }
        let held = self.per_scope.get_mut(&entry.scope_ref)?;
        *held = held.saturating_sub(1);
        if *held == 0 {
            self.per_scope.remove(&entry.scope_ref);
        }
        self.bytes = self.bytes.saturating_sub(entry.bytes.len());
        Some(entry)
    }

    fn expire(&mut self, now_ms: u64) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_ms <= now_ms)
            .map(|(handle, _)| handle.clone())
            .collect();
        for handle in expired {
            self.remove(&handle);
        }
    }

    /// Drops every handle of `conversation`, oldest first.
    fn end_conversation(&mut self, conversation: &str) {
        let ending: Vec<String> = self
            .order
            .iter()
            .filter(|handle| {
                self.entries
                    .get(*handle)
                    .is_some_and(|entry| entry.conversation_key == conversation)
            })
            .cloned()
            .collect();
        for handle in ending {
            self.remove(&handle);
        }
    }

    fn insert(&mut self, handle: String, entry: Entry) {
        let scope = entry.scope_ref.clone();
        self.bytes += entry.bytes.len();
        *self.per_scope.entry(scope.clone()).or_default() += 1;
        self.order.push_back(handle.clone());
        self.entries.insert(handle, entry);
        // Oldest first, so a scope keeps its most recent screenshots.
        while self
            .per_scope
            .get(&scope)
            .is_some_and(|held| *held > PER_SCOPE_LIMIT)
        {
            let oldest = self.oldest_of(&scope);
            match oldest {
                Some(oldest) => {
                    self.remove(&oldest);
                }
                None => break,
            }
        }
        while self.bytes > TOTAL_BYTES_LIMIT {
            let oldest = self.order.front().cloned();
            match oldest {
                Some(oldest) => {
                    self.remove(&oldest);
                }
                None => break,
            }
        }
    }

    fn oldest_of(&self, scope: &str) -> Option<String> {
        self.order
            .iter()
            .find(|handle| {
                self.entries
                    .get(*handle)
                    .is_some_and(|entry| entry.scope_ref == scope)
            })
            .cloned()
    }
}

/// What a reply's image field may carry a handle for.
struct Image<'a> {
    mime: &'static str,
    data_b64: &'a str,
}

/// The image field of a screenshot reply, when it carries usable bytes.
///
/// The two fields differ by capture path: a computer read_state puts its JPEG
/// under `reply.image`, and both browser planes put a PNG in a nested `image`
/// object. A missing, non-string or empty field, or a mime this module never
/// produces, mints no handle rather than one that could not resolve.
fn reply_image(reply: &Value) -> Option<Image<'_>> {
    let image = reply.get("image")?.as_object()?;
    let mime = image.get("mime")?.as_str()?;
    let mime = MIME_TYPES.iter().find(|known| **known == mime)?;
    let data_b64 = image.get("data_b64")?.as_str().filter(|data| !data.is_empty())?;
    Some(Image {
        mime,
        data_b64,
    })
}

/// The in-memory handle store. One per module process.
#[derive(Default)]
pub(crate) struct ImageHandles {
    state: Mutex<Handles>,
}

impl ImageHandles {
    /// Puts the bytes a reply is about to carry under a fresh handle, and
    /// returns that handle, or `None` when this reply mints none: no image,
    /// no scope stamp on the capturing route, or a reply the handle cannot
    /// describe.
    pub(crate) fn mint(&self, reply: &Value, capture: &Capture) -> Option<String> {
        let image = reply_image(reply)?;
        let decoded = cerebellum_core::serde_base64::decode(image.data_b64).ok()?;
        if decoded.is_empty() {
            return None;
        }
        let sha256 = Sha256::digest(&decoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let handle = new_handle();
        let entry = Entry {
            bytes: Zeroizing::new(decoded),
            mime: image.mime,
            sha256,
            scope_ref: capture.scope_ref.clone(),
            conversation_key: capture.conversation_key.clone(),
            expires_ms: capture.now_ms.saturating_add(LIFETIME.as_millis() as u64),
        };
        self.lock().insert(handle.clone(), entry);
        Some(handle)
    }

    /// The reply a handle resolves to when `scopes` is the authorized union
    /// private_content computes, or `None` for a handle that is unknown,
    /// expired or belongs to another scope. The three are one answer on
    /// purpose: telling them apart would say whether a handle exists.
    pub(crate) fn resolve(&self, handle: &str, scopes: &[&str], now_ms: u64) -> Option<Value> {
        if !is_handle(handle) {
            return None;
        }
        let mut state = self.lock();
        state.expire(now_ms);
        let entry = state.entries.get(handle)?;
        let mut authorized = false;
        for scope in scopes {
            // No early exit, so the work does not depend on which scope
            // matched. The compared strings are the caller's and the entry's
            // own, never the person's page.
            if *scope == entry.scope_ref {
                authorized = true;
            }
        }
        if !authorized {
            return None;
        }
        Some(json!({
            "mime": entry.mime,
            "sha256": entry.sha256,
            "bytes": cerebellum_core::serde_base64::encode(&entry.bytes),
        }))
    }

    /// Drops every handle captured under `conversation`. Called when the
    /// conversation's last route closes.
    pub(crate) fn end_conversation(&self, conversation: &str) {
        self.lock().end_conversation(conversation);
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.lock().entries.len()
    }

    fn lock(&self) -> MutexGuard<'_, Handles> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests;
