//! Per-cut replay records are separate from permanent privacy marks.
//!
//! Finished cuts are kept for good, holding only their step and saved
//! replies, so a repeated request keeps getting its first reply. Retiring
//! them would need two things first. The agent-data move contract
//! (`cortexkit-role-agent-data`) would have to state how long a repeated
//! request must keep its first answer, since a retired cut answers as
//! unknown; it states no such window today. And the checkpoint would need a
//! new format version recording when each cut finished, declared in the
//! format floor (the file that stops an older build from opening data it
//! can't read).

use super::*;
use cerebellum_core::format_floor::{FormatFloor, FORMAT_FLOOR_FILE};
use std::{fs::File, io::Read};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply {
    pub request: Value,
    pub reply: Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cut {
    pub step: Step,
    pub refs: Option<cortexkit_role_agent_data::refs::Refs>,
    pub payloads: BTreeMap<String, Payload>,
    pub replies: BTreeMap<String, Reply>,
}

impl Default for Cut {
    fn default() -> Self {
        Self {
            step: Step::None,
            refs: None,
            payloads: BTreeMap::new(),
            replies: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    format_version: u64,
    pub cuts: BTreeMap<String, Cut>,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            format_version: CHECKPOINT_FORMAT.version,
            cuts: BTreeMap::new(),
        }
    }
}

impl Participant {
    pub(super) async fn load(&self, memory: &Document) -> Result<Document, ErrorBody> {
        let Some(path) = self.path.clone() else {
            return Ok(memory.clone());
        };
        tokio::task::spawn_blocking(move || {
            let file = match File::open(path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Document::default())
                }
                Err(e) => return Err(unavailable(e)),
            };
            let mut bytes = Vec::new();
            file.take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(unavailable)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(unavailable("checkpoint file exceeds size limit"));
            }
            let document: Document = serde_json::from_slice(&bytes).map_err(unavailable)?;
            if document.format_version != CHECKPOINT_FORMAT.version {
                return Err(unavailable("unsupported checkpoint version"));
            }
            Ok(document)
        })
        .await
        .map_err(unavailable)?
    }

    /// Persist `document`, then hand it back with the lock. Serializing and
    /// writing the whole document both run on a blocking thread, so a large
    /// checkpoint never occupies an async worker. A durable participant reads
    /// its state from the file on every request, so only the in-memory one
    /// keeps a copy under the lock.
    pub(super) async fn save(
        &self,
        document: Document,
        mut guard: tokio::sync::OwnedMutexGuard<Document>,
    ) -> Result<(tokio::sync::OwnedMutexGuard<Document>, Document), ErrorBody> {
        let Some(path) = self.path.clone() else {
            *guard = document.clone();
            return Ok((guard, document));
        };
        tokio::task::spawn_blocking(move || {
            let bytes = serde_json::to_vec(&document).map_err(unavailable)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(unavailable("checkpoint file exceeds size limit"));
            }
            // Keep the checkpoint lock held until the actual disk write ends,
            // even when the request waiting for this thread is cancelled.
            let floor = FormatFloor::at(
                path.parent()
                    .expect("checkpoint directory")
                    .join(FORMAT_FLOOR_FILE),
            );
            floor.raise(CHECKPOINT_FORMAT).map_err(unavailable)?;
            crate::private_content::write_atomically(&path, &bytes).map_err(unavailable)?;
            Ok((guard, document))
        })
        .await
        .map_err(unavailable)?
    }
}
