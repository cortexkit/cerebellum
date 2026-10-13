use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cerebellum_core::format_floor::FormatFloor;

use super::{
    lock, AgentGrantStoreError, AgentGrantStoreState, AGENT_GRANT_STORE_FILE,
    AGENT_GRANT_STORE_FORMAT,
};

/// `None` means never migrated; a present empty state means migration completed.
pub trait AgentGrantStorage: Send + Sync {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError>;
    fn save(&self, state: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError>;
}

#[derive(Default, Clone)]
pub struct InMemoryAgentGrantStorage {
    state: Arc<Mutex<Option<AgentGrantStoreState>>>,
}

impl AgentGrantStorage for InMemoryAgentGrantStorage {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
        Ok(lock(&self.state).clone())
    }
    fn save(&self, state: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
        state.check()?;
        *lock(&self.state) = Some(state.clone());
        Ok(())
    }
}

pub struct FilesystemAgentGrantStorage {
    path: PathBuf,
    floor: FormatFloor,
}
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl FilesystemAgentGrantStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let floor = FormatFloor::governing(&path);
        Self { path, floor }
    }
    pub fn with_format_floor(mut self, floor: FormatFloor) -> Self {
        self.floor = floor;
        self
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn production() -> Result<Self, AgentGrantStoreError> {
        cerebellum_core::journal::journal_data_path(AGENT_GRANT_STORE_FILE)
            .map(Self::new)
            .map_err(|error| AgentGrantStoreError::Unreadable {
                detail: format!("{error:?}"),
            })
    }
}

impl AgentGrantStorage for FilesystemAgentGrantStorage {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
        let unreadable = |error: std::io::Error| AgentGrantStoreError::Unreadable {
            detail: error.to_string(),
        };
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unreadable(error)),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(unreadable)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| AgentGrantStoreError::Corrupt {
                detail: error.to_string(),
            })?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| AgentGrantStoreError::Corrupt {
                detail: "missing unsigned version".into(),
            })?;
        if version != AGENT_GRANT_STORE_FORMAT.version {
            return Err(AgentGrantStoreError::UnknownVersion { found: version });
        }
        let state: AgentGrantStoreState =
            serde_json::from_value(value).map_err(|error| AgentGrantStoreError::Corrupt {
                detail: error.to_string(),
            })?;
        state.check()?;
        Ok(Some(state))
    }

    fn save(&self, state: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
        state.check()?;
        let failed = |error: std::io::Error| AgentGrantStoreError::WriteFailed {
            detail: error.to_string(),
        };
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| {
            AgentGrantStoreError::WriteFailed {
                detail: error.to_string(),
            }
        })?;
        // Staging must know this format is present before any grant bytes are
        // written; a failed floor raise must leave even the temp file absent.
        self.floor
            .raise(AGENT_GRANT_STORE_FORMAT)
            .map_err(|error| AgentGrantStoreError::WriteFailed {
                detail: error.to_string(),
            })?;
        let directory = self.path.parent().unwrap_or_else(|| Path::new("."));
        cerebellum_core::private_fs::create_dir_all(directory).map_err(failed)?;
        let temporary = directory.join(format!(
            ".agent-grants.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| {
            let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            if let Ok(directory) = File::open(directory) {
                let _ = directory.sync_all();
            }
            Ok(())
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written.map_err(failed)
    }
}
