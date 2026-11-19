//! Display records retained before their pointers enter the bus queue.

use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

use super::*;

mod worker;
pub(super) use worker::DiskWorker;

const UNREAD_MS: u64 = 24 * 60 * 60 * 1_000;
const CONFIRMED_MS: u64 = 10 * 60 * 1_000;
// In the busiest retained hour of call_records.jsonl, 274 calls with a
// call_key reached a final state (about 6,600 over 24 hours at that rate).
// Keep 20,000 for headroom: the journal omits calls without a key and caps
// its history, so the measured rate is a lower bound.
const MAX_RECORDS: usize = 20_000;
const MAX_BYTES: usize = 32 * 1024 * 1024;

// Older builds ignore this optional directory, so its on-disk format does
// not need to stay readable by them, and rolling back to one stays a plain
// binary swap.
// Each file holds two little-endian u64 millisecond timestamps (zero for no
// confirmation), then the DisplayWrite JSON. Confirming does not grow the file.
// At capacity we reject new records rather than shorten an existing promise.
// Nothing else delivers a rejected record, so the display module never shows
// that call; the displayRecordsDroppedStoreFull health counter counts them.
// Both bounds are meant to hold a 24-hour outage at the call rate measured
// in the comment on MAX_RECORDS.
const HEADER_BYTES: usize = 16;

struct Entry {
    written: u64,
    confirmed: u64,
    bytes: Vec<u8>,
}

impl Entry {
    fn deadline(&self) -> u64 {
        if self.confirmed == 0 {
            self.written.saturating_add(UNREAD_MS)
        } else {
            self.confirmed.saturating_add(CONFIRMED_MS)
        }
    }

    fn size(&self) -> usize {
        HEADER_BYTES + self.bytes.len()
    }

    fn load(path: &Path, id: &str, cap: usize) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid display record");
        let mut contents = Vec::new();
        File::open(path)?
            .take(cap as u64 + 1)
            .read_to_end(&mut contents)?;
        if contents.len() <= HEADER_BYTES || contents.len() > cap {
            return Err(invalid());
        }
        let bytes = contents.split_off(HEADER_BYTES);
        let written = u64::from_le_bytes(contents[..8].try_into().unwrap());
        let confirmed = u64::from_le_bytes(contents[8..].try_into().unwrap());
        if confirmed != 0 && !(written..written.saturating_add(UNREAD_MS)).contains(&confirmed) {
            return Err(invalid());
        }
        let write: DisplayWrite = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if display_identity(&write).as_deref() != Some(id)
            || !crate::tool_display::valid_for_delivery(&write)
            || serde_json::to_vec(&write).map_err(|_| invalid())? != bytes
        {
            return Err(invalid());
        }
        Ok(Self {
            written,
            confirmed,
            bytes,
        })
    }
}

pub(super) struct Records {
    entries: HashMap<String, Entry>,
    // Index each deadline once so repeated reads do not grow the index.
    deadlines: BTreeSet<(u64, u64, String)>,
    bytes: usize,
    max_count: usize,
    max_bytes: usize,
    directory: Option<PathBuf>,
    directory_synced: bool,
    // If an unindexed file cannot be removed, reject new records rather than
    // risk exceeding the size limit with bytes the index does not count.
    writable: bool,
    now_at_start: u64,
    started: Instant,
}

impl Default for Records {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            deadlines: BTreeSet::new(),
            bytes: 0,
            max_count: MAX_RECORDS,
            max_bytes: MAX_BYTES,
            directory: None,
            directory_synced: false,
            writable: true,
            now_at_start: crate::wall_clock_ms(),
            started: Instant::now(),
        }
    }
}

impl Records {
    #[cfg(test)]
    pub(super) fn with_limits(max_count: usize, max_bytes: usize) -> Self {
        Self {
            max_count,
            max_bytes,
            ..Default::default()
        }
    }

    /// A disk store under `directory` with small limits, so a test can fill it.
    #[cfg(test)]
    pub(super) fn open_with_limits(
        directory: PathBuf,
        gauges: &Gauges,
        max_count: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            max_count,
            max_bytes,
            ..Self::open(directory, gauges)
        }
    }

    pub(super) fn open(directory: PathBuf, gauges: &Gauges) -> Self {
        Self::open_at(directory, gauges, crate::wall_clock_ms())
    }

    fn open_at(directory: PathBuf, gauges: &Gauges, now: u64) -> Self {
        let mut records = Self {
            directory: Some(directory.clone()),
            now_at_start: now,
            ..Self::default()
        };
        let files =
            match check_private_directory(&directory).and_then(|()| fs::read_dir(&directory)) {
                Ok(files) => files,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return records,
                Err(_) => {
                    records.writable = false;
                    gauges.display_disk_failures.fetch_add(1, Relaxed);
                    return records;
                }
            };
        for file in files {
            let Ok(file) = file else {
                gauges.display_damaged.fetch_add(1, Relaxed);
                records.writable = false;
                continue;
            };
            let name = file.file_name();
            let Some(name) = name.to_str() else { continue };
            let path = file.path();
            if temporary_name(name) {
                records.discard(&path, gauges);
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            let entry = match file.file_type().and_then(|kind| {
                if !valid_id(id) || !kind.is_file() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Entry::load(&path, id, records.max_bytes)
            }) {
                Ok(entry) => entry,
                Err(_) => {
                    gauges.display_damaged.fetch_add(1, Relaxed);
                    records.discard(&path, gauges);
                    continue;
                }
            };
            if entry.deadline() <= now {
                records.discard(&path, gauges);
            } else if records.fits(id, entry.size()) {
                records.track(id.to_owned(), entry);
            } else {
                // Only an externally enlarged store can start above these bounds.
                gauges.failed(Failure::RecordCapacity);
                records.discard(&path, gauges);
            }
        }
        gauges
            .display_loaded
            .store(records.entries.len() as u64, Relaxed);
        records.update_held(gauges);
        records
    }

    pub(super) fn now(&self) -> u64 {
        self.now_at_start
            .saturating_add(self.started.elapsed().as_millis() as u64)
    }

    fn path(&self, id: &str) -> Option<PathBuf> {
        self.directory
            .as_ref()
            .map(|dir| dir.join(format!("{id}.json")))
    }

    fn discard(&mut self, path: &Path, gauges: &Gauges) {
        if remove_file(path).is_err() {
            gauges.display_disk_failures.fetch_add(1, Relaxed);
            self.writable = false;
        }
    }

    fn track(&mut self, id: String, entry: Entry) {
        if let Some(previous) = self.entries.remove(&id) {
            self.deadlines
                .remove(&(previous.deadline(), previous.written, id.clone()));
            self.bytes -= previous.size();
        }
        self.bytes += entry.size();
        self.deadlines
            .insert((entry.deadline(), entry.written, id.clone()));
        self.entries.insert(id, entry);
    }

    fn fits(&self, id: &str, size: usize) -> bool {
        let existing = self.entries.get(id);
        self.entries.len() + usize::from(existing.is_none()) <= self.max_count
            && self.bytes - existing.map_or(0, Entry::size) + size <= self.max_bytes
    }

    fn persist(&mut self, id: &str, entry: &Entry) -> io::Result<()> {
        let Some(path) = self.path(id) else {
            return Ok(());
        };
        let directory = self.directory.as_deref().unwrap();
        match check_private_directory(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                cerebellum_core::private_fs::create_dir_all(directory)?;
                check_private_directory(directory)?;
                self.directory_synced = false;
            }
            Err(error) => return Err(error),
        }
        if !self.directory_synced {
            // The first record needs the directory entry itself to survive a crash.
            #[cfg(unix)]
            File::open(directory.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()?;
            self.directory_synced = true;
        }
        let mut encoded = Vec::with_capacity(entry.size());
        encoded.extend_from_slice(&entry.written.to_le_bytes());
        encoded.extend_from_slice(&entry.confirmed.to_le_bytes());
        encoded.extend_from_slice(&entry.bytes);
        crate::private_content::write_atomically(&path, &encoded)
    }

    fn update_held(&self, gauges: &Gauges) {
        gauges
            .display_held
            .store(self.entries.len() as u64, Relaxed);
    }

    fn next_deadline(&self) -> Option<u64> {
        self.deadlines.first().map(|key| key.0)
    }

    fn expire(&mut self, now: u64, gauges: &Gauges) -> io::Result<()> {
        while let Some((deadline, _, id)) = self.deadlines.first() {
            if *deadline > now {
                break;
            }
            if let Some(path) = self.path(id) {
                remove_file(&path)?;
            }
            let (_, _, id) = self.deadlines.pop_first().unwrap();
            self.bytes -= self.entries.remove(&id).unwrap().size();
            self.update_held(gauges);
        }
        Ok(())
    }

    pub(super) fn insert(
        &mut self,
        id: String,
        bytes: Vec<u8>,
        now: u64,
        gauges: &Gauges,
    ) -> io::Result<bool> {
        if !self.writable {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.expire(now, gauges)?;
        let (written, confirmed) = self
            .entries
            .get(&id)
            .map_or((now, 0), |entry| (entry.written, entry.confirmed));
        let entry = Entry {
            written,
            confirmed,
            bytes,
        };
        if !self.fits(&id, entry.size()) {
            return Ok(false);
        }
        if let Err(error) = self.persist(&id, &entry) {
            // A rename can succeed even if the subsequent directory sync fails.
            // Don't let a new, unindexed file get around the size bound.
            if let Some(path) = self.path(&id) {
                if let Some(previous) = self.entries.get(&id) {
                    if entry.size() > previous.size()
                        && fs::symlink_metadata(&path)
                            .is_ok_and(|metadata| metadata.len() > previous.size() as u64)
                    {
                        self.writable = false;
                    }
                } else {
                    self.discard(&path, gauges);
                }
            }
            return Err(error);
        }
        self.track(id, entry);
        self.update_held(gauges);
        Ok(true)
    }

    pub(super) fn read(
        &mut self,
        id: &str,
        now: u64,
        gauges: &Gauges,
    ) -> io::Result<Option<Vec<u8>>> {
        // A failed expiry deletion must not hide unrelated, live records.
        if self.expire(now, gauges).is_err() {
            gauges.display_disk_failures.fetch_add(1, Relaxed);
        }
        let Some(entry) = self.entries.get(id).filter(|entry| entry.deadline() > now) else {
            return Ok(None);
        };
        if entry.confirmed != 0 {
            return Ok(Some(entry.bytes.clone()));
        }
        let confirmed = Entry {
            written: entry.written,
            confirmed: now.max(entry.written).max(1),
            bytes: entry.bytes.clone(),
        };
        self.persist(id, &confirmed)?;
        let bytes = confirmed.bytes.clone();
        self.track(id.to_owned(), confirmed);
        Ok(Some(bytes))
    }
}

fn check_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(())
}

fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn temporary_name(name: &str) -> bool {
    let mut parts = name.split('.');
    matches!((parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(id), Some(pid), Some(sequence), Some("tmp"), None)
        if valid_id(id) && pid.parse::<u32>().is_ok() && sequence.parse::<u64>().is_ok())
}

#[cfg(test)]
mod tests;
