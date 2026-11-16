//! Recent display arguments, retained before their pointer enters the bus queue.

use std::collections::{HashMap, VecDeque};

use super::*;

const TARGET_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const MIN_AGE: Duration = Duration::from_secs(10 * 60 + QUEUE_WINDOW.as_secs());
// Match the call journal's 20,000-record ceiling, but never retain more payload
// bytes than the reply cache's 32 MiB. At the role's 16 KiB body cap that holds
// roughly 2,000 records; ordinary scalar call summaries leave much more room.
const MAX_RECORDS: usize = 20_000;
const MAX_BYTES: usize = 32 * 1024 * 1024;

struct Entry {
    bytes: Vec<u8>,
    written: Instant,
}

pub(super) struct Records {
    entries: HashMap<String, Entry>,
    order: VecDeque<String>,
    bytes: usize,
    max_count: usize,
    max_bytes: usize,
}

impl Default for Records {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_count: MAX_RECORDS,
            max_bytes: MAX_BYTES,
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
    fn remove(&mut self, id: &str) {
        if let Some(entry) = self.entries.remove(id) {
            self.bytes -= entry.bytes.len();
            self.order.retain(|held| held != id);
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some(id) = self.order.front() {
            if now.duration_since(self.entries[id].written) < TARGET_AGE {
                break;
            }
            let id = self.order.pop_front().expect("front exists");
            let entry = self.entries.remove(&id).expect("ordered entry exists");
            self.bytes -= entry.bytes.len();
        }
    }

    pub(super) fn insert(&mut self, id: &str, bytes: Vec<u8>, now: Instant) -> bool {
        self.expire(now);
        let previous = self.entries.get(id).map_or(0, |entry| entry.bytes.len());
        let mut count = self.entries.len() + usize::from(!self.entries.contains_key(id));
        let mut size = self.bytes - previous + bytes.len();
        let mut evict = vec![];
        for held in &self.order {
            if count <= self.max_count && size <= self.max_bytes {
                break;
            }
            let entry = &self.entries[held];
            if now.duration_since(entry.written) < MIN_AGE {
                break;
            }
            if held == id {
                continue;
            }
            count -= 1;
            size -= entry.bytes.len();
            evict.push(held.clone());
        }
        // Never publish a pointer whose ten-minute read window cannot fit.
        // Queue delay is reserved too; the queue drops events older than that.
        if count > self.max_count || size > self.max_bytes {
            return false;
        }
        if !evict.is_empty() {
            for held in evict {
                if let Some(entry) = self.entries.remove(&held) {
                    self.bytes -= entry.bytes.len();
                }
            }
            self.order.retain(|held| self.entries.contains_key(held));
        }
        self.remove(id);
        self.bytes += bytes.len();
        self.entries.insert(
            id.into(),
            Entry {
                bytes,
                written: now,
            },
        );
        self.order.push_back(id.into());
        true
    }

    pub(super) fn read(&mut self, id: &str, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        self.entries.get(id).map(|entry| entry.bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn minimum_retention_and_count_pressure_drop_new_wakes() {
        let mut records = Records {
            max_count: 2,
            ..Default::default()
        };
        let start = Instant::now();
        assert!(records.insert("a", vec![1], start));
        assert!(records.insert("b", vec![2], start));
        tokio::time::advance(Duration::from_secs(609)).await;
        assert!(!records.insert("c", vec![3], Instant::now()));
        assert_eq!(records.read("a", Instant::now()), Some(vec![1]));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(records.insert("c", vec![3], Instant::now()));
        assert!(records.read("a", Instant::now()).is_none());
        assert_eq!(records.read("b", Instant::now()), Some(vec![2]));
        assert_eq!(records.read("c", Instant::now()), Some(vec![3]));
    }

    #[tokio::test(start_paused = true)]
    async fn byte_eviction_expiry_restart_and_retry_refresh() {
        let mut records = Records {
            max_bytes: 3,
            ..Default::default()
        };
        assert!(records.insert("a", vec![1, 2], Instant::now()));
        assert!(!records.insert("b", vec![3, 4], Instant::now()));
        tokio::time::advance(Duration::from_secs(610)).await;
        assert!(records.insert("b", vec![3, 4], Instant::now()));
        assert!(records.read("a", Instant::now()).is_none());
        assert!(
            Records::default().read("b", Instant::now()).is_none(),
            "a restart loses even a live record"
        );
        tokio::time::advance(Duration::from_secs(24 * 60 * 60 - 1)).await;
        assert!(records.read("b", Instant::now()).is_some());
        assert!(records.insert("b", vec![3, 4], Instant::now()));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(records.read("b", Instant::now()).is_some());
        tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;
        assert!(records.read("b", Instant::now()).is_none());
    }
}
