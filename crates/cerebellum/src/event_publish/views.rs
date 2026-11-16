//! One bounded startup reconciliation; drop the bucket watch after its snapshot.

use std::collections::BTreeSet;

use super::*;

pub(super) const RECONCILE_WINDOW: Duration = Duration::from_secs(30);
const SNAPSHOT_WINDOW: Duration = Duration::from_secs(10);

pub(crate) enum SnapshotItem {
    Key(String),
    CaughtUp,
}

pub(crate) trait Snapshot: Send {
    fn next(&mut self) -> BoxFuture<'_, Result<SnapshotItem, Failure>>;
}

pub(crate) trait Bucket: Send + Sync {
    fn watch(&self) -> BoxFuture<'_, Result<Box<dyn Snapshot>, Failure>>;
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, Failure>>;
    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), Failure>>;
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), Failure>>;
}

fn value_cap() -> usize {
    cortexkit_bus_naming::MODULE_BUCKETS
        .iter()
        .find(|bucket| bucket.owner == "cerebellum" && bucket.name == "views")
        .expect("declared views bucket")
        .max_value_bytes as usize
}

fn key(pin: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    pin.bytes()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

async fn bounded<T>(future: BoxFuture<'_, Result<T, Failure>>) -> Result<T, Failure> {
    tokio::time::timeout(PUBLISH_WINDOW, future)
        .await
        .unwrap_or(Err(Failure::Timeout))
}

async fn snapshot(bucket: &dyn Bucket) -> Result<BTreeSet<String>, Failure> {
    tokio::time::timeout(SNAPSHOT_WINDOW, async {
        let mut watch = bucket.watch().await?;
        let mut keys = BTreeSet::new();
        loop {
            match watch.next().await? {
                SnapshotItem::Key(key) => {
                    keys.insert(key);
                }
                SnapshotItem::CaughtUp => return Ok(keys),
            }
        }
    })
    .await
    .unwrap_or(Err(Failure::Timeout))
}

pub(super) async fn reconcile(
    bucket: &dyn Bucket,
    replies: Vec<(String, Vec<u8>)>,
    gauges: &Gauges,
) {
    // A failed snapshot cannot establish which keys are orphaned. Still repair
    // known pins through get/put, without relying on any partial snapshot.
    let existing = match snapshot(bucket).await {
        Ok(keys) => Some(keys),
        Err(reason) => {
            gauges.failed(reason);
            None
        }
    };
    let desired: BTreeSet<_> = replies.iter().map(|(pin, _)| key(pin)).collect();
    for (pin, bytes) in replies {
        if bytes.len() > value_cap() {
            gauges.failed(Failure::Overflow);
            eprintln!(
                "bus views skipped pin {pin}: {} bytes exceeds {} byte cap",
                bytes.len(),
                value_cap()
            );
            continue;
        }
        let key = key(&pin);
        let result = match bounded(bucket.get(&key)).await {
            Ok(Some(held)) if held == bytes => continue,
            Ok(_) => bounded(bucket.put(&key, &bytes)).await,
            Err(reason) => Err(reason),
        };
        match result {
            Ok(()) => {
                gauges.published.fetch_add(1, Relaxed);
            }
            Err(reason) => gauges.failed(reason),
        }
    }
    if let Some(existing) = existing {
        for key in existing.difference(&desired) {
            match bounded(bucket.delete(key)).await {
                Ok(()) => {
                    gauges.published.fetch_add(1, Relaxed);
                }
                Err(reason) => gauges.failed(reason),
            }
        }
    }
}

#[cfg(test)]
mod tests;
