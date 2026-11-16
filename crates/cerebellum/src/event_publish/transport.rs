//! The shared client owns credentials only while a publish connection is live.

use std::path::PathBuf;

use cortexkit_bus_client::{BusClient, BusClientOptions};
use subc_client_rs::{consumer::ConsumerOptions, SubcConsumer};

use super::*;

pub(crate) struct BusTransport {
    pub(crate) connection_file: PathBuf,
}

struct BusConnection {
    client: BusClient,
}

impl Transport for BusTransport {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn Connection>, Failure>> {
        Box::pin(async move {
            let subc = SubcConsumer::connect(&self.connection_file, ConsumerOptions::default())
                .await
                .map_err(|_| Failure::Unavailable)?;
            let options = BusClientOptions::new("cerebellum").map_err(|_| Failure::Unavailable)?;
            let client = BusClient::connect(Arc::new(subc), options)
                .await
                .map_err(|_| Failure::Unavailable)?;
            Ok(Box::new(BusConnection { client }) as Box<dyn Connection>)
        })
    }
}

impl Connection for BusConnection {
    fn views_bucket(&self) -> Result<Box<dyn views::Bucket>, Failure> {
        let bucket = self
            .client
            .bucket("cerebellum", "views")
            .map_err(|_| Failure::Unavailable)?;
        Ok(Box::new(bucket))
    }

    fn publish<'a>(
        &'a mut self,
        kind: &'a Kind,
        message_id: &'a str,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let _ = kind.subject(self.client.acct())?;
            let (event, version, reader) = kind.parts();
            let _receipt = self
                .client
                .publish_event(event, version, reader, message_id, bytes.to_vec())
                .await
                .map_err(|_| Failure::Unavailable)?;
            Ok(())
        })
    }
}

impl views::Bucket for cortexkit_bus_client::Bucket {
    fn watch(&self) -> BoxFuture<'_, Result<Box<dyn views::Snapshot>, Failure>> {
        Box::pin(async move {
            let watch = self.watch().await.map_err(|_| Failure::Unavailable)?;
            Ok(Box::new(watch) as Box<dyn views::Snapshot>)
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, Failure>> {
        Box::pin(async move {
            self.get(key)
                .await
                .map(|entry| entry.map(|entry| entry.value.to_vec()))
                .map_err(|_| Failure::Unavailable)
        })
    }

    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.put(key, bytes.to_vec())
                .await
                .map(|_| ())
                .map_err(|_| Failure::Unavailable)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.delete(key)
                .await
                .map(|_| ())
                .map_err(|_| Failure::Unavailable)
        })
    }
}

impl views::Snapshot for cortexkit_bus_client::BucketWatch {
    fn next(&mut self) -> BoxFuture<'_, Result<views::SnapshotItem, Failure>> {
        Box::pin(async move {
            loop {
                match self.next().await.map_err(|_| Failure::Unavailable)? {
                    cortexkit_bus_client::BucketItem::Put { key, .. } => {
                        return Ok(views::SnapshotItem::Key(key));
                    }
                    cortexkit_bus_client::BucketItem::CaughtUp => {
                        return Ok(views::SnapshotItem::CaughtUp);
                    }
                    cortexkit_bus_client::BucketItem::Delete { .. } => {}
                    _ => return Err(Failure::Unavailable),
                }
            }
        })
    }
}
