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
