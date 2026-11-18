use std::{path::PathBuf, sync::Arc};

use cortexkit_bus_client::{BusClient, BusClientOptions};
use cortexkit_bus_naming::AccountNames;
use futures_util::{future::BoxFuture, StreamExt};
use subc_client_rs::{consumer::ConsumerOptions, SubcConsumer};

use super::{notice, Connection, Notice, OpenFailure, Transport};

pub(crate) struct LiveTransport {
    connection_file: PathBuf,
    module: String,
}

impl LiveTransport {
    pub(crate) fn new(connection_file: PathBuf, module: String) -> Self {
        Self {
            connection_file,
            module,
        }
    }
}

struct Reader(tokio::task::JoinHandle<()>);

impl Drop for Reader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Transport for LiveTransport {
    fn open(&self) -> BoxFuture<'_, Result<Connection, OpenFailure>> {
        Box::pin(async move {
            // Like the event publisher, let the SDK authenticate the daemon
            // socket with this module's registration claim. Sharing its bus
            // credential manager avoids revoking a still-connected publisher.
            let subc = SubcConsumer::connect(&self.connection_file, ConsumerOptions::default())
                .await
                .map_err(|_| OpenFailure::Unavailable)?;
            let options =
                BusClientOptions::new(&self.module).map_err(|_| OpenFailure::Unavailable)?;
            let client = BusClient::connect(Arc::new(subc), options)
                .await
                .map_err(|_| OpenFailure::Unavailable)?;
            let names =
                AccountNames::derive(client.acct()).map_err(|_| OpenFailure::Unavailable)?;
            let mut changes = client.connection_changes();
            let connection = client.connection();
            let mut subscribers = Vec::new();
            for subject in notice::subjects(&names).map_err(|_| OpenFailure::Unavailable)? {
                subscribers.push(
                    connection
                        .subscribe(&subject)
                        .await
                        .map_err(|_| OpenFailure::Unavailable)?,
                );
            }
            let (sender, notices) = tokio::sync::mpsc::channel(64);
            let reader = tokio::spawn(async move {
                // Raw subscriptions stay on their original socket. A credential
                // rotation or failed renewal ends this reader so the listener
                // can reopen while a cursor badge or preview is still visible.
                let _client = client;
                let mut messages = futures_util::stream::select_all(subscribers);
                loop {
                    let message = tokio::select! {
                        _ = changes.changed() => break,
                        message = messages.next() => message,
                    };
                    let Some(message) = message else { break };
                    let Some(headers) = message.headers.as_ref() else {
                        continue;
                    };
                    let header = |name: &str| headers.get_last(name).map(|value| value.as_str());
                    if let Some(notice) = Notice::parse(
                        &names,
                        message.subject.as_str(),
                        header(notice::KEY_HEADER),
                        header("agent"),
                        header("session_ref"),
                    ) {
                        if sender.send(notice).await.is_err() {
                            break;
                        }
                    }
                }
            });
            Ok(Connection {
                notices,
                refresh_at: None,
                _guard: Box::new(Reader(reader)),
            })
        })
    }
}
