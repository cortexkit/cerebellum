use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use cortexkit_bus_naming::AccountNames;
use cortexkit_bus_nats::{ConnectConfig, NatsConnection};
use futures_util::{future::BoxFuture, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{sync::Mutex, time::Instant};

use crate::login_capture::vault::{ClaustrumVault, CookieVault};

use super::{notice, reply::decode_reply, Connection, Notice, Transport};

pub(crate) struct LiveTransport {
    management: Arc<ClaustrumVault>,
    credential: Mutex<Option<Credential>>,
}

#[derive(Clone, Deserialize)]
struct Credential {
    jwt: String,
    exp: u64,
    credential_public: String,
    inbox_prefix: String,
    server_url: String,
    acct: String,
    spawn_generation: u64,
    credential_epoch: u64,
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Credential {
    fn validate(&self) -> Result<(), String> {
        AccountNames::derive(&self.acct).map_err(|error| error.to_string())?;
        let config =
            ConnectConfig::new(&self.credential_public).map_err(|error| error.to_string())?;
        if self.jwt.is_empty()
            || self.exp <= now_seconds().saturating_add(60)
            || config.inbox_prefix() != self.inbox_prefix
            || self
                .server_url
                .strip_prefix("nats://127.0.0.1:")
                .and_then(|port| port.parse::<u16>().ok())
                .filter(|port| *port > 0)
                .is_none()
        {
            return Err("invalid ckbus credential".into());
        }
        Ok(())
    }
}

async fn management(
    transport: &ClaustrumVault,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    // A visible badge can outlive its inbound call. Its credential/signing
    // RPCs each have five seconds and own a separate daemon connection, which
    // is dropped with the reply or cancellation rather than held while idle.
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut route = transport
            .open()
            .await
            .map_err(|error| format!("{error:?}"))?;
        let body = serde_json::to_vec(&json!({"method": method, "params": params}))
            .map_err(|error| error.to_string())?;
        let response = route
            .call(&body)
            .await
            .map_err(|error| format!("{error:?}"))?;
        decode_reply(&response)
    })
    .await
    .map_err(|_| "ckbus deadline exceeded".to_owned())?
}

impl LiveTransport {
    pub(crate) fn new(connection_file: PathBuf, module: String) -> Self {
        Self {
            management: Arc::new(ClaustrumVault::management(connection_file, module, "ckbus")),
            credential: Mutex::new(None),
        }
    }

    async fn credential(&self) -> Result<Credential, String> {
        let mut prior = self.credential.lock().await;
        // A failed renewal must not leave a stale identity cached forever.
        // The next credential request asks ck-bus for a fresh credential.
        if let Some(previous) = prior.take() {
            match management(
                &self.management,
                "ckbus.credential_renew",
                json!({"credential_public": previous.credential_public}),
            )
            .await
            {
                Ok(reply) => {
                    let mut renewed = previous.clone();
                    if reply["credential_public"].as_str() != Some(&previous.credential_public)
                        || reply["spawn_generation"].as_u64() != Some(previous.spawn_generation)
                        || reply["credential_epoch"].as_u64() != Some(previous.credential_epoch)
                    {
                        return Err("ckbus renewal changed credential identity".into());
                    }
                    renewed.jwt = reply["jwt"].as_str().ok_or("missing JWT")?.to_owned();
                    renewed.exp = reply["exp"]
                        .as_u64()
                        .filter(|exp| *exp > previous.exp)
                        .ok_or("renewal did not extend expiry")?;
                    renewed.validate()?;
                    *prior = Some(renewed.clone());
                    return Ok(renewed);
                }
                Err(error)
                    if error.contains("ckbus_credential_superseded")
                        || error.contains("ckbus_credential_revoked") => {}
                Err(error) => return Err(error),
            }
        }
        // No credential survives a process run. Only ck-bus owns the private
        // signing key; the callback below asks it to sign the server's nonce.
        let reply = management(&self.management, "ckbus.credential", json!({})).await?;
        let credential: Credential = serde_json::from_value(reply)
            .map_err(|_| "invalid ckbus credential reply".to_owned())?;
        credential.validate()?;
        *prior = Some(credential.clone());
        Ok(credential)
    }
}

struct Task<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Transport for LiveTransport {
    fn open(&self) -> BoxFuture<'_, Result<Connection, String>> {
        Box::pin(async move {
            let credential = self.credential().await?;
            let rpc = self.management.clone();
            let public = credential.credential_public.clone();
            let jwt = credential.jwt.clone();
            let options = async_nats::ConnectOptions::with_auth_callback(move |nonce| {
                let rpc = rpc.clone();
                let public = public.clone();
                let jwt = jwt.clone();
                async move {
                    // NATS requires a Sync authentication future; the route's
                    // mutable request future is Send only. Its owned task is
                    // cancelled with the callback rather than left detached.
                    let mut request = Task(tokio::spawn(async move {
                        management(
                            &rpc,
                            "ckbus.nonce_sign",
                            json!({"credential_public": public, "nonce_b64": STANDARD.encode(nonce)}),
                        )
                        .await
                    }));
                    let reply = (&mut request.0)
                        .await
                        .map_err(|_| async_nats::AuthError::new("ckbus signing task stopped"))?
                        .map_err(async_nats::AuthError::new)?;
                    let signature = STANDARD
                        .decode(
                            reply["signature_b64"]
                                .as_str()
                                .ok_or_else(|| async_nats::AuthError::new("missing signature"))?,
                        )
                        .map_err(|_| async_nats::AuthError::new("invalid signature"))?;
                    if signature.len() != 64 {
                        return Err(async_nats::AuthError::new("invalid signature length"));
                    }
                    let mut auth = async_nats::Auth::new();
                    auth.jwt = Some(jwt);
                    auth.signature = Some(signature);
                    Ok(auth)
                }
            })
            .max_reconnects(0)
            .connection_timeout(Duration::from_secs(2));
            let connection = NatsConnection::connect(
                &credential.server_url,
                options,
                ConnectConfig::new(&credential.credential_public)
                    .map_err(|error| error.to_string())?,
            )
            .await
            .map_err(|error| error.to_string())?;
            let names =
                AccountNames::derive(&credential.acct).map_err(|error| error.to_string())?;
            let mut subscribers = Vec::new();
            for subject in notice::subjects(&names)? {
                subscribers.push(
                    connection
                        .subscribe(&subject)
                        .await
                        .map_err(|error| error.to_string())?,
                );
            }
            let (sender, notices) = tokio::sync::mpsc::channel(64);
            let reader = tokio::spawn(async move {
                // Keep the client with its subscribers so cancellation drops all
                // connection owners, not just one of the four subscriptions.
                let _connection = connection;
                let mut messages = futures_util::stream::select_all(subscribers);
                while let Some(message) = messages.next().await {
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
                refresh_at: Instant::now()
                    + Duration::from_secs(credential.exp.saturating_sub(now_seconds() + 60)),
                _guard: Box::new(Task(reader)),
            })
        })
    }
}
