//! A scripted Cingulate for the client's wire tests.
//!
//! Each test queues the replies Cingulate would give, in order, by method.
//! Replies are taken from the copied `consent-requester-v2` vectors wherever
//! the contract publishes one, so the client is tested against Cingulate's
//! own served bytes rather than against shapes written here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use super::live_call::LiveCall;
use super::route::{BoxFuture, CallError, CingulateOpener, CingulateRoute};
use super::wire::{Refusal, RefusalCode};

pub const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/consent-requester-v2"
);

/// A copied vector file, parsed.
pub fn vector(name: &str) -> Value {
    let path = std::path::Path::new(VECTORS).join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The `result` member of a copied reply vector.
pub fn vector_result(name: &str) -> Value {
    vector(name)["result"].clone()
}

/// The reply a copied vector file holds, as the scripted Cingulate gives it:
/// a success reply's `result`, or a refusal file's exact Error frame body,
/// read through the same parser the production route uses.
pub fn vector_reply(name: &str) -> Reply {
    let reply = vector(name);
    match reply.get("result") {
        Some(result) => Reply::Result(result.clone()),
        None => Reply::ErrorBody(std::fs::read(std::path::Path::new(VECTORS).join(name)).unwrap()),
    }
}

/// The four replies Cingulate served for `consent.detach`, by what each
/// shows: a pending card now detached, a card that had already settled (the
/// vector's card id is `el_2`, not the `el_1` the other vectors use), a
/// second detach of the same pending card, and a card of another owner.
pub const DETACH_PENDING: &str = "cerebellum-detach-pending-reply.json";
pub const DETACH_SETTLED: &str = "cerebellum-detach-settled-reply.json";
pub const DETACH_REPEAT: &str = "cerebellum-detach-repeat-reply.json";
pub const DETACH_WRONG_OWNER: &str = "cerebellum-detach-wrong-owner-refusal.json";

/// One reply the scripted Cingulate gives to a call, in place of a real
/// Cingulate response.
pub enum Reply {
    Result(Value),
    Refused(&'static str),
    /// An Error frame with exactly this body, as a refusal vector holds it.
    ErrorBody(Vec<u8>),
    Transport,
    /// Never answers: the call waits until the caller stops waiting.
    Hang,
    /// Signal that the call started, then wait for the test to supply its reply.
    Controlled {
        called: tokio::sync::oneshot::Sender<()>,
        reply: tokio::sync::oneshot::Receiver<Value>,
    },
}

/// How a test ends a card it has a scripted Cingulate hold, in the terms a
/// person or Cingulate would end it. Each test fixture turns this into the
/// record or refusal Cingulate gives for that ending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedAnswer {
    /// The person chose an option. The body is `{"decision": <option id>}`,
    /// and the option id becomes the record's `answered_choice_id`.
    Answered(Value),
    /// The card expired with nobody answering it.
    NoAnswer,
    /// Cingulate refused to put the card to anyone.
    NotPutToAnyone,
    /// The card or its answer could not be carried.
    Undeliverable,
}

pub fn refusal(code: &str) -> CallError {
    CallError::Refused(Refusal {
        code: RefusalCode::parse(code),
        message: format!("scripted {code}"),
    })
}

#[derive(Default)]
pub struct ScriptedCingulate {
    pub opens: AtomicUsize,
    pub calls: Mutex<Vec<(String, Value)>>,
    scopes: Mutex<Vec<subc_protocol::scope::ScopeSelector>>,
    script: Mutex<VecDeque<(&'static str, Reply)>>,
    /// When set, refuse every route.open with this daemon code, as a daemon
    /// would when core has not listed cerebellum as a carrier (a module
    /// allowed to open routes) of the agent's session scope
    /// (`scope_not_carrier`), or when that scope has ended (`scope_ended`).
    pub refuse_open: Mutex<Option<&'static str>>,
}

impl ScriptedCingulate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn then(self: &Arc<Self>, method: &'static str, reply: Reply) -> &Arc<Self> {
        self.script.lock().unwrap().push_back((method, reply));
        self
    }

    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }

    pub fn methods(&self) -> Vec<String> {
        self.calls().into_iter().map(|(method, _)| method).collect()
    }

    pub fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    pub fn scopes(&self) -> Vec<subc_protocol::scope::ScopeSelector> {
        self.scopes.lock().unwrap().clone()
    }
}

struct ScriptedRoute(Arc<ScriptedCingulate>);

impl CingulateOpener for Arc<ScriptedCingulate> {
    fn open<'a>(
        &'a self,
        live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        Box::pin(async move {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.scopes.lock().unwrap().push(live.scope().clone());
            if let Some(code) = *self.refuse_open.lock().unwrap() {
                return Err(CallError::Transport {
                    code: Some(code.into()),
                });
            }
            Ok(Box::new(ScriptedRoute(Arc::clone(self))) as Box<dyn CingulateRoute>)
        })
    }
}

impl CingulateRoute for ScriptedRoute {
    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, CallError>> {
        Box::pin(async move {
            self.0
                .calls
                .lock()
                .unwrap()
                .push((method.to_string(), params));
            let next = self.0.script.lock().unwrap().pop_front();
            let Some((expected, reply)) = next else {
                panic!("the script has no reply left for {method}");
            };
            assert_eq!(method, expected, "the client sent an unscripted method");
            match reply {
                Reply::Result(value) => Ok(value),
                Reply::Refused(code) => Err(refusal(code)),
                Reply::ErrorBody(body) => Err(Refusal::from_error_body(&body)
                    .map_or(CallError::Transport { code: None }, CallError::Refused)),
                Reply::Transport => Err(CallError::Transport { code: None }),
                Reply::Hang => std::future::pending().await,
                Reply::Controlled { called, reply } => {
                    called.send(()).expect("the test is waiting for the call");
                    Ok(reply.await.expect("the test supplies the reply"))
                }
            }
        })
    }
}
