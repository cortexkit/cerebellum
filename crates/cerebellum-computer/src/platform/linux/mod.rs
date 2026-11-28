//! Epoch-bound AT-SPI application and element identities.

use std::collections::HashSet;
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cerebellum_linux::atspi::{self, Attributes, Bus, Error, Object};
use cerebellum_linux::identity::{self, VerifiedApp};
use serde::{Deserialize, Serialize};

use super::{DriverError, ProcessGrant};
use crate::app_state::source::{ElementHandle, ElementToken, RawAppState, RawElement, ReadBounds};

mod actions;
pub mod launch;
mod scoped;
mod tree;

#[derive(Clone)]
pub struct Live {
    pub epoch: u64,
    pub bus: Bus,
}

/// The session selects the current bus and verifies the process generation and
/// executable. An accessibility peer's UI reports cannot prove its identity.
pub trait Session: Send + Sync {
    fn current(&self) -> Result<Live, &'static str>;
    fn prove(&self, pid: u32) -> Result<VerifiedApp, identity::Refusal>;
    fn reprove(
        &self,
        pid: u32,
        generation: &str,
        subject: &str,
    ) -> Result<VerifiedApp, identity::Refusal>;
}

#[derive(Clone)]
pub struct Source(pub Arc<dyn Session>);

#[derive(Deserialize, Serialize)]
struct Binding {
    epoch: u64,
    peer: String,
    generation: String,
}

impl Binding {
    fn decode(evidence: &str) -> Result<Self, &'static str> {
        evidence
            .strip_prefix("atspi:")
            .and_then(|body| serde_json::from_str(body).ok())
            .ok_or("stale_reference")
    }

    fn root(&self) -> Object {
        Object {
            peer: self.peer.clone(),
            path: atspi::ROOT.to_owned(),
        }
    }
}

pub fn kernel_generation(evidence: &str) -> String {
    Binding::decode(evidence).map_or_else(|_| evidence.to_owned(), |binding| binding.generation)
}

#[derive(Debug, Clone)]
struct Token {
    object: Object,
    grant: ProcessGrant,
    raw_role: Option<(u32, String)>,
    attributes: Option<Attributes>,
}

impl ElementToken for Token {
    fn same_element(&self, other: &dyn ElementToken) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.grant == other.grant && self.object == other.object)
    }

    fn identity_hash(&self) -> u64 {
        let mut hash = DefaultHasher::new();
        self.grant.pid.hash(&mut hash);
        self.grant.bundle_identity.hash(&mut hash);
        self.grant.process_generation_evidence.hash(&mut hash);
        self.object.hash(&mut hash);
        hash.finish()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

const QUERY_LIMIT: Duration = Duration::from_millis(500);
const STALE: &str = "stale_reference";
const UNREADABLE: &str = "accessibility_tree_unavailable";

fn reason(error: Error) -> &'static str {
    match error {
        Error::Stale => STALE,
        Error::Unreadable | Error::Timeout => UNREADABLE,
    }
}

#[derive(Debug)]
pub struct Application {
    pub name: String,
    pub pid: u32,
    pub proof: Result<VerifiedApp, identity::Refusal>,
    pub grant: Option<ProcessGrant>,
}

struct Open {
    live: Live,
    root: Object,
    app: VerifiedApp,
}

impl Source {
    pub fn inventory(&self) -> Result<Vec<Application>, &'static str> {
        let live = self.0.current()?;
        let entries = atspi::bounded(Instant::now() + ReadBounds::default().timeout, async {
            let mut entries = Vec::new();
            let mut seen = HashSet::new();
            for root in live.bus.applications().await? {
                if !seen.insert(root.clone()) {
                    continue;
                }
                let Ok(pid) = live.bus.pid(&root).await else {
                    continue;
                };
                let proof = self.0.prove(pid);
                let name = live.bus.name(&root).await.unwrap_or_default();
                let grant = proof.as_ref().ok().map(|app| ProcessGrant {
                    pid,
                    bundle_identity: app.subject.clone(),
                    process_generation_evidence: format!(
                        "atspi:{}",
                        serde_json::to_string(&Binding {
                            epoch: live.epoch,
                            peer: root.peer,
                            generation: app.generation_evidence(),
                        })
                        .expect("binding contains only primitive values")
                    ),
                });
                let name = if name.trim().is_empty() {
                    proof
                        .as_ref()
                        .ok()
                        .and_then(|app| app.path.file_name())
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default()
                } else {
                    name
                };
                entries.push(Application {
                    name,
                    pid,
                    proof,
                    grant,
                });
            }
            Ok(entries)
        })
        .map_err(reason)?;
        self.same_epoch(live.epoch)?;
        Ok(entries)
    }

    fn same_epoch(&self, epoch: u64) -> Result<(), &'static str> {
        if self.0.current()?.epoch != epoch {
            return Err(STALE);
        }
        Ok(())
    }

    fn open(&self, grant: &ProcessGrant, deadline: Instant) -> Result<Open, &'static str> {
        let binding = Binding::decode(&grant.process_generation_evidence)?;
        let live = self.0.current()?;
        if live.epoch != binding.epoch {
            return Err(STALE);
        }
        let root = binding.root();
        let actual_pid = atspi::bounded(deadline, live.bus.pid(&root)).map_err(reason)?;
        if actual_pid != grant.pid {
            return Err(STALE);
        }
        let app = self
            .0
            .reprove(grant.pid, &binding.generation, &grant.bundle_identity)
            .map_err(|e| e.reason())?;
        Ok(Open { live, root, app })
    }

    pub fn verify(&self, grant: &ProcessGrant) -> Result<(), &'static str> {
        let open = self.open(grant, Instant::now() + QUERY_LIMIT)?;
        self.same_epoch(open.live.epoch)
    }

    pub fn bound_display_name(&self, grant: &ProcessGrant) -> Result<String, &'static str> {
        let deadline = Instant::now() + QUERY_LIMIT;
        let open = self.open(grant, deadline)?;
        let name = atspi::bounded(deadline, open.live.bus.name(&open.root))
            .ok()
            .filter(|name| !name.trim().is_empty());
        self.same_epoch(open.live.epoch)?;
        Ok(open.app.display_name(name.as_deref()))
    }

    pub fn token_grant(element: &ElementHandle) -> Option<&ProcessGrant> {
        element
            .as_any()
            .downcast_ref::<Token>()
            .map(|token| &token.grant)
    }

    fn resolve_token<'a>(
        &self,
        element: &'a ElementHandle,
        deadline: Instant,
    ) -> Result<(&'a Token, Open), &'static str> {
        let token = element.as_any().downcast_ref::<Token>().ok_or(STALE)?;
        let open = self.open(&token.grant, deadline)?;
        if token.object.peer != open.root.peer {
            return Err(STALE);
        }
        Ok((token, open))
    }

    pub fn read_tree(
        &self,
        target: &ProcessGrant,
        element: Option<&ElementHandle>,
        bounds: ReadBounds,
    ) -> Result<RawAppState, &'static str> {
        let deadline = Instant::now() + bounds.timeout;
        let open = self.open(target, deadline)?;
        let object = if let Some(handle) = element {
            let token = handle.as_any().downcast_ref::<Token>().ok_or(STALE)?;
            if &token.grant != target || token.object.peer != open.root.peer {
                return Err(STALE);
            }
            &token.object
        } else {
            &open.root
        };
        let state = atspi::bounded(
            deadline,
            tree::read(&open, target, object, element.is_some(), bounds),
        )
        .map_err(reason)?;
        self.same_epoch(open.live.epoch)?;
        Ok(state)
    }

    pub fn driver_error(reason: &'static str) -> DriverError {
        DriverError::StartupRefused(reason)
    }
}

type NodeFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<RawElement>, Error>> + 'a>>;
