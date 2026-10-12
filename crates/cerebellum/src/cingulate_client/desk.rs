//! Raising cards with Cingulate and reading their answers, for one held call.
//!
//! The rules this file keeps:
//!
//! - A route is opened only through [`ConsentDesk::session`], and only while
//!   the [`LiveCall`] it is given is still held.
//! - A held call waits on its card in place for at most the park limit. If
//!   the card has not settled by then, the card is detached
//!   (`consent.detach`) at the moment the call stops holding it, so a later
//!   answer reaches the agent through Cingulate's notice to core and is read
//!   by cerebellum on the agent's next call, never twice.
//! - Every answer cerebellum acts on belongs to a card cerebellum raised on
//!   the same session, found in its registry by elicitation id. An answer in
//!   the feed for any other card is ignored.
//! - A settlement read from the answers feed is acknowledged only after it
//!   was applied and the registry saying so was stored, so a crash between
//!   the two re-reads it and applies it again, idempotently, rather than
//!   losing it.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::card::{CardKind, CardRequest};
use super::live_call::{LiveCall, NotLive, SessionKey};
use super::route::{CallError, CingulateOpener, CingulateRoute};
use super::wire::{self, CardState, Execution, Record, RefusalCode};

/// How a card ended, from the point of view of the code that raised it.
///
/// The same endings the reverse elicitation lane reported, kept as separate
/// variants because callers must treat them differently: a refusal is a
/// decision, silence may be answered next time, a card nobody was shown
/// never will be, and a delivery failure is this side's fault and worth
/// retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// The operator chose one of the card's granting options.
    Granted { choice_id: String },
    /// The operator chose the decline, or a choice this card did not offer as
    /// a grant (read as not consent).
    Declined { choice_id: String },
    /// The card expired unanswered, or is no longer retained.
    NoAnswer,
    /// Cingulate will not put the card to anyone, and asking again goes the
    /// same way until something outside cerebellum changes: cerebellum is not
    /// an admitted requester for this kind, Cingulate refuses a card without
    /// a safe default, or the agent is retired.
    NotPutToAnyone,
    /// The card or its answer could not be carried: no route, a transport
    /// failure, the consent module being unavailable, or cerebellum building
    /// a card Cingulate cannot accept (a defect on this side, not an
    /// unreachable person). Retry once; if it fails again the module needs
    /// attention.
    DeliveryFailed,
    /// Cerebellum withdrew the card.
    Withdrawn,
    /// No card could be raised for this call at all, for a reason that is
    /// not about Cingulate or the person: see [`NoCard`].
    NoCard(NoCard),
}

/// Why no card can be raised for a call. Each is one row of the
/// `consent_unavailable` reply the flows give, with its own reason and
/// remedy, and in none of them is a route to Cingulate used to ask anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCard {
    /// The call came from no agent session that could raise a card: an
    /// unscoped route (every operator `direct` route), a scope naming no
    /// agent, or a caller the session admission does not admit.
    NoAgentSession,
    /// The daemon refused the route because core does not list cerebellum
    /// as a carrier of the agent's session scope (`scope_not_carrier`).
    NotACarrier,
    /// The daemon refused the route because the session's scope has ended
    /// (`scope_ended`).
    ScopeEnded,
    /// The registry of raised cards on disk is newer than this build reads,
    /// or damaged. Raising a card would mean saving over it, so none is
    /// raised.
    RegistryUnreadable,
    /// The call is no longer held: its reply was already decided or its
    /// route unbound, so there is nobody to reply to.
    CallEnded,
}

impl NoCard {
    /// The reason for a call that `LiveCall` refused ([`NotLive`]): an
    /// unscoped call or one naming no agent has no agent session to raise
    /// the card for, and an ended call has nobody to reply to.
    pub fn of_not_live(not_live: NotLive) -> Self {
        match not_live {
            NotLive::Unscoped | NotLive::NoAgent => Self::NoAgentSession,
            NotLive::CallEnded => Self::CallEnded,
        }
    }

    /// The `reason` the reply carries. `None` for [`NoCard::CallEnded`],
    /// whose call sends no reply about the card.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::NoAgentSession => Some("no_agent_session"),
            Self::NotACarrier => Some("not_a_carrier"),
            Self::ScopeEnded => Some("scope_ended"),
            Self::RegistryUnreadable => Some("consent_registry_unreadable"),
            Self::CallEnded => None,
        }
    }

    /// What the agent can do about it. `None` for [`NoCard::CallEnded`].
    pub fn remedy(self) -> Option<&'static str> {
        match self {
            Self::NoAgentSession => {
                Some("call from the agent session that needs the permission; it can raise the card")
            }
            Self::NotACarrier => {
                Some("the agent session does not list cerebellum as a carrier; restart the session")
            }
            Self::ScopeEnded => Some("this session has ended; call from the current session"),
            Self::RegistryUnreadable => {
                Some("the consent registry file is newer or damaged; update cerebellum")
            }
            Self::CallEnded => None,
        }
    }
}

/// The daemon's refusal codes for opening the route to Cingulate that mean
/// no card can be raised in this session at all, so they map to their own
/// [`NoCard`] reason instead of a retryable delivery failure. Any other
/// refusal of the open is a delivery failure.
const OPEN_REFUSED_NOT_CARRIER: &str = "scope_not_carrier";
const OPEN_REFUSED_SCOPE_ENDED: &str = "scope_ended";

impl Ending {
    /// The ending a failed call to Cingulate stands for: a refusal of
    /// `consent.request`, `consent.await`, `consent.get` or another method,
    /// a refused or failed route open, or a call that could not open one.
    pub fn of_refusal(error: &CallError) -> Self {
        match error {
            CallError::NotLive => Self::NoCard(NoCard::CallEnded),
            CallError::RegistryUnreadable => Self::NoCard(NoCard::RegistryUnreadable),
            CallError::Transport { code: Some(code) } if code == OPEN_REFUSED_NOT_CARRIER => {
                Self::NoCard(NoCard::NotACarrier)
            }
            CallError::Transport { code: Some(code) } if code == OPEN_REFUSED_SCOPE_ENDED => {
                Self::NoCard(NoCard::ScopeEnded)
            }
            CallError::Transport { .. } => Self::DeliveryFailed,
            CallError::Refused(refusal) => match refusal.code {
                RefusalCode::RequesterRefused
                | RefusalCode::FailClosedRequired
                | RefusalCode::ConsentRetired => Self::NotPutToAnyone,
                // Cerebellum built a card Cingulate cannot decode or accept:
                // a defect here, which telling the agent "nobody is
                // reachable" would hide.
                RefusalCode::InvalidRequest
                | RefusalCode::UnknownKind
                | RefusalCode::RequestTooLarge
                | RefusalCode::InvalidEnvelope => Self::DeliveryFailed,
                // The card is gone from this requester's view: acknowledged,
                // past retention, or not this session's. Nothing can be
                // concluded about a choice.
                RefusalCode::NotOwner | RefusalCode::NotFound => Self::NoAnswer,
                RefusalCode::UnknownMethod
                | RefusalCode::ConsentUnavailable
                | RefusalCode::StoreError
                | RefusalCode::Cancelled
                | RefusalCode::InvalidExecution
                | RefusalCode::Unknown(_) => Self::DeliveryFailed,
            },
        }
    }

    /// The ending a settled record stands for, read against the card it
    /// answers. `None` while the card is still pending.
    pub fn of_record(record: &Record, card: &RaisedCard) -> Option<Self> {
        Some(match record.state {
            CardState::Pending => return None,
            CardState::Answered => match record.answered_choice_id.clone() {
                Some(choice_id) if card.grant_ids.contains(&choice_id) => {
                    Self::Granted { choice_id }
                }
                Some(choice_id) => Self::Declined { choice_id },
                None => Self::NoAnswer,
            },
            CardState::Expired | CardState::Other(_) => Self::NoAnswer,
            CardState::Withdrawn => Self::Withdrawn,
        })
    }
}

/// How a held call's wait on its card ended.
///
/// A settlement is only reported here, never marked applied: the flow that
/// holds the card decides whether this call or another one (a second call
/// joined to the same card, or the session's next-call drain) acts on it,
/// and the one that does calls [`ConsentDesk::mark_applied`] after storing
/// the effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InCall {
    /// The card settled while the call held it: answer in the call.
    Settled(Ending),
    /// The call stops holding the card unsettled. The card was detached, so
    /// Cingulate notifies the agent when it settles, and the session's next
    /// call applies the answer.
    Pending { ask_id: String },
    /// The call was cancelled while it waited; the card was detached or
    /// withdrawn as the cancel asked (see [`LetGo`]).
    Cancelled,
    /// The call's route unbound while it waited; the card was withdrawn.
    RouteClosed,
}

/// What a cancelled call does with the card it holds, chosen by whoever
/// cancels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LetGo {
    /// The conversation is still bound, so the agent may still want the
    /// answer: the card is detached and stays answerable, and its answer
    /// reaches the agent as a late answer.
    Detach,
    /// Nobody is left to want the answer (the conversation is gone, the
    /// session said goodbye, or the module is draining): the card is
    /// withdrawn.
    Withdraw,
}

/// What `consent.detach` did.
#[derive(Debug, Clone, PartialEq)]
pub enum Detach {
    /// The card is pending and now detached: a later settlement produces a
    /// notice to the agent. Detaching an already detached card says the same.
    Detached(Record),
    /// The card had already settled; no notice will ever be sent for it.
    AlreadySettled(Record),
    /// The card stays open but was not detached (the consent module answered
    /// `unknown_method`, or a pending record without the detached mark), so
    /// no notice would come for it. Callers withdraw such a card and end the
    /// call as [`Ending::DeliveryFailed`]: there is no way to promise the
    /// agent its answer.
    NotDetached,
}

impl Detach {
    /// What a `consent.detach` reply says, read as the parsed record or the
    /// failure of the call.
    pub fn of_reply(reply: Result<Record, CallError>) -> Result<Self, Ending> {
        match reply {
            Ok(record) if record.is_settled() => Ok(Self::AlreadySettled(record)),
            Ok(record) if record.detached => Ok(Self::Detached(record)),
            // A pending record without `detached: true` means Cingulate did
            // not detach the card, so the agent cannot be promised the notice
            // Cingulate sends when a detached card settles.
            Ok(_) => Ok(Self::NotDetached),
            // A consent module that does not implement `consent.detach`
            // refuses it as an unknown method: the card stays open, not
            // detached.
            Err(CallError::Refused(refusal)) if refusal.code == RefusalCode::UnknownMethod => {
                Ok(Self::NotDetached)
            }
            Err(error) => Err(Ending::of_refusal(&error)),
        }
    }
}

/// A card cerebellum raised, remembered until its settlement has been applied
/// and acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaisedCard {
    pub elicitation_id: String,
    pub session: SessionKey,
    pub kind: CardKind,
    /// What the card is about, in the raising code's own terms (an app's
    /// bundle identity, a login's parameters): the key a later call looks
    /// its answer up by.
    pub subject: String,
    pub grant_ids: Vec<String>,
    pub decline_id: String,
    pub next_steps: BTreeMap<String, String>,
    /// The settlement has been applied; only its acknowledgment is left.
    pub applied: bool,
}

/// Where the registry of raised cards is kept across restarts.
pub trait RegistryStore: Send + Sync {
    /// Read the whole registry. A registry never written reads as empty. An
    /// error means the stored registry exists but cannot be read (a newer
    /// version, or damaged); the desk then raises no cards and never saves
    /// over it.
    fn load(&self) -> Result<Vec<RaisedCard>, String>;
    /// Store the whole registry. An error means the change may not survive
    /// a restart, so nothing that depends on it is acknowledged.
    fn save(&self, cards: &[RaisedCard]) -> Result<(), String>;
}

/// The registry file's name under the module's journal directory.
pub const CINGULATE_RAISED_FILE: &str = "cingulate_raised.json";

/// The highest registry file version this build reads, and the one it
/// writes.
pub const CINGULATE_RAISED_VERSION: u64 = 1;

/// The registry file's durable format (name and version). Every format this
/// module writes is recorded in the operator's format-floor file before its
/// first write; installing a new build compares the floors against what that
/// build can read (`durable_formats::readable_formats`) and refuses a build
/// that could not read a file already on disk.
pub const CINGULATE_RAISED_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new("cingulate-raised", CINGULATE_RAISED_VERSION);

/// The registry file's contents: its version, read before anything else so
/// a file from a newer build is refused rather than misread.
#[derive(Serialize, Deserialize)]
struct RegistryFile {
    version: u64,
    cards: Vec<RaisedCard>,
}

/// The registry in one JSON file, replaced atomically on every save.
pub struct FileRegistryStore {
    path: std::path::PathBuf,
    floor: cerebellum_core::format_floor::FormatFloor,
}

static TEMPORARY_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl FileRegistryStore {
    /// A registry file at `path`, raising the format floor that governs
    /// where it is: the operator's floor under the module's data directory,
    /// none for a file anywhere else (a test's scratch directory).
    pub fn new(path: std::path::PathBuf) -> Self {
        let floor = cerebellum_core::format_floor::FormatFloor::governing(&path);
        Self { path, floor }
    }

    /// Raise `floor` instead of the one chosen from the file's location.
    pub fn with_format_floor(mut self, floor: cerebellum_core::format_floor::FormatFloor) -> Self {
        self.floor = floor;
        self
    }

    /// The operator's registry, beside the audit journal.
    pub fn production() -> Result<Self, String> {
        cerebellum_core::journal::journal_data_path(CINGULATE_RAISED_FILE)
            .map(Self::new)
            .map_err(|error| format!("{error:?}"))
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl RegistryStore for FileRegistryStore {
    fn load(&self) -> Result<Vec<RaisedCard>, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            // Never written: no card has been raised on this machine.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        let version = value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or("the registry file has no version")?;
        if !(1..=CINGULATE_RAISED_VERSION).contains(&version) {
            return Err(format!(
                "the registry file is version {version}; this build reads up to {CINGULATE_RAISED_VERSION}"
            ));
        }
        let file: RegistryFile =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        Ok(file.cards)
    }

    fn save(&self, cards: &[RaisedCard]) -> Result<(), String> {
        use std::io::Write;

        // The format floor is raised here, before the first write, not at
        // startup: until a card is raised no file in this format exists, so
        // rolling back to a build without it stays a plain binary swap. Once
        // the file is written, the floor must record its format, or the
        // install-time check could accept a build that cannot read it.
        self.floor
            .raise(CINGULATE_RAISED_FORMAT)
            .map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec_pretty(&RegistryFile {
            version: CINGULATE_RAISED_VERSION,
            cards: cards.to_vec(),
        })
        .map_err(|error| error.to_string())?;
        let directory = self
            .path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        cerebellum_core::private_fs::create_dir_all(&directory)
            .map_err(|error| error.to_string())?;
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| CINGULATE_RAISED_FILE.to_string());
        let temporary = directory.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        // Written beside the target and renamed over it, so a crash mid-write
        // leaves either the old registry or the new one, never half of one.
        let written = (|| {
            let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, &self.path)?;
            if let Ok(directory) = std::fs::File::open(&directory) {
                let _ = directory.sync_all();
            }
            Ok::<(), std::io::Error>(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        written.map_err(|error| error.to_string())
    }
}

/// The application of one settlement failed; it is not acknowledged, and is
/// read and applied again on a later call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyFailed(pub String);

/// What applying one settlement from the answers feed did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    /// The effect is stored.
    Applied,
    /// The flow holds no record that could carry the effect (it was kept
    /// only in memory and lost in a restart), so nothing was done. The
    /// settlement is still acknowledged, so it is not read again, and no
    /// grant is ever made from it.
    NoRecord,
}

/// What one pass over the answers feed did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Settlements applied in this pass, by elicitation id.
    pub applied: Vec<String>,
    /// Settlements of this session's cards that the flow had no record for
    /// ([`Apply::NoRecord`]): acknowledged without any effect.
    pub without_effect: Vec<String>,
    /// Settlements of cards cerebellum did not raise on this session, which
    /// were not applied.
    pub ignored: Vec<String>,
    /// The cursor acknowledged, when the pass got that far.
    pub acked: Option<i64>,
}

/// Approvals of single-use cards (login import and capture) that arrived
/// after the raising call stopped waiting, keyed by session and subject. Each
/// waits for the agent's next call of the same tool with the same arguments,
/// which may act on it once.
#[derive(Default)]
struct SingleUse {
    approvals: HashMap<(SessionKey, String), (String, String)>,
}

/// Cerebellum's side of Cingulate: the opener and the registry of raised
/// cards.
pub struct ConsentDesk {
    opener: Arc<dyn CingulateOpener>,
    store: Option<Arc<dyn RegistryStore>>,
    /// False when the stored registry could not be read at startup. The desk
    /// then opens no route, raises no card, and never saves, so the file it
    /// could not read is left exactly as it was for a build that can.
    readable: bool,
    registry: Mutex<HashMap<String, RaisedCard>>,
    single_use: Mutex<SingleUse>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl ConsentDesk {
    /// A desk whose registry lives only in memory.
    pub fn new(opener: Arc<dyn CingulateOpener>) -> Self {
        Self {
            opener,
            store: None,
            readable: true,
            registry: Mutex::new(HashMap::new()),
            single_use: Mutex::new(SingleUse::default()),
        }
    }

    /// A desk whose registry is loaded from, and saved to, `store`. When the
    /// stored registry cannot be read, the desk is unusable: every
    /// [`ConsentDesk::session`] returns `CallError::RegistryUnreadable`.
    pub fn with_store(opener: Arc<dyn CingulateOpener>, store: Arc<dyn RegistryStore>) -> Self {
        let (readable, cards) = match store.load() {
            Ok(cards) => (
                true,
                cards
                    .into_iter()
                    .map(|card| (card.elicitation_id.clone(), card))
                    .collect(),
            ),
            Err(_) => (false, HashMap::new()),
        };
        Self {
            opener,
            store: Some(store),
            readable,
            registry: Mutex::new(cards),
            single_use: Mutex::new(SingleUse::default()),
        }
    }

    /// Open a route to Cingulate for `live`'s call.
    ///
    /// Returns `CallError::NotLive` without opening anything once the call is
    /// no longer held. The daemon admits this route only because core lists
    /// cerebellum as a carrier of the agent's session scope (allowed to open
    /// routes to Cingulate under it), and that permission exists for calls the
    /// agent is making, not for cerebellum acting on its own.
    ///
    /// Returns `CallError::RegistryUnreadable` without opening anything when
    /// the stored registry could not be read: a card raised now could not be
    /// remembered without saving over that file.
    pub async fn session<'a>(&'a self, live: &'a LiveCall) -> Result<DeskSession<'a>, CallError> {
        if !live.is_held() {
            return Err(CallError::NotLive);
        }
        if !self.readable {
            return Err(CallError::RegistryUnreadable);
        }
        let route = self.opener.open(live).await?;
        Ok(DeskSession {
            desk: self,
            live,
            route,
        })
    }

    /// The card cerebellum raised under `elicitation_id`, if it still holds it.
    pub fn raised(&self, elicitation_id: &str) -> Option<RaisedCard> {
        lock(&self.registry).get(elicitation_id).cloned()
    }

    /// The open card this session raised about `subject`, for a call that
    /// should wait on it rather than raise a second one.
    pub fn open_card_for(&self, session: &SessionKey, subject: &str) -> Option<RaisedCard> {
        lock(&self.registry)
            .values()
            .find(|card| !card.applied && card.session == *session && card.subject == subject)
            .cloned()
    }

    /// Every card this session raised whose settlement has not been applied,
    /// in no particular order. A session with none has nothing to read from
    /// the answers feed, so its call need not open a route to Cingulate.
    pub fn unapplied(&self, session: &SessionKey) -> Vec<RaisedCard> {
        lock(&self.registry)
            .values()
            .filter(|card| !card.applied && card.session == *session)
            .cloned()
            .collect()
    }

    /// Take, at most once, the single-use approval `drain_answers` recorded
    /// for `subject` on this session after the raising call had stopped
    /// waiting. Returns the card's elicitation id, which the calling retry
    /// reports its execution against with `report_execution`.
    pub fn take_single_use_approval(&self, session: &SessionKey, subject: &str) -> Option<String> {
        lock(&self.single_use)
            .approvals
            .remove(&(session.clone(), subject.to_string()))
            .map(|(elicitation_id, _choice)| elicitation_id)
    }

    fn record_single_use_approval(&self, card: &RaisedCard, choice_id: &str) {
        lock(&self.single_use).approvals.insert(
            (card.session.clone(), card.subject.clone()),
            (card.elicitation_id.clone(), choice_id.to_string()),
        );
    }

    fn save(&self) -> Result<(), String> {
        if !self.readable {
            // Never save over a registry this build could not read.
            return Err("the stored registry could not be read; it is not overwritten".into());
        }
        let Some(store) = &self.store else {
            return Ok(());
        };
        let cards: Vec<RaisedCard> = lock(&self.registry).values().cloned().collect();
        store.save(&cards)
    }

    /// Record that `elicitation_id`'s settlement has been acted on and its
    /// effect stored, then store the registry.
    ///
    /// Returns whether this call is the one that marked it: `Ok(false)` when
    /// it was already marked, or is not a card this desk holds. An error
    /// means the registry could not be stored, so the mark may not survive a
    /// restart and nothing that depends on it may be acknowledged.
    pub fn mark_applied(&self, elicitation_id: &str) -> Result<bool, String> {
        let flipped = match lock(&self.registry).get_mut(elicitation_id) {
            Some(card) if !card.applied => {
                card.applied = true;
                true
            }
            _ => false,
        };
        self.save().map(|()| flipped)
    }

    fn forget(&self, ids: &[String]) {
        {
            let mut registry = lock(&self.registry);
            for id in ids {
                registry.remove(id);
            }
        }
        let _ = self.save();
    }
}

/// One open route to Cingulate, for the life of one held call.
pub struct DeskSession<'a> {
    desk: &'a ConsentDesk,
    live: &'a LiveCall,
    route: Box<dyn CingulateRoute>,
}

/// What ended a held call's wait on its card.
enum Woke<C> {
    Read(Result<Record, CallError>),
    Cancelled(C),
    RouteClosed,
}

impl DeskSession<'_> {
    async fn record(&mut self, method: &str, params: Value) -> Result<Record, CallError> {
        let result = self.route.call(method, params).await?;
        Record::parse(result).ok_or(CallError::Transport { code: None })
    }

    /// Raise `card` about `subject` and remember it. Returns the card's
    /// elicitation id, the ask id the agent is given.
    pub async fn raise(&mut self, card: CardRequest, subject: &str) -> Result<String, Ending> {
        let result = self
            .route
            .call(wire::CONSENT_REQUEST, card.params.clone())
            .await
            .map_err(|error| Ending::of_refusal(&error))?;
        let elicitation_id = result
            .get("elicitation_id")
            .and_then(Value::as_str)
            .ok_or(Ending::DeliveryFailed)?
            .to_string();
        lock(&self.desk.registry).insert(
            elicitation_id.clone(),
            RaisedCard {
                elicitation_id: elicitation_id.clone(),
                session: self.live.session().clone(),
                kind: card.kind,
                subject: subject.to_string(),
                grant_ids: card.grant_ids,
                decline_id: card.decline_id,
                next_steps: card.next_steps,
                applied: false,
            },
        );
        // The save result is deliberately ignored: if it fails, the card is
        // missing from the stored registry and an answer arriving after a
        // restart would be ignored, but the card is raised either way, so an
        // answer given while this call waits is unaffected.
        let _ = self.desk.save();
        Ok(elicitation_id)
    }

    /// Raise `card` about `subject`, then detach it at once, without waiting
    /// on it: for cards asked ahead, whose call replies `consent_pending`
    /// straight away. Returns the elicitation id, the ask id the agent is
    /// given. The answer reaches the agent through Cingulate's notice and is
    /// applied on the session's next call.
    ///
    /// A card that could not be detached is withdrawn and the call ends
    /// [`Ending::DeliveryFailed`], since nothing would tell the agent it was
    /// answered. A card already settled by the time of the detach is returned
    /// like a detached one: its settlement waits in the answers feed for the
    /// next call.
    pub async fn raise_detached(
        &mut self,
        card: CardRequest,
        subject: &str,
    ) -> Result<String, Ending> {
        let elicitation_id = self.raise(card, subject).await?;
        match self.detach_or_withdraw(&elicitation_id).await? {
            Detach::Detached(_) | Detach::AlreadySettled(_) => Ok(elicitation_id),
            Detach::NotDetached => Err(Ending::DeliveryFailed),
        }
    }

    /// Wait on `elicitation_id` for at most `wait`, while also watching for
    /// the caller's cancellation and for the route the call arrived on
    /// unbinding.
    async fn wait_on<C>(
        &mut self,
        elicitation_id: &str,
        wait: Duration,
        cancelled: impl Future<Output = C>,
    ) -> Woke<C> {
        let live = self.live;
        let route_closed = async {
            while live.is_held() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        let timeout_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let waiting = self.record(
            wire::CONSENT_AWAIT,
            wire::await_params(elicitation_id, timeout_ms),
        );
        tokio::select! {
            read = waiting => Woke::Read(read),
            cancel = cancelled => Woke::Cancelled(cancel),
            () = route_closed => Woke::RouteClosed,
        }
    }

    /// Hold the call on the card for at most `park`, then either answer in
    /// the call or detach the card and report it pending.
    ///
    /// `cancelled` resolves when the caller cancels the call, saying whether
    /// the card is detached or withdrawn ([`LetGo`]). The route the call
    /// arrived on is watched too; its unbinding withdraws the card.
    ///
    /// A settlement returned here is not marked applied: the caller marks it
    /// with [`ConsentDesk::mark_applied`] once it has stored the effect, and
    /// only if it is the one that acts on it.
    pub async fn park(
        &mut self,
        elicitation_id: &str,
        park: Duration,
        cancelled: impl Future<Output = LetGo>,
    ) -> InCall {
        let Some(card) = self.desk.raised(elicitation_id) else {
            // Never wait on, and never act on, a card this desk did not raise.
            // Being asked to is a defect on this side.
            return InCall::Settled(Ending::DeliveryFailed);
        };
        if let Some(terminal) = crate::terminal_arbiter::TerminalArbiter::current() {
            terminal.set_step(crate::terminal_arbiter::CallStep::Consent);
        }
        let read = match self.wait_on(elicitation_id, park, cancelled).await {
            Woke::Read(read) => read,
            Woke::Cancelled(LetGo::Detach) => {
                let _ = self.detach_or_withdraw(elicitation_id).await;
                return InCall::Cancelled;
            }
            Woke::Cancelled(LetGo::Withdraw) => {
                let _ = self.withdraw(elicitation_id).await;
                return InCall::Cancelled;
            }
            Woke::RouteClosed => {
                let _ = self.withdraw(elicitation_id).await;
                return InCall::RouteClosed;
            }
        };
        let record = match read {
            Ok(record) => record,
            Err(error) => return InCall::Settled(Ending::of_refusal(&error)),
        };
        if let Some(ending) = Ending::of_record(&record, &card) {
            return InCall::Settled(ending);
        }
        match self.detach_or_withdraw(elicitation_id).await {
            Ok(Detach::Detached(_)) => InCall::Pending {
                ask_id: elicitation_id.to_string(),
            },
            Ok(Detach::AlreadySettled(record)) => {
                InCall::Settled(Ending::of_record(&record, &card).unwrap_or(Ending::NoAnswer))
            }
            Ok(Detach::NotDetached) => InCall::Settled(Ending::DeliveryFailed),
            Err(ending) => InCall::Settled(ending),
        }
    }

    /// Hold the call on the card for at most `wait` and never detach it: for
    /// a card whose answer is wanted only by this call (the user-browser site
    /// card, which expires as the wait ends).
    ///
    /// An answer is returned as [`InCall::Settled`] and left for the caller
    /// to mark applied, as with [`DeskSession::park`]. Anything else (the
    /// card still pending or expired when the wait ends, a failed await, the
    /// caller's cancellation, the route unbinding) withdraws the card and
    /// then forgets it whatever the withdrawal said, an `expired` readback
    /// included: no later call will ever act on it, so a stray record of it
    /// in the answers feed is ignored.
    pub async fn hold(
        &mut self,
        elicitation_id: &str,
        wait: Duration,
        cancelled: impl Future<Output = ()>,
    ) -> InCall {
        let Some(card) = self.desk.raised(elicitation_id) else {
            return InCall::Settled(Ending::DeliveryFailed);
        };
        if let Some(terminal) = crate::terminal_arbiter::TerminalArbiter::current() {
            terminal.set_step(crate::terminal_arbiter::CallStep::Consent);
        }
        let unanswered = match self.wait_on(elicitation_id, wait, cancelled).await {
            Woke::Read(Ok(record)) => match Ending::of_record(&record, &card) {
                Some(ending @ (Ending::Granted { .. } | Ending::Declined { .. })) => {
                    return InCall::Settled(ending)
                }
                Some(ending) => InCall::Settled(ending),
                // Still pending when the wait ended: the card is about to
                // expire, and nobody will wait on it again.
                None => InCall::Settled(Ending::NoAnswer),
            },
            Woke::Read(Err(error)) => InCall::Settled(Ending::of_refusal(&error)),
            Woke::Cancelled(()) => InCall::Cancelled,
            Woke::RouteClosed => InCall::RouteClosed,
        };
        let _ = self.withdraw(elicitation_id).await;
        self.desk.forget(&[elicitation_id.to_string()]);
        unanswered
    }

    /// Mark the moment cerebellum stops holding the call on `elicitation_id`.
    ///
    /// Cingulate orders detach and settlement in one transaction, so exactly
    /// one of "settled while held" (returned here, to answer in the call) and
    /// "settled after detach" (notified to the agent) applies.
    pub async fn detach(&mut self, elicitation_id: &str) -> Result<Detach, Ending> {
        let reply = self
            .record(wire::CONSENT_DETACH, wire::id_params(elicitation_id))
            .await;
        Detach::of_reply(reply)
    }

    /// Detach `elicitation_id`, and withdraw it if it could not be detached:
    /// an open card nobody would hear the answer to must not stay on the
    /// person's phone.
    async fn detach_or_withdraw(&mut self, elicitation_id: &str) -> Result<Detach, Ending> {
        let detach = self.detach(elicitation_id).await?;
        if matches!(detach, Detach::NotDetached) {
            let _ = self.withdraw(elicitation_id).await;
        }
        Ok(detach)
    }

    pub async fn get(&mut self, elicitation_id: &str) -> Result<Record, Ending> {
        self.record(wire::CONSENT_GET, wire::id_params(elicitation_id))
            .await
            .map_err(|error| Ending::of_refusal(&error))
    }

    /// Withdraw a card cerebellum raised. A card that already settled keeps
    /// its settlement; withdrawal never reverses an answer.
    ///
    /// The desk forgets the card when it is withdrawn, and when Cingulate
    /// says it is not this session's or no longer exists
    /// (`elicitation_not_owner`, `elicitation_not_found`): no answer to it
    /// can ever be read, so nothing else would clear it from the registry.
    pub async fn withdraw(&mut self, elicitation_id: &str) -> Result<Record, Ending> {
        match self
            .record(wire::CONSENT_WITHDRAW, wire::id_params(elicitation_id))
            .await
        {
            Ok(record) => {
                // A withdrawal never appears in the answers feed, so nothing
                // would ever clear it from the registry otherwise. A card that
                // settled first stays, for the feed to apply.
                if record.state == CardState::Withdrawn {
                    self.desk.forget(&[elicitation_id.to_string()]);
                }
                Ok(record)
            }
            Err(error) => {
                if let CallError::Refused(refusal) = &error {
                    if matches!(refusal.code, RefusalCode::NotOwner | RefusalCode::NotFound) {
                        self.desk.forget(&[elicitation_id.to_string()]);
                    }
                }
                Err(Ending::of_refusal(&error))
            }
        }
    }

    /// Report what became of an answered card.
    pub async fn report_execution(
        &mut self,
        elicitation_id: &str,
        execution: Execution,
    ) -> Result<Record, CallError> {
        self.record(
            wire::CONSENT_REPORT_EXECUTION,
            wire::report_execution_params(elicitation_id, execution),
        )
        .await
    }

    /// Apply every settlement in the answers feed that answers a card this
    /// session raised, then acknowledge the feed.
    ///
    /// `apply` receives the card, its record and its ending, and must make
    /// the effect durable before returning [`Apply::Applied`]; it returns
    /// [`Apply::NoRecord`] when the flow holds nothing the effect could be
    /// applied to. The feed is acknowledged only after every settlement read
    /// is marked in the stored registry, either way. A single-use card's
    /// (login import or capture, see `CardKind::single_use`) approval is
    /// also recorded here, but only when it was applied, so the agent's next
    /// call of the same tool with the same arguments can take it with
    /// [`ConsentDesk::take_single_use_approval`] and act on it once.
    pub async fn drain_answers(
        &mut self,
        apply: &mut (dyn FnMut(&RaisedCard, &Record, &Ending) -> Result<Apply, ApplyFailed> + Send),
    ) -> Result<DrainReport, Ending> {
        let mut report = DrainReport::default();
        let mut seen = Vec::new();
        let mut since = 0;
        let cursor = loop {
            let page = self
                .route
                .call(wire::CONSENT_ANSWERS, wire::answers_params(since))
                .await
                .map_err(|error| Ending::of_refusal(&error))?;
            let page = wire::AnswersPage::parse(&page).ok_or(Ending::DeliveryFailed)?;
            for record in &page.records {
                let card = self
                    .desk
                    .raised(&record.elicitation_id)
                    .filter(|card| card.session == *self.live.session());
                let Some(card) = card else {
                    report.ignored.push(record.elicitation_id.clone());
                    continue;
                };
                seen.push(card.elicitation_id.clone());
                if card.applied {
                    continue;
                }
                let Some(ending) = Ending::of_record(record, &card) else {
                    continue;
                };
                let applied = match apply(&card, record, &ending) {
                    Ok(applied) => applied,
                    // Not acknowledged: the next call reads it again.
                    Err(ApplyFailed(_)) => return Ok(report),
                };
                if applied == Apply::Applied && card.kind.single_use() {
                    if let Ending::Granted { choice_id } = &ending {
                        self.desk.record_single_use_approval(&card, choice_id);
                    }
                }
                if self.desk.mark_applied(&card.elicitation_id).is_err() {
                    return Ok(report);
                }
                match applied {
                    Apply::Applied => report.applied.push(card.elicitation_id.clone()),
                    Apply::NoRecord => report.without_effect.push(card.elicitation_id.clone()),
                }
            }
            match page.continuation {
                Some(next) => since = next,
                None => break page.cursor,
            }
        };
        if self
            .route
            .call(wire::CONSENT_ACK, wire::ack_params(cursor))
            .await
            .is_ok()
        {
            report.acked = Some(cursor);
            self.desk.forget(&seen);
        }
        Ok(report)
    }
}

/// The reply a call gives when it stops holding an unsettled card. A card
/// is reported pending only once `consent.detach` detached it (see
/// [`Detach::Detached`]), so Cingulate's notice will wake the agent when it
/// settles.
pub fn pending_reply(ask_id: &str) -> Value {
    let remedy = "The person has been asked and hasn't answered yet. You'll be woken when they \
                  answer; then call this tool again with the same arguments.";
    json!({"outcome": "consent_pending", "ask_id": ask_id, "remedy": remedy})
}

/// The instruction for the agent after the operator chose `choice_id`, which
/// belongs on cerebellum's reply and never on the card.
pub fn next_step_for(card: &RaisedCard, choice_id: &str) -> Option<String> {
    card.next_steps.get(choice_id).cloned()
}
