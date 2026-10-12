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
use super::live_call::{LiveCall, SessionKey};
use super::route::{CallError, CingulateOpener, CingulateRoute};
use super::wire::{self, CardState, Execution, Record, RefusalCode};

/// How a card ended, as the code that raised it reads it.
///
/// These are the endings the reverse lane reported, kept apart for the same
/// reason: a refusal is a decision, silence may be answered next time, a card
/// nobody was shown never will be, and a delivery failure is this side's
/// fault and worth retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    /// The operator chose one of the card's granting options.
    Granted { choice_id: String },
    /// The operator chose the decline, or a choice this card did not offer as
    /// a grant (read as not consent).
    Declined { choice_id: String },
    /// The card expired unanswered, or is no longer retained.
    NoAnswer,
    /// Cingulate would not put the card to anyone: the requester or kind was
    /// refused, the card was malformed, or the agent is retired. Asking again
    /// goes the same way.
    NotPutToAnyone,
    /// The card or its answer could not be carried: no route, a transport
    /// failure, or the consent module being unavailable.
    DeliveryFailed,
    /// Cerebellum withdrew the card.
    Withdrawn,
}

impl Ending {
    /// The ending a refusal of `consent.request`, `consent.await` or
    /// `consent.get` stands for.
    pub fn of_refusal(error: &CallError) -> Self {
        match error {
            CallError::NotLive | CallError::Transport { .. } => Self::DeliveryFailed,
            CallError::Refused(refusal) => match refusal.code {
                RefusalCode::RequesterRefused
                | RefusalCode::InvalidRequest
                | RefusalCode::UnknownKind
                | RefusalCode::FailClosedRequired
                | RefusalCode::ConsentRetired
                | RefusalCode::RequestTooLarge
                | RefusalCode::InvalidEnvelope => Self::NotPutToAnyone,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InCall {
    /// The card settled while the call held it: answer in the call.
    Settled(Ending),
    /// The call stops holding the card unsettled. `wake` says whether
    /// Cingulate will notify the agent when it settles: true only when the
    /// card was detached.
    Pending { ask_id: String, wake: bool },
    /// The call was cancelled while it waited; the card was withdrawn.
    Cancelled,
    /// The call's route unbound while it waited; the card was withdrawn.
    RouteClosed,
}

/// What `consent.detach` did.
#[derive(Debug, Clone, PartialEq)]
pub enum Detach {
    /// The card is pending and now detached: a later settlement produces a
    /// notice to the agent.
    Detached(Record),
    /// The card had already settled; no notice will ever be sent for it.
    AlreadySettled(Record),
    /// The consent module does not know `consent.detach` yet (it answered
    /// `unknown_method`). The card stays open but was never detached, so no
    /// notice will come for it.
    NotDetached,
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
    fn load(&self) -> Vec<RaisedCard>;
    /// Store the whole registry. An error means the change may not survive
    /// a restart, so nothing that depends on it is acknowledged.
    fn save(&self, cards: &[RaisedCard]) -> Result<(), String>;
}

/// The registry in one JSON file, replaced atomically on every save.
pub struct FileRegistryStore {
    path: std::path::PathBuf,
}

impl FileRegistryStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl RegistryStore for FileRegistryStore {
    fn load(&self) -> Vec<RaisedCard> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, cards: &[RaisedCard]) -> Result<(), String> {
        let bytes = serde_json::to_vec(cards).map_err(|error| error.to_string())?;
        let partial = self.path.with_extension("partial");
        std::fs::write(&partial, bytes).map_err(|error| error.to_string())?;
        std::fs::rename(&partial, &self.path).map_err(|error| error.to_string())
    }
}

/// The application of one settlement failed; it is not acknowledged, and is
/// read and applied again on a later call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyFailed(pub String);

/// What one pass over the answers feed did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Settlements applied in this pass, by elicitation id.
    pub applied: Vec<String>,
    /// Settlements of cards cerebellum did not raise on this session, which
    /// were not applied.
    pub ignored: Vec<String>,
    /// The cursor acknowledged, when the pass got that far.
    pub acked: Option<i64>,
}

/// Late approvals of single-use cards (login import and capture), each
/// waiting for the one retry that may act on it.
#[derive(Default)]
struct SingleUse {
    approvals: HashMap<(SessionKey, String), (String, String)>,
}

/// Cerebellum's side of Cingulate: the opener and the registry of raised
/// cards.
pub struct ConsentDesk {
    opener: Arc<dyn CingulateOpener>,
    store: Option<Arc<dyn RegistryStore>>,
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
            registry: Mutex::new(HashMap::new()),
            single_use: Mutex::new(SingleUse::default()),
        }
    }

    /// A desk whose registry is loaded from, and saved to, `store`.
    pub fn with_store(opener: Arc<dyn CingulateOpener>, store: Arc<dyn RegistryStore>) -> Self {
        let cards = store
            .load()
            .into_iter()
            .map(|card| (card.elicitation_id.clone(), card))
            .collect();
        Self {
            opener,
            store: Some(store),
            registry: Mutex::new(cards),
            single_use: Mutex::new(SingleUse::default()),
        }
    }

    /// Open a route to Cingulate for `live`'s call.
    ///
    /// Refuses without opening anything once the call is no longer held:
    /// the carrier listing that admits this route exists for calls the agent
    /// is making, not for cerebellum acting on its own.
    pub async fn session<'a>(&'a self, live: &'a LiveCall) -> Result<DeskSession<'a>, CallError> {
        if !live.is_held() {
            return Err(CallError::NotLive);
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

    /// Take the late single-use approval recorded for `subject` on this
    /// session, at most once. Returns the card's elicitation id, which the
    /// retry reports its execution against.
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
        let Some(store) = &self.store else {
            return Ok(());
        };
        let cards: Vec<RaisedCard> = lock(&self.registry).values().cloned().collect();
        store.save(&cards)
    }

    fn mark_applied(&self, elicitation_id: &str) -> Result<(), String> {
        if let Some(card) = lock(&self.registry).get_mut(elicitation_id) {
            card.applied = true;
        }
        self.save()
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
        // A card that is not in the stored registry would have its late
        // answer ignored after a restart; the card is still raised, so the
        // in-call answer is unaffected.
        let _ = self.desk.save();
        Ok(elicitation_id)
    }

    /// Hold the call on the card for at most `park`, then either answer in
    /// the call or detach the card and report it pending.
    ///
    /// `cancelled` resolves when the caller cancels the call. The route the
    /// call arrived on is watched too. Either ending withdraws the card,
    /// since nobody is left to want its answer from this call.
    ///
    /// A settlement returned here is the call's to apply before it replies;
    /// the registry marks it applied so the answers feed does not apply it a
    /// second time.
    pub async fn park(
        &mut self,
        elicitation_id: &str,
        park: Duration,
        cancelled: impl Future<Output = ()>,
    ) -> InCall {
        let Some(card) = self.desk.raised(elicitation_id) else {
            // Never wait on, and never act on, a card this desk did not raise.
            return InCall::Settled(Ending::NotPutToAnyone);
        };
        let live = self.live;
        let route_closed = async {
            while live.is_held() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        let timeout_ms = u64::try_from(park.as_millis()).unwrap_or(u64::MAX);
        enum Woke {
            Read(Result<Record, CallError>),
            Cancelled,
            RouteClosed,
        }
        let woke = {
            let waiting = self.record(
                wire::CONSENT_AWAIT,
                wire::await_params(elicitation_id, timeout_ms),
            );
            tokio::select! {
                read = waiting => Woke::Read(read),
                () = cancelled => Woke::Cancelled,
                () = route_closed => Woke::RouteClosed,
            }
        };
        let read = match woke {
            Woke::Read(read) => read,
            Woke::Cancelled => {
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
            let _ = self.desk.mark_applied(elicitation_id);
            return InCall::Settled(ending);
        }
        match self.detach(elicitation_id).await {
            Ok(Detach::Detached(_)) => InCall::Pending {
                ask_id: elicitation_id.to_string(),
                wake: true,
            },
            Ok(Detach::AlreadySettled(record)) => {
                let ending = Ending::of_record(&record, &card).unwrap_or(Ending::NoAnswer);
                let _ = self.desk.mark_applied(elicitation_id);
                InCall::Settled(ending)
            }
            Ok(Detach::NotDetached) => InCall::Pending {
                ask_id: elicitation_id.to_string(),
                wake: false,
            },
            Err(ending) => InCall::Settled(ending),
        }
    }

    /// Mark the moment cerebellum stops holding the call on `elicitation_id`.
    ///
    /// Cingulate orders detach and settlement in one transaction, so exactly
    /// one of "settled while held" (returned here, to answer in the call) and
    /// "settled after detach" (notified to the agent) applies.
    pub async fn detach(&mut self, elicitation_id: &str) -> Result<Detach, Ending> {
        match self
            .record(wire::CONSENT_DETACH, wire::id_params(elicitation_id))
            .await
        {
            Ok(record) if record.is_settled() => Ok(Detach::AlreadySettled(record)),
            Ok(record) if record.detached => Ok(Detach::Detached(record)),
            // A pending record without the mark is outside the contract: the
            // card was not detached, so no wake can be promised.
            Ok(_) => Ok(Detach::NotDetached),
            // Tolerated until the consent module ships the operation: the
            // card stays open, undetached.
            Err(CallError::Refused(refusal)) if refusal.code == RefusalCode::UnknownMethod => {
                Ok(Detach::NotDetached)
            }
            Err(error) => Err(Ending::of_refusal(&error)),
        }
    }

    pub async fn get(&mut self, elicitation_id: &str) -> Result<Record, Ending> {
        self.record(wire::CONSENT_GET, wire::id_params(elicitation_id))
            .await
            .map_err(|error| Ending::of_refusal(&error))
    }

    /// Withdraw a card cerebellum raised. A card that already settled keeps
    /// its settlement; withdrawal never reverses an answer.
    pub async fn withdraw(&mut self, elicitation_id: &str) -> Result<Record, Ending> {
        let record = self
            .record(wire::CONSENT_WITHDRAW, wire::id_params(elicitation_id))
            .await
            .map_err(|error| Ending::of_refusal(&error))?;
        // A withdrawal never appears in the answers feed, so nothing would
        // ever clear it from the registry otherwise. A card that settled
        // first stays, for the feed to apply.
        if record.state == CardState::Withdrawn {
            self.desk.forget(&[elicitation_id.to_string()]);
        }
        Ok(record)
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
    /// the effect durable before returning `Ok`: the feed is acknowledged
    /// only after every applied settlement is marked in the stored registry.
    /// A single-use card's approval is recorded here for the retry to take,
    /// in addition to whatever `apply` does.
    pub async fn drain_answers(
        &mut self,
        apply: &mut (dyn FnMut(&RaisedCard, &Record, &Ending) -> Result<(), ApplyFailed> + Send),
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
                if let Err(ApplyFailed(_)) = apply(&card, record, &ending) {
                    // Not acknowledged: the next call reads it again.
                    return Ok(report);
                }
                if card.kind.single_use() {
                    if let Ending::Granted { choice_id } = &ending {
                        self.desk.record_single_use_approval(&card, choice_id);
                    }
                }
                if self.desk.mark_applied(&card.elicitation_id).is_err() {
                    return Ok(report);
                }
                report.applied.push(card.elicitation_id.clone());
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

/// The reply a call gives when it stops holding an unsettled card.
///
/// Only a detached card is followed by a notice to the agent, so only then
/// may the reply promise a wake; otherwise it says to call again later.
pub fn pending_reply(ask_id: &str, wake: bool) -> Value {
    let remedy = if wake {
        "The person has been asked and hasn't answered yet. You'll be woken when they answer; \
         then call this tool again with the same arguments."
    } else {
        "The person has been asked and hasn't answered yet. No notice will come for this card: \
         call this tool again later with the same arguments."
    };
    json!({"outcome": "consent_pending", "ask_id": ask_id, "remedy": remedy})
}

/// The instruction for the agent after the operator chose `choice_id`, which
/// belongs on cerebellum's reply and never on the card.
pub fn next_step_for(card: &RaisedCard, choice_id: &str) -> Option<String> {
    card.next_steps.get(choice_id).cloned()
}
