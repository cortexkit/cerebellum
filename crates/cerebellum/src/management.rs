//! Management operations: asking for permission to reach an application.
//!
//! Separate from tool calls because the two surfaces take different request
//! envelopes and because what they do differs in kind. A tool call acts; a
//! management operation arranges the authority under which acting is possible.
//!
//! WHY OPENING A LEASE IS ITS OWN CALL rather than something the first action
//! does implicitly: an implicit prompt would ask the user to approve reaching an
//! application the agent is ALREADY MID-ACTION AGAINST, which turns consent into
//! ratification — the thing being consented to arrives pre-committed. Keeping
//! the ask ahead of the action costs a round trip and buys an approval the user
//! can refuse before anything has happened.
//!
//! The cost of an explicit step is that it can be forgotten. That is paid for at
//! the other end: an action against an unleased target refuses with the name of
//! this operation and the application it needs, so forgetting costs one round
//! trip and teaches.

use std::sync::Arc;
use std::time::Duration;

use cerebellum_computer::platform::{TargetCandidate, TargetResolution};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::consent::{ActionKind, ConsentLeases, GrantKind, LeaseKey, Opening};
use serde_json::{json, Value};
use tokio::sync::Mutex;

/// The one operation this surface serves.
pub const OPEN_TARGET: &str = "computer.open_target";

/// Read an action kind from its wire spelling.
///
/// `None` for anything unrecognised, so a kind this module does not know is
/// refused rather than resolved to a default. Defaulting would put a request
/// under whichever gate the default names, and the plausible default is the
/// permissive one.
pub fn action_kind_from_wire(kind: &str) -> Option<ActionKind> {
    match kind {
        "observe" => Some(ActionKind::Observe),
        "compose" => Some(ActionKind::Compose),
        "mutate_durable" => Some(ActionKind::MutateDurable),
        _ => None,
    }
}

/// How long a consent question may stay unanswered before it stops being one.
///
/// Long enough for a person to notice a prompt and decide; short enough that an
/// abandoned question does not sit outstanding indefinitely. Its expiry is a
/// definite not-granted rather than an unfinished wait — the caller has long
/// since been told the request is pending, so nothing is blocked on it.
const CONSENT_DEADLINE: Duration = Duration::from_secs(300);

/// How long a granted lease lasts when the user allows one.
///
/// The prompt offers a bounded grant rather than an open-ended one, so this is
/// the bound. It is not configurable here: a duration that can be raised toward
/// indefinite reintroduces the grant nobody could later say they issued.
const GRANT_DURATION: Duration = Duration::from_secs(600);

/// Resolving an application name to the process that answers to it.
///
/// Behind a trait because the resolution reads the window server, which exists
/// only on the platform this plane drives — while everything above it is
/// ordinary logic that should be exercised wherever the tests run. A concrete
/// dependency here would put the consent flow in the half no continuous build
/// compiles.
pub trait TargetResolver: Send + Sync {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution;
}

/// Resolves application names against this machine.
///
/// The macOS reading and a refusal elsewhere are the two halves: a host with no
/// window server cannot say an application is absent, only that it cannot look,
/// and reporting "not running" would be a claim rather than a reading. Both
/// answers refuse; only one of them is evidence.
#[derive(Debug, Default)]
pub struct PlatformResolver {
    timeout: Duration,
}

impl PlatformResolver {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

impl TargetResolver for PlatformResolver {
    #[cfg(target_os = "macos")]
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        cerebellum_computer::platform::native::resolve_target(bundle_identity, self.timeout)
    }

    #[cfg(not(target_os = "macos"))]
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        let _ = self.timeout;
        TargetResolution::NotRunning
    }
}

/// The state a management route needs.
pub struct ManagementPlane {
    leases: Mutex<ConsentLeases>,
    resolver: Arc<dyn TargetResolver>,
}

impl ManagementPlane {
    pub fn new(resolver: Arc<dyn TargetResolver>) -> Self {
        Self {
            leases: Mutex::new(ConsentLeases::new()),
            resolver,
        }
    }

    /// Resolve an application name and report what authority exists over it.
    ///
    /// Returns without waiting for the user. The operation's own deadline is
    /// seconds and a person's is minutes, so waiting would time out on almost
    /// every genuine ask and report a decision nobody made. The caller is told
    /// the request is pending and asks again later; the answer, when it comes,
    /// is applied by the task this spawns.
    pub async fn open_target<C: MonotonicClock>(
        &self,
        grantee: &str,
        bundle_identity: &str,
        action_kind: ActionKind,
        can_relay_to_a_person: bool,
        clock: &C,
    ) -> (Value, Option<Question>) {
        // Resolved BEFORE any lease is consulted, because a lease over an
        // application that is not running, or that names two processes, is not
        // something to act on even when it is held. The lease says the user
        // agreed; resolution says what they agreed about still exists.
        let resolution = self.resolver.resolve(bundle_identity);
        let grant = match resolution {
            TargetResolution::Resolved(grant) => grant,
            TargetResolution::NotRunning => {
                return (
                    json!({
                        "outcome": "not_running",
                        "bundle_identity": bundle_identity,
                        "remedy": "start the application, then ask again",
                    }),
                    None,
                );
            }
            TargetResolution::Ambiguous(candidates) => {
                return (
                    json!({
                        "outcome": "ambiguous",
                        "bundle_identity": bundle_identity,
                        "instances": describe(&candidates),
                        // Named rather than chosen between: picking one would
                        // grant access to a process the user never selected.
                        "remedy": "quit all but one instance, then ask again",
                    }),
                    None,
                );
            }
        };

        let key = LeaseKey {
            grantee: grantee.to_string(),
            bundle_identity: bundle_identity.to_string(),
            action_kind,
        };

        let opening = {
            let mut leases = self.leases.lock().await;
            leases.open(key.clone(), clock, new_ask_id)
        };

        match opening {
            Opening::AlreadyHeld(lease) => {
                let remaining = {
                    let leases = self.leases.lock().await;
                    let _ = &*leases;
                    ConsentLeases::remaining(&lease, clock)
                };
                (
                    json!({
                        "outcome": "already_held",
                        "bundle_identity": bundle_identity,
                        "pid": grant.pid,
                        // A duration rather than the expiry instant, which is
                        // comparable only against this module's clock. Stale by
                        // however long it takes to arrive, so it is worth planning
                        // against and not worth relying on: the check made when the
                        // lease is used stays the authority.
                        "remaining_ms": remaining.map(|left| left.as_millis() as u64),
                    }),
                    None,
                )
            }
            // Already being asked: the caller waits for that answer. Putting the
            // question again would show the user a second prompt for something
            // already on their screen.
            Opening::AlreadyAsking(pending) => (
                json!({
                    "outcome": "consent_pending",
                    "bundle_identity": bundle_identity,
                    "ask_id": pending.ask_id,
                    "remedy": "ask again once the request has been answered",
                }),
                None,
            ),
            Opening::AskNeeded(pending) => {
                if !can_relay_to_a_person {
                    // Nobody can be asked, so nothing can be granted. Reported
                    // as its own outcome rather than as a pending question:
                    // waiting for an answer that cannot be requested would
                    // report the user as unresponsive for a fault on this side.
                    let mut leases = self.leases.lock().await;
                    leases.settle(&pending.ask_id, None, clock);
                    return (
                        json!({
                            "outcome": "consent_unavailable",
                            "bundle_identity": bundle_identity,
                            "remedy":
                                "reconnect declaring the ability to relay a question to a person",
                        }),
                        None,
                    );
                }

                // The question travels back to the caller rather than being sent
                // here, so this type decides WHAT to ask without needing a wire
                // to ask on -- which is what lets the whole flow be exercised
                // where no window server and no route exist.
                let question = Question {
                    ask_id: pending.ask_id.clone(),
                    body: consent_question(&pending.ask_id, bundle_identity, action_kind),
                    deadline: CONSENT_DEADLINE,
                };
                (
                    json!({
                        "outcome": "consent_pending",
                        "bundle_identity": bundle_identity,
                        "ask_id": pending.ask_id,
                        "remedy": "ask again once the request has been answered",
                    }),
                    Some(question),
                )
            }
        }
    }

    /// Apply a user's answer to the question it answers.
    ///
    /// An answer to a question this module is not holding grants nothing: it is
    /// either a reply to one already settled or an answer to something never
    /// asked, and neither may create authority.
    pub async fn settle<C: MonotonicClock>(
        &self,
        ask_id: &str,
        answer: Option<&Value>,
        clock: &C,
    ) -> bool {
        let granted = answer.and_then(|answer| grant_from_answer(answer, clock));
        let mut leases = self.leases.lock().await;
        leases.settle(ask_id, granted, clock).is_some()
    }

    /// Whether a lease currently admits an action, without spending one.
    pub async fn admits<C: MonotonicClock>(&self, key: &LeaseKey, clock: &C) -> bool {
        let mut leases = self.leases.lock().await;
        leases.admits(key, clock).is_admitted()
    }
}

/// A question to put to the user, and how long it stays one.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub ask_id: String,
    pub body: Value,
    pub deadline: Duration,
}

/// The question put to the user.
///
/// The wording carries the scope in words because the prompt's attachment cannot:
/// a preview shows one window at one moment while the grant covers the whole
/// application for its duration, so a user deciding from the picture would be
/// deciding on something the grant does not preserve.
fn consent_question(ask_id: &str, bundle_identity: &str, action_kind: ActionKind) -> Value {
    let verb = match action_kind {
        ActionKind::Observe => "see",
        ActionKind::Compose => "control",
        ActionKind::MutateDurable => "make lasting changes in",
    };
    json!({
        "jsonrpc": "2.0",
        "id": ask_id,
        "method": "elicitation/create",
        "params": {
            "message": format!(
                "Allow this agent to {verb} {bundle_identity}? \
                 It will apply to that application's windows for the next 10 minutes, \
                 including windows and pages you open during that time."
            ),
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "decision": {
                        "type": "string",
                        // No indefinite option. An open-ended grant to reach an
                        // application is one nobody could later say they issued;
                        // durable permission is a configuration act instead.
                        "enum": ["allow_once", "allow_10_minutes", "deny"],
                    }
                },
                "required": ["decision"],
            },
        },
    })
}

/// Turn a user's answer into the grant it authorises, if any.
///
/// An answer this does not recognise is a refusal rather than a default: a reply
/// that cannot be read is not evidence that anyone agreed to anything.
pub fn grant_from_answer<C: MonotonicClock>(answer: &Value, clock: &C) -> Option<GrantKind> {
    match answer.get("decision").and_then(Value::as_str) {
        Some("allow_once") => Some(GrantKind::Once),
        // Computed against this module's clock, which is the only clock the
        // expiry will ever be compared to.
        Some("allow_10_minutes") => {
            Some(GrantKind::Until(clock.now().saturating_add(GRANT_DURATION)))
        }
        _ => None,
    }
}

fn describe(candidates: &[TargetCandidate]) -> Vec<Value> {
    candidates
        .iter()
        .map(|candidate| {
            json!({
                "pid": candidate.pid,
                "window_count": candidate.window_count,
            })
        })
        .collect()
}

/// A fresh identity for a question, unique across this module's lifetime.
fn new_ask_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("consent-{}", NEXT.fetch_add(1, Ordering::Relaxed) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::platform::ProcessGrant;
    use cerebellum_core::clock::FakeClock;

    struct Fixed(TargetResolution);

    impl TargetResolver for Fixed {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            self.0.clone()
        }
    }

    fn plane(resolution: TargetResolution) -> ManagementPlane {
        ManagementPlane::new(Arc::new(Fixed(resolution)))
    }

    fn one_instance() -> TargetResolution {
        TargetResolution::Resolved(ProcessGrant {
            pid: 4242,
            bundle_identity: "com.apple.Safari".to_string(),
            process_generation_evidence: "1700000000000000".to_string(),
        })
    }

    async fn open(plane: &ManagementPlane, clock: &FakeClock) -> (Value, Option<Question>) {
        plane
            .open_target(
                "pj-example",
                "com.apple.Safari",
                ActionKind::Observe,
                true,
                clock,
            )
            .await
    }

    /// An unleased application asks, and hands back the question to put.
    #[tokio::test]
    async fn an_unleased_application_produces_a_question() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, question) = open(&plane, &clock).await;
        assert_eq!(reply["outcome"], "consent_pending");
        let question = question.expect("an unleased application must produce a question");
        assert_eq!(question.ask_id, reply["ask_id"].as_str().unwrap());

        // The wording carries the scope, because the grant outlives the moment
        // and covers more than whatever the user can see when they answer.
        let message = question.body["params"]["message"].as_str().unwrap();
        assert!(message.contains("com.apple.Safari"), "{message}");
        assert!(message.contains("10 minutes"), "{message}");
        assert!(message.contains("open during that time"), "{message}");

        // No indefinite option is offered.
        let options = question.body["params"]["requestedSchema"]["properties"]["decision"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(options.len(), 3);
        assert!(!options.iter().any(|option| {
            let option = option.as_str().unwrap_or_default();
            option.contains("always") || option.contains("forever")
        }));
    }

    /// A repeat request joins the question in flight rather than asking again.
    ///
    /// The reply is the same, and the ABSENCE of a second question is the
    /// property: a caller handed one puts it, and the user would then see two
    /// prompts for a single request.
    #[tokio::test]
    async fn a_repeat_request_does_not_produce_a_second_question() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (first, first_question) = open(&plane, &clock).await;
        let (second, second_question) = open(&plane, &clock).await;

        assert_eq!(first["ask_id"], second["ask_id"]);
        assert!(first_question.is_some());
        assert!(
            second_question.is_none(),
            "a repeat request would have prompted the user twice"
        );
    }

    /// Two instances refuse, name both, and ask nothing.
    ///
    /// Asking would be asking about a target that does not exist: the user
    /// cannot grant access to "Safari" when the name does not identify one.
    #[tokio::test]
    async fn two_instances_refuse_without_asking() {
        let plane = plane(TargetResolution::Ambiguous(vec![
            TargetCandidate {
                pid: 100,
                window_count: 2,
            },
            TargetCandidate {
                pid: 101,
                window_count: 1,
            },
        ]));
        let clock = FakeClock::new();

        let (reply, question) = open(&plane, &clock).await;
        assert_eq!(reply["outcome"], "ambiguous");
        assert!(question.is_none(), "an ambiguous target was asked about");

        let instances = reply["instances"].as_array().unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0]["pid"], 100);
        assert_eq!(instances[0]["window_count"], 2);
        assert_eq!(instances[1]["pid"], 101);
    }

    /// An application that is not running refuses without asking.
    #[tokio::test]
    async fn a_missing_application_refuses_without_asking() {
        let plane = plane(TargetResolution::NotRunning);
        let clock = FakeClock::new();

        let (reply, question) = open(&plane, &clock).await;
        assert_eq!(reply["outcome"], "not_running");
        assert!(question.is_none());
    }

    /// With nobody to ask, the request fails rather than waiting.
    ///
    /// Reported as its own outcome: leaving a question outstanding for a
    /// consumer that cannot relay it would report the user as unresponsive for
    /// a fault on this side.
    #[tokio::test]
    async fn a_consumer_that_cannot_relay_gets_no_pending_question() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, question) = plane
            .open_target(
                "pj-example",
                "com.apple.Safari",
                ActionKind::Observe,
                false,
                &clock,
            )
            .await;

        assert_eq!(reply["outcome"], "consent_unavailable");
        assert!(question.is_none());

        // And nothing is left pending, so a later request asks afresh rather
        // than joining a question that was never put.
        let (again, _) = open(&plane, &clock).await;
        assert_eq!(again["outcome"], "consent_pending");
    }

    /// An allowed answer mints the lease, and a later request is already held.
    #[tokio::test]
    async fn an_allowed_answer_grants_a_bounded_lease() {
        let plane = plane(one_instance());
        let mut clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();

        assert!(
            plane
                .settle(
                    &ask_id,
                    Some(&json!({"decision": "allow_10_minutes"})),
                    &clock
                )
                .await
        );

        let (held, question) = open(&plane, &clock).await;
        assert_eq!(held["outcome"], "already_held");
        assert!(question.is_none(), "a held lease asked again");
        assert_eq!(held["remaining_ms"], 600_000);

        // The bound is real: the lease stops admitting once it passes.
        clock.advance(Duration::from_secs(600));
        let (expired, question) = open(&plane, &clock).await;
        assert_eq!(expired["outcome"], "consent_pending");
        assert!(question.is_some(), "an expired lease did not ask again");
    }

    /// A refusal grants nothing, and the next request asks afresh.
    #[tokio::test]
    async fn a_refusal_grants_nothing() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();

        assert!(
            !plane
                .settle(&ask_id, Some(&json!({"decision": "deny"})), &clock)
                .await
        );

        let (again, question) = open(&plane, &clock).await;
        assert_eq!(again["outcome"], "consent_pending");
        assert!(question.is_some(), "a refused request did not ask again");
    }

    /// An answer that cannot be read grants nothing.
    ///
    /// A reply this does not understand is not evidence that anyone agreed, so
    /// it is a refusal rather than a value to fall back from.
    #[tokio::test]
    async fn an_unreadable_answer_grants_nothing() {
        let clock = FakeClock::new();
        assert!(grant_from_answer(&json!({}), &clock).is_none());
        assert!(grant_from_answer(&json!({"decision": "yes"}), &clock).is_none());
        assert!(grant_from_answer(&json!({"decision": "allow_forever"}), &clock).is_none());
        assert!(grant_from_answer(&json!({"decision": "allow_once"}), &clock).is_some());
    }

    /// An answer to a question nobody asked grants nothing.
    #[tokio::test]
    async fn an_answer_to_an_unknown_question_grants_nothing() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        assert!(
            !plane
                .settle(
                    "never-asked",
                    Some(&json!({"decision": "allow_once"})),
                    &clock
                )
                .await
        );
    }
}
