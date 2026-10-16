//! A scripted Cingulate route for desk probes, which answers every card the
//! way the person running the probe would.
//!
//! Running a probe is the person's consent to what it does, but a probe can't
//! name one answer for every card. Each kind offers different choices: an app
//! card offers "Use <app> for 30 minutes", a takeover card offers "Allow this
//! takeover once" and the whole-computer options. So the route reads the
//! options the card actually offers and picks the narrowest reusable grant:
//! 30 minutes on the app, then 30 minutes of the whole computer, then whatever
//! single-call approval is offered. It never picks "always" or "don't allow".
//!
//! Included with `#[path = "support/allowing_cingulate.rs"] mod
//! allowing_cingulate;` at the top level of a probe.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cerebellum::cingulate_client::live_call::LiveCall;
use cerebellum::cingulate_client::route::{BoxFuture, CallError, CingulateOpener, CingulateRoute};
use cerebellum::cingulate_client::{Reply, ScriptedCingulate};
use serde_json::{json, Value};

/// The choices a probe may take, narrowest reusable grant first.
const PREFERRED: [&str; 3] = ["allow_30m", "computer_30m", "allow_once"];

/// The option a probe answers with, or None when the card offers none of
/// the choices a probe may take.
pub fn probe_choice(request: &Value) -> Option<&'static str> {
    let offered: Vec<&str> = request["options"]
        .as_array()?
        .iter()
        .filter_map(|option| option["id"].as_str())
        .collect();
    PREFERRED.into_iter().find(|id| offered.contains(id))
}

/// Opens one scripted route per card, naming its card `<prefix><n>`.
pub struct AllowingCingulate {
    prefix: &'static str,
    next: AtomicU64,
}

impl AllowingCingulate {
    pub fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            next: AtomicU64::new(1),
        }
    }
}

impl CingulateOpener for AllowingCingulate {
    fn open<'a>(
        &'a self,
        live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        Box::pin(async move {
            let id = format!(
                "{}{}",
                self.prefix,
                self.next.fetch_add(1, Ordering::Relaxed)
            );
            let script = ScriptedCingulate::new();
            script.then(
                "consent.request",
                Reply::Result(json!({"elicitation_id": id})),
            );
            let inner = script.open(live).await?;
            Ok(Box::new(AllowingRoute { script, inner, id }) as Box<dyn CingulateRoute>)
        })
    }
}

/// Scripts the card's answer once its request shows what it offers.
struct AllowingRoute {
    script: Arc<ScriptedCingulate>,
    inner: Box<dyn CingulateRoute>,
    id: String,
}

impl CingulateRoute for AllowingRoute {
    fn features(&self) -> Option<cerebellum::cingulate_client::features::CingulateFeatures> {
        self.inner.features()
    }

    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, CallError>> {
        if method == "consent.request" {
            let answer = match probe_choice(&params) {
                Some(choice) => {
                    println!("  QUESTION {} -> ANSWER {choice}", params["message"]);
                    json!({"elicitation_id": self.id, "state": "answered", "answered_choice_id": choice})
                }
                None => {
                    println!(
                        "  QUESTION {} offers no probe choice; declining",
                        params["message"]
                    );
                    json!({"elicitation_id": self.id, "state": "answered", "answered_choice_id": "deny"})
                }
            };
            self.script.then("consent.await", Reply::Result(answer));
        }
        self.inner.call(method, params)
    }
}

#[cfg(test)]
mod tests {
    use super::probe_choice;
    use serde_json::json;

    fn card(ids: &[&str]) -> serde_json::Value {
        json!({"options": ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>()})
    }

    #[test]
    fn the_probe_takes_the_narrowest_grant_each_card_offers() {
        let app = card(&[
            "allow_30m",
            "allow_always",
            "computer_30m",
            "computer_always",
            "deny",
        ]);
        assert_eq!(probe_choice(&app), Some("allow_30m"));
        let takeover = card(&["allow_once", "computer_30m", "computer_always", "deny"]);
        assert_eq!(probe_choice(&takeover), Some("computer_30m"));
        let stripped_takeover = card(&["allow_once", "deny"]);
        assert_eq!(probe_choice(&stripped_takeover), Some("allow_once"));
        assert_eq!(probe_choice(&card(&["allow_always", "deny"])), None);
    }
}
