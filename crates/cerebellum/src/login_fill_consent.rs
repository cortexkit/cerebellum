//! The person's approval for `browser.fill_login`, asked for on the vault's
//! behalf.
//!
//! When the vault answers `approval_required`, cerebellum raises a Cingulate
//! consent card carrying the vault's request id and statement unchanged, and
//! holds the call on it like its own cards. If the person approves while the
//! call waits, the vault is asked again and the login filled. An approval
//! that arrives after the call stopped waiting fills nothing: the vault
//! records the approval from the person's answer itself, and the agent's next
//! `browser.fill_login` call is the one that uses it. Cerebellum's part in a
//! late answer is only to acknowledge it.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::browser::fill::{
    Approval, FillPlan, FillRefusal, LoginMaterialSource, SecretUseAnswer, SecretUseRequest,
    SourceUnavailable,
};
use crate::browser::BrowserError;
use crate::cingulate_client::card::{consent_request, CardKind};
use crate::cingulate_client::desk::{
    Apply, ApplyFailed, Ending, InCall, LetGo, NoCard, RaisedCard,
};
use crate::cingulate_client::wire::{Execution, ExecutionReason, Record};
use crate::consent_drain::{AppliedSettlement, ConsentEffects};
use crate::{AcceptedBindFacts, Planes};
use cerebellum_computer::platform::vocabulary::CapabilityResultValidationError;

/// The card's declining option, which is also its default.
pub(crate) const DECLINE: &str = "decline";

/// The approval card for one vault request.
///
/// The dedicated kind permits only the vault's bytes. Cingulate derives its
/// display and expiry from the statement, and the phone grants at the vault
/// before answering this card. No generic Allow can release a login.
pub(crate) fn secret_use_card(approval: &Approval) -> Value {
    json!({"params": {"kind": "secret_use", "secret_use": {"items": [{
        "request_id": approval.request_id, "statement_b64url": approval.statement_b64url,
    }]}}})
}

/// Late answers to approval cards need nothing stored here: the vault keeps
/// the approval. The card stays counted as pending so the session's drain
/// never withdraws a card the person may still answer.
struct SecretUseEffects;

impl ConsentEffects for SecretUseEffects {
    fn has_pending(&self, _card: &RaisedCard) -> bool {
        true
    }

    fn apply(
        &self,
        _card: &RaisedCard,
        _record: &Record,
        _ending: &Ending,
    ) -> Result<AppliedSettlement, ApplyFailed> {
        Ok(AppliedSettlement {
            effect: Apply::Applied,
            completion: None,
        })
    }
}

pub(crate) fn register(planes: &Planes) {
    planes
        .consent_drain
        .register(CardKind::SecretUse, Arc::new(SecretUseEffects));
}

async fn ask(
    source: &dyn LoginMaterialSource,
    request: &SecretUseRequest,
) -> Result<SecretUseAnswer, SourceUnavailable> {
    source.secret_use(request).await
}

/// Serve one `browser.fill_login` call.
pub(crate) async fn serve(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    request: (u16, u32, u64),
    arguments: &Value,
    park_limit: Duration,
) -> Result<Value, CapabilityResultValidationError> {
    let mut origin = None;
    let reply = Box::pin(serve_inner(
        planes,
        facts,
        request,
        arguments,
        park_limit,
        &mut origin,
    ))
    .await;
    let outcome = reply
        .as_ref()
        .ok()
        .and_then(|reply| reply["outcome"].as_str())
        .unwrap_or("internal_failure")
        .to_string();
    let filled = reply
        .as_ref()
        .ok()
        .and_then(|reply| reply["filled"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|field| match field.as_str()? {
            "username" => Some(crate::journal::LoginFillField::Username),
            "password" => Some(crate::journal::LoginFillField::Password),
            "otp" => Some(crate::journal::LoginFillField::Otp),
            _ => None,
        })
        .collect();
    if let Err(error) = planes
        .browser
        .journal_login_fill(
            &facts.identity,
            crate::journal::LoginFillPayload {
                outcome,
                origin,
                filled,
            },
        )
        .await
    {
        return planes.browser.finish_fill_reply(
            planes
                .browser
                .fill_reply(
                    &facts.identity,
                    Err(BrowserError::Internal {
                        reason_code: error.reason_code,
                    }),
                )
                .await,
        );
    }
    reply
}

async fn serve_inner(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    request: (u16, u32, u64),
    arguments: &Value,
    park_limit: Duration,
    origin: &mut Option<String>,
) -> Result<Value, CapabilityResultValidationError> {
    let browser = &planes.browser;
    let identity = &facts.identity;
    let Some(source) = browser.login_material_source() else {
        return refuse(planes, facts, FillRefusal::VaultUnavailable).await;
    };
    let plan = match browser.plan_fill_login(identity, arguments).await {
        Ok(plan) => plan,
        Err(error) => {
            return browser.finish_fill_reply(browser.fill_reply(identity, Err(error)).await)
        }
    };
    *origin = Some(plan.origin.clone());
    // The scope the call arrived on, the head's for a codemode run: the vault
    // decides who is asking from it alone.
    let Some(stamp) = facts
        .head_context()
        .scope
        .as_ref()
        .and_then(|stamp| serde_json::to_value(stamp).ok())
    else {
        return refuse(planes, facts, FillRefusal::LoginUnavailable).await;
    };
    let secret_use = SecretUseRequest {
        name: plan.secret.clone(),
        stamp,
        origin: plan.origin.clone(),
    };
    if let Err(error) = browser.check_planned_login(identity, &plan).await {
        return browser.finish_fill_reply(browser.fill_reply(identity, Err(error)).await);
    }
    let result = match ask(source.as_ref(), &secret_use).await {
        Ok(SecretUseAnswer::Released(material)) => {
            browser.fill_planned_login(identity, plan, material).await
        }
        Ok(SecretUseAnswer::ApprovalRequired(approval)) => {
            return Box::pin(approve_then_fill(
                planes,
                facts,
                request,
                (plan, source.as_ref(), &secret_use),
                approval,
                park_limit,
            ))
            .await;
        }
        Ok(SecretUseAnswer::Refused) => {
            Err(BrowserError::FillRefused(FillRefusal::LoginUnavailable))
        }
        Err(SourceUnavailable) => Err(BrowserError::FillRefused(FillRefusal::VaultUnavailable)),
    };
    browser.finish_fill_reply(browser.fill_reply(identity, result).await)
}

async fn refuse(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    refusal: FillRefusal,
) -> Result<Value, CapabilityResultValidationError> {
    planes.browser.finish_fill_reply(
        planes
            .browser
            .fill_reply(&facts.identity, Err(BrowserError::FillRefused(refusal)))
            .await,
    )
}

async fn not_approved(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    ending: &Ending,
) -> Result<Value, CapabilityResultValidationError> {
    if let Ending::NoCard(NoCard::SecretUseRefused(reason)) = ending {
        return refuse(planes, facts, FillRefusal::ApprovalServiceRefused(*reason)).await;
    }
    refuse(
        planes,
        facts,
        FillRefusal::ApprovalNotGiven {
            decision: crate::browser_consent::word(ending, DECLINE),
            asked: !matches!(ending, Ending::NoCard(_)),
        },
    )
    .await
}

/// File the vault's approval card, hold the call on it, and fill only if the
/// person approves while the call waits.
async fn approve_then_fill(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    request: (u16, u32, u64),
    (plan, source, secret_use): (FillPlan, &dyn LoginMaterialSource, &SecretUseRequest),
    approval: Approval,
    park_limit: Duration,
) -> Result<Value, CapabilityResultValidationError> {
    let browser = &planes.browser;
    let identity = &facts.identity;
    if crate::codemode::legacy_run(facts) {
        return not_approved(planes, facts, &Ending::NoCard(NoCard::NoAgentSession)).await;
    }
    if facts.flow_id.is_some() {
        // An unattended flow has nobody to ask.
        return not_approved(planes, facts, &Ending::NoCard(NoCard::NoAgentSession)).await;
    }
    let Some(cancel) = planes.cancellations.get(request) else {
        return not_approved(planes, facts, &Ending::NoCard(NoCard::CallEnded)).await;
    };
    let live = match crate::browser_consent::live(facts, planes, request.0, request.1) {
        Ok(live) => live,
        Err(ending) => return not_approved(planes, facts, &ending).await,
    };
    let mut session = match planes.consent.session(&live).await {
        Ok(session) => session,
        Err(error) => return not_approved(planes, facts, &Ending::of_refusal(&error)).await,
    };
    if !session.supports_secret_use_approval() {
        return refuse(
            planes,
            facts,
            FillRefusal::ApprovalServiceRefused(
                crate::cingulate_client::desk::SecretUseRefusal::MissingCapability,
            ),
        )
        .await;
    }
    let Ok(card) = consent_request(
        CardKind::SecretUse,
        &secret_use_card(&approval),
        Duration::ZERO,
        None,
        None,
        None,
    ) else {
        return not_approved(planes, facts, &Ending::DeliveryFailed).await;
    };
    let subject = crate::cingulate_client::subject::secret_use(
        &identity.conversation_key,
        &approval.request_id,
    );
    let detached = crate::codemode::active();
    let raised = match planes.consent.open_card_for(live.session(), &subject) {
        Some(open) => Ok(open.elicitation_id),
        None if detached => session.raise_detached(card, &subject).await,
        None => session.raise(card, &subject).await,
    };
    let id = match raised {
        Ok(id) => id,
        Err(ending) => return not_approved(planes, facts, &ending).await,
    };
    if let Err(ending) = crate::codemode::prepare_consent(&id, CardKind::SecretUse).await {
        return not_approved(planes, facts, &ending).await;
    }
    let pending = || {
        let reply = crate::cingulate_client::desk::pending_reply(&id);
        async move { browser.finish_fill_reply(browser.fill_reply(identity, Ok(reply)).await) }
    };
    if detached {
        return pending().await;
    }
    let mut drain = planes.drain_signal.subscribe();
    let mut draining = false;
    let cancelled = async {
        tokio::select! {
            biased;
            _ = drain.wait_for(|value| *value) => { draining = true; LetGo::Withdraw },
            _ = cancel.cancelled() => if planes.routes.get(request.0, request.1).is_some() && planes.routes.carries_conversation(&identity.conversation_key) { LetGo::Detach } else { LetGo::Withdraw },
        }
    };
    let guard = crate::call_context::ROUTE_GUARD.try_with(Arc::clone).ok();
    let parked = guard.as_ref().map(|guard| guard.park_on_consent());
    let ending = session.park(&id, park_limit, cancelled).await;
    drop(parked);
    match ending {
        InCall::Settled(Ending::Granted { .. }) => {
            let _ = planes.consent.mark_applied(&id);
            // The vault recorded the approval from the person's answer; asked
            // again, it releases the login.
            let result = match browser.check_planned_login(identity, &plan).await {
                Err(error) => Err(error),
                Ok(()) => match ask(source, secret_use).await {
                    Ok(SecretUseAnswer::Released(material)) => {
                        browser.fill_planned_login(identity, plan, material).await
                    }
                    Ok(_) => Err(BrowserError::FillRefused(FillRefusal::LoginUnavailable)),
                    Err(SourceUnavailable) => {
                        Err(BrowserError::FillRefused(FillRefusal::VaultUnavailable))
                    }
                },
            };
            let (execution, reason) = if result.is_ok() {
                (Execution::Executed, None)
            } else {
                (
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::RefusedAtDispatch),
                )
            };
            let _ = session
                .report_execution_reason(&id, execution, reason)
                .await;
            browser.finish_fill_reply(browser.fill_reply(identity, result).await)
        }
        InCall::Pending { .. } => pending().await,
        InCall::Cancelled if !draining => {
            // Stopping the call did not decline the approval.
            let reply = browser
                .fill_reply(identity, Ok(json!({"outcome": "cancelled"})))
                .await;
            browser.finish_fill_reply(reply)
        }
        InCall::Settled(ending) => {
            let _ = planes.consent.mark_applied(&id);
            not_approved(planes, facts, &ending).await
        }
        InCall::Cancelled => {
            refuse(
                planes,
                facts,
                FillRefusal::ApprovalNotGiven {
                    decision: "module_draining",
                    asked: true,
                },
            )
            .await
        }
        InCall::RouteClosed => {
            refuse(
                planes,
                facts,
                FillRefusal::ApprovalNotGiven {
                    decision: "route_closed",
                    asked: true,
                },
            )
            .await
        }
    }
}
