//! Resume only live held browser calls, through the ordinary request boundary.

use crate::*;
mod tasks;
pub(crate) use tasks::Tasks;

tokio::task_local! {
    static RESUMING: ResumeContext;
}

type DispatchEvidence = (
    cerebellum_core::dispatch_witness::DispatchWitness,
    Arc<std::sync::atomic::AtomicBool>,
);

#[derive(Clone)]
pub(crate) struct ResumeContext {
    ask_id: String,
    call_key: String,
    dispatch: Arc<std::sync::Mutex<Option<DispatchEvidence>>>,
}

pub(crate) fn resuming() -> bool {
    RESUMING.try_with(|_| true).unwrap_or(false)
}

pub(crate) fn context() -> Option<ResumeContext> {
    RESUMING.try_with(Clone::clone).ok()
}

pub(crate) async fn with_context<F: std::future::Future>(
    context: Option<ResumeContext>,
    future: F,
) -> F::Output {
    match context {
        Some(context) => {
            let key = context.call_key.clone();
            RESUMING
                .scope(context, call_context::CALL_KEY.scope(key, future))
                .await
        }
        None => future.await,
    }
}

pub(crate) fn track_consent(planes: &Planes) {
    if let Ok(context) = RESUMING.try_with(Clone::clone) {
        if let Some(terminal) = TerminalArbiter::current() {
            *context.dispatch.lock().unwrap() = Some((
                terminal.witness.clone(),
                Arc::clone(&terminal.gate_dispatched),
            ));
            terminal.track_consent(Arc::clone(&planes.consent), &context.ask_id);
        }
    }
}

/// Actions naming an element reference retain the original snapshot id so
/// normal dispatch checks the same target again.
/// Coordinates describe an old picture, which cannot be re-verified safely.
pub(crate) fn can_resume(arguments: &Value) -> bool {
    arguments["action"] != "click_point"
        && !["point", "x_px", "y_px", "image_width_px", "image_height_px"]
            .iter()
            .any(|key| arguments.get(key).is_some())
}

pub(crate) fn retain(planes: &Planes, facts: &AcceptedBindFacts, call_key: &str, frame: &Frame) {
    let Ok(body) = serde_json::from_slice::<Value>(&frame.body) else {
        return;
    };
    if body["name"] != flat_tools::BROWSER_USE
        || facts.codemode_head.is_none()
        || !cortexkit_role_tool_provider::consumer_reads_held_reply_v1(
            facts.consumer_capabilities(),
        )
    {
        return;
    }
    let Some(bind_sequence) = planes
        .routes
        .bind_sequence(frame.header.channel, frame.header.epoch)
    else {
        return;
    };
    let Ok(head) = codemode::user_browser_route(planes, frame.header.channel, frame.header.epoch)
    else {
        return;
    };
    let Some(head_sequence) = planes.routes.bind_sequence(head.channel, head.epoch) else {
        return;
    };
    let hold = (body["arguments"]["browser"] != "user")
        .then(|| {
            planes.sessions.idle_hold(
                &facts.identity.conversation_key,
                Arc::clone(&planes.lease_clock),
            )
        })
        .flatten()
        .map(|idle| journal::call_records::BrowserHold {
            idle,
            request: (frame.header.channel, frame.header.epoch, frame.header.corr),
            head_route: (head.channel, head.epoch),
            head_scope: facts
                .codemode_head
                .as_ref()
                .and_then(|head| head.scope.as_ref())
                .map(journal::call_records::ScopeIdentity::from_stamp),
        });
    let resume = can_resume(&body["arguments"]).then(|| journal::call_records::BrowserResume {
        frame: frame.clone(),
        facts: facts.clone(),
        bind_sequence,
        head: Some(((head.channel, head.epoch), head_sequence)),
        approved: false,
        ask_id: String::new(),
        created: std::time::Instant::now(),
        idle_hold: None,
    });
    if hold.is_none() && resume.is_none() {
        return;
    }
    planes.calls.retain_browser_request(
        &journal::call_records::principal_label(facts.principal.as_ref()),
        call_key,
        resume,
        hold,
        &planes.browser_resumes,
    );
}

fn still_live(planes: &Planes, resume: &journal::call_records::BrowserResume) -> bool {
    let header = &resume.frame.header;
    resume.created.elapsed() <= journal::call_records::CACHE_MAX_AGE
        && planes.routes.get(header.channel, header.epoch).as_ref() == Some(&resume.facts)
        && planes.routes.bind_sequence(header.channel, header.epoch) == Some(resume.bind_sequence)
        && resume
            .facts
            .scope
            .as_ref()
            .is_some_and(|scope| !planes.scopes.is_superseded(scope))
        && resume.head.is_some_and(|((channel, epoch), sequence)| {
            planes.routes.bind_sequence(channel, epoch) == Some(sequence)
        })
        && codemode::user_browser_route(planes, header.channel, header.epoch).is_ok()
}

pub(crate) fn run_ready(
    planes: &Planes,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
    Box::pin(async move {
        for (principal, call_key) in planes.calls.approved_browser_requests() {
            let Some(bytes) = planes.calls.browser_request_bytes(&principal, &call_key) else {
                continue;
            };
            let Some(reservation) = planes
                .browser_resumes
                .reserve((principal.clone(), call_key.clone()), bytes)
            else {
                continue;
            };
            let request = planes.calls.claim_browser_request(
                &principal,
                &call_key,
                wall_clock_ms(),
                |resume| still_live(planes, resume),
            );
            if let Ok(Some(resume)) = request {
                planes
                    .browser_resumes
                    .spawn(reservation, resume, planes.clone());
            }
        }
    })
}
