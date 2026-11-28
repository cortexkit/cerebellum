//! Expose real native computer dispatch/consent futures to the 16 KiB size
//! check, and poll an actual held computer call on a 1 MiB thread stack.

use super::*;

pub(crate) fn future_sizes() -> Vec<(&'static str, usize)> {
    let planes = planes_without_cards();
    let request = wait_request();
    let (tx, _rx) = mpsc::channel(8);
    let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();
    let call = CallObservation::new();
    let arguments: Value = serde_json::from_slice(&request.body).unwrap();
    let arguments = &arguments["arguments"];
    let context = computer_capability::ServeContext {
        cancel: CancelHandle::pending(),
        grantee: &facts.identity.agent_project_id,
        identity: cerebellum_core::journal::JournalIdentity {
            witness: call.dispatch.clone(),
            principal: String::new(),
            conversation_key: facts.identity.conversation_key.clone(),
            agent_project_id: facts.identity.agent_project_id.clone(),
            session_kind: facts.identity.session_kind,
            origin: facts.identity.origin.clone(),
            computer_order: None,
        },
        management: &planes.management,
        consent: consent_context(&planes, &facts, &tx, CHANNEL, EPOCH),
        clock: planes.lease_clock.as_ref(),
        now_ms: 0,
    };
    let cancel = CancelHandle::pending();
    let need = computer_grants::GrantNeed::App {
        bundle_identity: APP.into(),
        display_name: APP.into(),
        code: Arc::new(computer_grants::SignedByFixtureTeam),
    };
    let mut sizes = vec![
        (
            "handle_tool_request_enforced",
            std::mem::size_of_val(&handle_tool_request_enforced(
                request.clone(),
                &tx,
                &planes,
                &call,
            )),
        ),
        (
            "ManagementPlane::admit_app",
            std::mem::size_of_val(&planes.management.admit_app(APP, &context.consent, &cancel)),
        ),
        (
            "ComputerGrants::require",
            std::mem::size_of_val(&planes.management.computer_grants().require(
                &need,
                &context.consent,
                &cancel,
            )),
        ),
        (
            "ComputerGrants::require_takeover_dispatch",
            std::mem::size_of_val(
                &planes
                    .management
                    .computer_grants()
                    .require_takeover_dispatch(
                        cerebellum_core::consent::TakeoverAction::Move,
                        &context.consent,
                        &cancel,
                    ),
            ),
        ),
    ];
    sizes.extend(computer_capability::future_size_tests::sizes(
        planes.computer.as_ref().unwrap(),
        arguments,
        context,
    ));
    sizes
}

/// A native computer call must retain half of the default 2 MiB test-thread
/// stack for its caller. It must actually ask, withdraw and apply a late answer;
/// measuring an unpolled future alone cannot account for nested poll frames.
#[test]
fn a_computer_consent_call_fits_half_a_default_thread_stack() {
    let call = std::thread::Builder::new()
        .name("computer-consent-stack-budget".into())
        .stack_size(1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    // The stack proof must not depend on sandbox access to the
                    // platform's temporary directory for its card registry.
                    let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../target/computer-consent-stack-tests");
                    let planes = computer_grants::tests::CardService::install_in(
                        planes_without_cards(),
                        CHANNEL,
                        EPOCH,
                        scratch,
                    );
                    withdraw_asked_call_and_apply_late_grant(planes).await;
                })
        })
        .unwrap();
    call.join()
        .expect("the computer call completed consent and late settlement");
}

#[tokio::test]
async fn an_unrelated_fixture_commit_preserves_the_asked_computer_call() {
    let planes = planes();
    // Place a direct-plane fixture commit between the keyed call's admission
    // and settlement. Its witness must not invalidate another call's evidence.
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    *planes.call_record_workers.before_settlement.lock().unwrap() = Some(Box::new(move || {
        barrier.wait();
        barrier.wait();
    }));
    let commit = std::thread::spawn(move || {
        other.wait();
        crate::fixture_dispatch_witness().mark_committed();
        other.wait();
    });
    withdraw_asked_call_and_apply_late_grant(planes).await;
    commit.join().unwrap();
}

pub(super) async fn withdraw_asked_call_and_apply_late_grant(planes: Planes) {
    let unattributed_before = cerebellum_core::dispatch_witness::unattributed_commit_count();
    let (tx, mut rx) = mpsc::channel(8);
    let mut request = wait_request();
    let mut body: Value = serde_json::from_slice(&request.body).unwrap();
    body["call_key"] = json!("pf:computer-pending");
    request.body = serde_json::to_vec(&body).unwrap();
    COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST
        .scope(
            Duration::from_millis(20),
            computer_grants::tests::with_live(handle_tool_request_for_test_with_existing_planes(
                request, &tx, &planes,
            )),
        )
        .await
        .unwrap();
    let question = planes
        .consent_test
        .as_ref()
        .unwrap()
        .card(CHANNEL, EPOCH)
        .await;
    assert_eq!(question.header.ty, FrameType::Request);
    assert_eq!(reply(&mut rx).await["outcome"], "consent_pending");
    handle_frame(
        frame(
            FrameType::Request,
            CHANNEL,
            CORR + 1,
            json!({"name":"tool.withdraw", "arguments":{"call_key":"pf:computer-pending"}}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let withdrawn: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(
        withdrawn["answer"],
        "withdrawn",
        "lookup observations: {:?}; unattributed commits before={unattributed_before} after={}",
        planes
            .call_record_workers
            .lookup_observations
            .lock()
            .unwrap(),
        cerebellum_core::dispatch_witness::unattributed_commit_count()
    );
    assert!(planes.consent_test.as_ref().unwrap().answer(
        question.header.corr,
        cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"})),
    ));
    computer_grants::tests::drain_call(&planes, CHANNEL, EPOCH).await;
    let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();
    let caller = computer_grants::GrantCaller {
        holder: permission_scope::authorizing_holder(&facts),
        conversation_key: facts.identity.conversation_key,
        agent_project_id: facts.identity.agent_project_id,
        durable_identity_attested: true,
    };
    let need = computer_grants::GrantNeed::App {
        bundle_identity: APP.into(),
        display_name: APP.into(),
        code: Arc::new(computer_grants::SignedByFixtureTeam),
    };
    tokio::time::timeout(HANG_GUARD, async {
        while !planes.management.computer_grants().holds(&caller, &need) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the late answer records the app grant");
    assert!(
        rx.try_recv().is_err(),
        "no cancelled card or resumed action"
    );
    settle_to(&planes, (0, 0)).await;
    let unattributed_after = cerebellum_core::dispatch_witness::unattributed_commit_count();
    assert_eq!(
        unattributed_after, unattributed_before,
        "a concurrent fixture committed a detached dispatch witness"
    );
    eprintln!(
        "consent dispatch isolation: test={} before={unattributed_before} after={unattributed_after} delta={}",
        std::thread::current().name().unwrap_or("unnamed"),
        unattributed_after - unattributed_before
    );
}
