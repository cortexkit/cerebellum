//! A completed late capture is visible before its separate audit write.

use super::*;
use std::future::Future;

fn captured_in(export: &str, credential_id: &str) -> usize {
    export.lines()
        .map(|line| serde_json::from_str::<journal::JournalEntry>(line).expect("journal rows are JSON"))
        .filter(|entry| matches!(&entry.payload,
            Some(journal::JournalPayload::LoginCapture(payload))
                if payload.credential_id == credential_id && payload.outcome.starts_with("captured:")
        ))
        .count()
}

pub(super) async fn captured_count(planes: &Planes, credential_id: &str) -> usize {
    captured_in(
        &planes.browser.journal_export_for_test().await,
        credential_id,
    )
}

pub(super) async fn wait_for_new_capture(planes: &Planes, credential_id: &str, before: usize) {
    let mut last = String::new();
    let recorded = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            last = planes.browser.journal_export_for_test().await;
            if captured_in(&last, credential_id) > before {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        recorded.is_ok(),
        "the capture audit did not record a new row for {credential_id}: {last}"
    );
}

/// Publishing a successful capture result must not wait for its separate
/// audit write. Queue a reader ahead of that writer: callers can then see a
/// captured result while the journal snapshot still contains earlier attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_capture_result_precedes_its_asynchronous_audit() {
    let fixture = login_capture::test_support::fixture();
    fixture.launcher.script.lock().unwrap().login_poll = 8;
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_audit_work")
        .unanswered("el_audit_work");
    let planes = cingulate.planes(&fixture);
    let (tx, mut rx) = mpsc::channel(16);
    let first = capture_reply(&planes, &tx, &mut rx, 520, ollama_capture_params()).await;
    assert_eq!(first["outcome"], "consent_pending", "{first}");
    cingulate.feed(late_answer("el_audit_work", "allow"));
    await_remembered(&planes, true).await;
    assert_eq!(fixture.vault.calls(), 0);

    let mut other = ollama_capture_params();
    other["account"] = json!("personal");
    cingulate
        .raises("el_audit_personal")
        .unanswered("el_audit_personal");
    let second = capture_reply(&planes, &tx, &mut rx, 521, other).await;
    assert_eq!(second["outcome"], "consent_pending", "{second}");
    let credential = "cookie:ollama.com:work";
    let before = captured_count(&planes, credential).await;
    assert_eq!(before, 0);

    let audit = planes.browser.hold_journal_for_test().await;
    let mut snapshot = Box::pin(planes.browser.journal_export_for_test());
    // Poll once under the held mutex so this reader is queued before capture
    // can enqueue its final audit write. No timing delay chooses the winner.
    std::future::poll_fn(|cx| {
        assert!(snapshot.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    cingulate.feed(json!([])).takes_report("el_audit_work");
    let initial = capture_initial_reply(&planes, &tx, &mut rx, 522, ollama_capture_params()).await;
    assert_eq!(initial["outcome"], "capture_pending", "{initial}");
    let late = capture_stored_late(&planes, 522).await;
    assert_eq!(late["result"]["outcome"], "captured", "{late}");
    assert_eq!(fixture.vault.request_params().len(), 1);
    assert_eq!(
        fixture.vault.request_params()[0]["consent_ref"],
        "el_audit_work"
    );

    drop(audit);
    let stale = snapshot.await;
    assert_eq!(captured_in(&stale, credential), 0, "{stale}");
    wait_for_new_capture(&planes, credential, before).await;
    assert_eq!(captured_count(&planes, credential).await, 1);
    assert_eq!(
        fixture.vault.request_params().len(),
        1,
        "audit did not run another capture"
    );
    assert!(!planes.consent.has_single_use_approvals());
    assert!(!planes.management.computer_grants().remembers_login_answer());
}
