use super::*;

// A read right after a navigation can reach the extension before the new
// document's observer is installed. These pin that a snapshot waits for it
// within OBSERVER_WAIT, refuses only at that bound, and that a navigation which
// committed never reports `refused` because its page read failed.

#[tokio::test]
async fn snapshot_waits_for_an_observer_that_arrives_late() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let plans = fixture.state.lock().unwrap().plan_count;
    fixture.state.lock().unwrap().observer_unavailable_reads = 3;
    let start = tokio::time::Instant::now();
    let (read, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(read["outcome"], "ok", "{read}");
    assert!(
        read["state_text"].as_str().unwrap().contains("Go"),
        "{read}"
    );
    // Three unobserved document reads, then the one that found the observer,
    // before the snapshot's own plans.
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.observer_unavailable_reads, 0);
    assert!(
        state.plan_count >= plans + 4,
        "{}",
        state.plan_count - plans
    );
    assert!(start.elapsed() < OBSERVER_WAIT, "{:?}", start.elapsed());
}

#[tokio::test]
async fn snapshot_refuses_an_observer_that_never_arrives_only_at_the_bound() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().observer_unavailable = true;
    let start = tokio::time::Instant::now();
    let (read, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(read["outcome"], "refused", "{read}");
    assert_eq!(read["reason"], "observer_unavailable", "{read}");
    assert!(start.elapsed() >= OBSERVER_WAIT, "{:?}", start.elapsed());
    assert!(cards.is_empty());
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

fn navigate_and_read(tab: &str) -> Value {
    json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/go","intent":"read the next page","severity":{"tier":1,"credential":false,"financial":false},"read_page":true})
}

#[tokio::test]
async fn a_committed_navigation_whose_page_read_fails_reports_the_navigation() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().fail_method = Some((
        "Accessibility.getFullAXTree",
        -32000,
        "Accessibility agent hasn't been enabled".into(),
    ));
    let (reply, cards) = fixture.call(1, navigate_and_read(&tab), "allow_30m").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["input_dispatched"], false, "{reply}");
    assert_eq!(reply["tab"], tab.as_str());
    assert_eq!(cards.len(), 1);
    let read = &reply["read_page"];
    assert_eq!(read["outcome"], "refused", "{reply}");
    assert_eq!(read["reason"], "cdp_error", "{reply}");
    assert!(
        read["remedy"]
            .as_str()
            .is_some_and(|remedy| !remedy.is_empty()),
        "{reply}"
    );
    assert!(read.get("state_text").is_none(), "{reply}");
    assert_eq!(
        fixture.state.lock().unwrap().tabs[&tab].url,
        "https://example.com/go"
    );
}

#[tokio::test]
async fn a_navigation_page_read_waits_for_an_observer_lost_during_the_capture() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    // The capture's accessibility plan and the next document read find no
    // observer, as when the landed page commits a child frame mid-read.
    fixture.state.lock().unwrap().observer_loss_on_capture = 2;
    let (reply, _) = fixture.call(1, navigate_and_read(&tab), "allow_30m").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let read = &reply["read_page"];
    assert_eq!(read["outcome"], "ok", "{reply}");
    assert!(
        read["state_text"].as_str().unwrap().contains("Go"),
        "{reply}"
    );
    assert_eq!(fixture.state.lock().unwrap().observer_unavailable_reads, 0);
}

#[tokio::test]
async fn a_committed_navigation_without_an_observer_is_reported_not_refused() {
    for read_page in [false, true] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        fixture.state.lock().unwrap().observer_lost_on_navigate = true;
        let mut args = navigate_and_read(&tab);
        args["read_page"] = json!(read_page);
        let (reply, cards) = fixture.call(1, args, "allow_30m").await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        assert!(reply.get("reason").is_none(), "{reply}");
        assert_eq!(reply["observer_available"], false, "{reply}");
        assert_eq!(
            reply["remedy"],
            "The page changed; take a snapshot before acting."
        );
        assert_eq!(reply["tab"], tab.as_str());
        assert!(reply["interaction_epoch"].is_u64(), "{reply}");
        assert_eq!(cards.len(), 1);
        if read_page {
            assert_eq!(reply["read_page"]["outcome"], "refused", "{reply}");
            assert_eq!(
                reply["read_page"]["reason"], "observer_unavailable",
                "{reply}"
            );
        } else {
            assert!(reply.get("read_page").is_none(), "{reply}");
        }
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.tabs[&tab].url, "https://example.com/go");
        assert!(state.captures.is_empty());
    }
}
