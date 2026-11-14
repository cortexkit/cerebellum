use super::*;
use std::sync::Condvar;
use std::thread::ThreadId;
use tokio::sync::Notify;

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<u8>>,
    sessions: Mutex<Vec<(u8, &'static str, ThreadId)>>,
    statuses: Mutex<Vec<Vec<Token>>>,
    status_failure: AtomicBool,
    status_block: Option<Arc<Block>>,
}

enum Request {
    Read(u8),
    Block(u8, Arc<Block>),
    Fail,
    Panic,
}

struct Session<'a>(&'a Fake, u8);

impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.0.record(self.1, "drop");
    }
}

impl Fake {
    fn record(&self, id: u8, event: &'static str) {
        self.sessions
            .lock()
            .unwrap()
            .push((id, event, std::thread::current().id()));
    }
}

impl Source for Fake {
    type Request = Request;
    type Reply = u8;
    type Status = Vec<Token>;
    type Error = ();

    fn request(&self, request: Request) -> Result<u8, ()> {
        let (id, block) = match request {
            Request::Read(id) => (id, None),
            Request::Block(id, block) => (id, Some(block)),
            Request::Fail => return Err(()),
            Request::Panic => panic!("fake source failed on its worker"),
        };
        self.calls.lock().unwrap().push(id);
        self.record(id, "open");
        let _session = Session(self, id);
        self.record(id, "use");
        if let Some(block) = block {
            block.wait();
        }
        Ok(id)
    }

    fn status(&self, tokens: &'static [Token]) -> Result<Vec<Token>, ()> {
        self.statuses.lock().unwrap().push(tokens.to_vec());
        if let Some(block) = &self.status_block {
            block.wait();
        }
        if self.status_failure.load(Ordering::SeqCst) {
            Err(())
        } else {
            Ok(tokens.to_vec())
        }
    }
}

#[derive(Default)]
struct Block {
    started: Notify,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Block {
    fn wait(&self) {
        self.started.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

// Unblock workers even if an assertion fails, so the runtime can shut down.
struct Release(Arc<Block>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn block() -> (Arc<Block>, Release) {
    let block = Arc::new(Block::default());
    (block.clone(), Release(block))
}

fn gate() -> Arc<TerminalArbiter> {
    Arc::new(TerminalArbiter::new(
        subc_protocol::Frame::build(
            subc_protocol::FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
            1,
            1,
            1,
            br#"{"method":"ability.call","params":{}}"#.to_vec(),
        )
        .unwrap(),
    ))
}

fn stop(terminal: &TerminalArbiter) {
    assert!(terminal.stop(crate::terminal_arbiter::TerminalCause::Cancelled));
    assert!(terminal.gate.stopped());
    assert!(
        !terminal.state.lock().unwrap().possibly_dispatched,
        "read-only handler marked a mutation"
    );
}

async fn lease(unit: &SourceUnit) -> SourceLease {
    unit.arrive(gate()).unwrap().wait().await.unwrap()
}

async fn worker_done(unit: &SourceUnit) {
    while !unit
        .0
        .work
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .done
        .load(Ordering::Acquire)
    {
        tokio::task::yield_now().await;
    }
}

#[test]
fn platform_units_share_one_runner_for_all_their_tokens() {
    for (platform, expected) in [
        (Platform::MacOs, &[UnitKind::Pim, UnitKind::Fda][..]),
        (Platform::Windows, &[UnitKind::Outlook][..]),
        (Platform::Linux, &[UnitKind::Eds][..]),
    ] {
        let units = SourceUnits::new(platform);
        assert_eq!(
            units.iter().map(SourceUnit::kind).collect::<Vec<_>>(),
            expected
        );
        for &token in platform.tokens() {
            let unit = units.for_token(token).unwrap();
            for &sibling in unit.kind().tokens() {
                assert!(Arc::ptr_eq(&unit.0, &units.for_token(sibling).unwrap().0));
            }
        }
        assert_eq!(
            units.iter().flat_map(|unit| unit.kind().tokens()).count(),
            platform.tokens().len()
        );
        if platform != Platform::MacOs {
            assert!(units.for_token(Token::Messages).is_none());
        }
    }
}

#[tokio::test]
async fn requests_run_in_arrival_order_even_when_waiters_are_polled_in_reverse() {
    let unit = SourceUnit::new(UnitKind::Outlook);
    let source = Arc::new(Fake::default());
    let (blocked, release) = block();
    let mut first = lease(&unit).await;
    let first_source = source.clone();
    let first_work = tokio::spawn(async move {
        first
            .request(first_source, Request::Block(1, blocked))
            .await
    });
    release.0.started.notified().await;
    let second = unit.arrive(gate()).unwrap();
    let third = unit.arrive(gate()).unwrap();
    let third_source = source.clone();
    let third_work = tokio::spawn(async move {
        third
            .wait()
            .await
            .unwrap()
            .request(third_source, Request::Read(3))
            .await
    });
    let second_source = source.clone();
    let second_work = tokio::spawn(async move {
        second
            .wait()
            .await
            .unwrap()
            .request(second_source, Request::Read(2))
            .await
    });
    tokio::task::yield_now().await;
    assert_eq!(*source.calls.lock().unwrap(), [1]);
    drop(release);
    assert_eq!(first_work.await.unwrap(), SourceOutcome::Completed(Ok(1)));
    assert_eq!(second_work.await.unwrap(), SourceOutcome::Completed(Ok(2)));
    assert_eq!(third_work.await.unwrap(), SourceOutcome::Completed(Ok(3)));
    assert_eq!(*source.calls.lock().unwrap(), [1, 2, 3]);
    let caller_thread = std::thread::current().id();
    let sessions = source.sessions.lock().unwrap();
    let (sessions, remainder) = sessions.as_chunks::<3>();
    assert!(remainder.is_empty());
    for events in sessions {
        assert_eq!(
            events.iter().map(|event| event.1).collect::<Vec<_>>(),
            ["open", "use", "drop"]
        );
        assert!(events.iter().all(|event| event.2 == events[0].2));
        assert_ne!(
            events[0].2, caller_thread,
            "source ran on the async call thread"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn queue_limit_is_ten_seconds_from_arrival_not_first_poll() {
    assert_eq!(QUEUE_LIMIT, Duration::from_secs(10));
    let unit = SourceUnit::new(UnitKind::Pim);
    let first = lease(&unit).await;
    let second = unit.arrive(gate()).unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    let waiting = tokio::spawn(second.wait());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(999)).await;
    assert!(!waiting.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(matches!(
        waiting.await.unwrap(),
        Err(QueueError::SourceTimeout)
    ));
    drop(first);
    drop(lease(&unit).await);
}

#[tokio::test(start_paused = true)]
async fn queued_stop_leaves_no_source_call_or_dispatch_mark_and_unblocks_successor() {
    assert_eq!(STOP_POLL, Duration::from_millis(250));
    let unit = SourceUnit::new(UnitKind::Eds);
    let source = Arc::new(Fake::default());
    let holder = lease(&unit).await;
    let stopped = gate();
    let ticket = unit.arrive(stopped.clone()).unwrap();
    let queued_source = source.clone();
    let waiting = tokio::spawn(async move {
        let mut lease = ticket.wait().await?;
        Ok(lease.request(queued_source, Request::Read(1)).await)
    });
    tokio::task::yield_now().await;
    let stop_time = Instant::now();
    stop(&stopped);
    tokio::time::advance(STOP_POLL).await;
    assert!(matches!(waiting.await.unwrap(), Err(QueueError::Stopped)));
    assert!(stop_time.elapsed() <= Duration::from_secs(1));
    assert!(source.calls.lock().unwrap().is_empty());
    drop(holder);
    assert_eq!(
        lease(&unit).await.request(source, Request::Read(2)).await,
        SourceOutcome::Completed(Ok(2))
    );
}

#[tokio::test]
async fn stop_after_acquisition_starts_nothing_but_dispatched_work_finishes_without_data() {
    let unit = SourceUnit::new(UnitKind::Outlook);
    let source = Arc::new(Fake::default());
    let stopped = gate();
    let mut before_dispatch = unit.arrive(stopped.clone()).unwrap().wait().await.unwrap();
    stop(&stopped);
    assert_eq!(
        before_dispatch
            .request(source.clone(), Request::Read(1))
            .await,
        SourceOutcome::Stopped
    );
    assert!(source.calls.lock().unwrap().is_empty());
    drop(before_dispatch);

    let stopped = gate();
    let mut dispatched = unit.arrive(stopped.clone()).unwrap().wait().await.unwrap();
    let (blocked, release) = block();
    let dispatched_source = source.clone();
    let work = tokio::spawn(async move {
        let outcome = dispatched
            .request(dispatched_source.clone(), Request::Block(2, blocked))
            .await;
        assert_eq!(
            dispatched
                .request(dispatched_source, Request::Read(3))
                .await,
            SourceOutcome::Stopped
        );
        outcome
    });
    release.0.started.notified().await;
    stop(&stopped);
    tokio::task::yield_now().await;
    assert!(
        !work.is_finished(),
        "stop interrupted dispatched source work"
    );
    drop(release);
    assert_eq!(work.await.unwrap(), SourceOutcome::Discarded(Ok(())));
    assert_eq!(*source.calls.lock().unwrap(), [2]);
}

#[tokio::test(start_paused = true)]
async fn source_gets_its_own_deadline_then_quarantines_without_a_second_worker() {
    deadline_quarantine(UnitKind::Outlook).await;
}

#[tokio::test(start_paused = true)]
async fn eds_source_deadline_quarantines_all_tokens_without_a_second_worker() {
    deadline_quarantine(UnitKind::Eds).await;
}

async fn deadline_quarantine(kind: UnitKind) {
    assert_eq!(SOURCE_LIMIT, Duration::from_secs(10));
    let unit = SourceUnit::new(kind);
    let source = Arc::new(Fake::default());
    let holder = lease(&unit).await;
    let delayed = unit.arrive(gate()).unwrap();
    tokio::time::advance(Duration::from_millis(9_999)).await;
    drop(holder);
    let mut delayed = delayed.wait().await.unwrap();
    assert_eq!(delayed.source_deadline() - Instant::now(), SOURCE_LIMIT);
    let (blocked, release) = block();
    let worker_source = source.clone();
    let work = tokio::spawn(async move {
        let outcome = delayed
            .request(worker_source.clone(), Request::Block(1, blocked))
            .await;
        // Retrying through the same lease must not start another thread either.
        assert_eq!(
            delayed.request(worker_source, Request::Read(2)).await,
            SourceOutcome::TimedOut
        );
        (delayed, outcome)
    });
    release.0.started.notified().await;
    let queued = unit.arrive(gate()).unwrap();
    let queued = tokio::spawn(queued.wait());
    tokio::time::advance(Duration::from_millis(9_999)).await;
    assert!(!work.is_finished());
    assert!(!unit.quarantined());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(
        unit.quarantined(),
        "status must change at the deadline, before polling the handler"
    );
    let (timed_out_lease, outcome) = work.await.unwrap();
    assert_eq!(outcome, SourceOutcome::TimedOut);
    assert!(matches!(
        queued.await.unwrap(),
        Err(QueueError::SourceTimeout)
    ));
    let now = Instant::now();
    assert!(matches!(
        unit.arrive(gate()),
        Err(QueueError::SourceTimeout)
    ));
    assert_eq!(
        unit.status(source.clone(), gate()).await,
        UnitStatus::SourceUnresponsive
    );
    assert_eq!(
        Instant::now(),
        now,
        "quarantine waited instead of refusing at once"
    );
    assert!(source.statuses.lock().unwrap().is_empty());
    assert_eq!(*source.calls.lock().unwrap(), [1]);
    drop(timed_out_lease);
    assert!(
        unit.quarantined(),
        "dropping the handler released stuck work"
    );
    drop(release);
    worker_done(&unit).await;
    assert!(!unit.quarantined());
    assert_eq!(
        lease(&unit)
            .await
            .request(source.clone(), Request::Read(3))
            .await,
        SourceOutcome::Completed(Ok(3))
    );
    assert_eq!(*source.calls.lock().unwrap(), [1, 3]);
    let sessions = source.sessions.lock().unwrap();
    let first: Vec<_> = sessions.iter().filter(|event| event.0 == 1).collect();
    assert_eq!(first.len(), 3);
    assert!(first.iter().all(|event| event.2 == first[0].2));
    assert_eq!(
        first[2].1, "drop",
        "timed-out session was not cleaned up on its worker"
    );
}

#[tokio::test]
async fn status_is_one_queued_request_for_all_tokens() {
    let unit = SourceUnit::new(UnitKind::Eds);
    let source = Arc::new(Fake::default());
    let mut holder = lease(&unit).await;
    let (blocked, release) = block();
    let holder_source = source.clone();
    let work = tokio::spawn(async move {
        holder
            .request(holder_source, Request::Block(1, blocked))
            .await
    });
    release.0.started.notified().await;
    let status_unit = unit.clone();
    let status_source = source.clone();
    let status = tokio::spawn(async move { status_unit.status(status_source, gate()).await });
    tokio::task::yield_now().await;
    assert!(!status.is_finished());
    assert!(source.statuses.lock().unwrap().is_empty());
    drop(release);
    assert_eq!(work.await.unwrap(), SourceOutcome::Completed(Ok(1)));
    assert_eq!(
        status.await.unwrap(),
        UnitStatus::Responsive(vec![Token::Calendar, Token::Reminders, Token::Contacts])
    );
    assert_eq!(
        *source.statuses.lock().unwrap(),
        [vec![Token::Calendar, Token::Reminders, Token::Contacts]]
    );
}

#[tokio::test(start_paused = true)]
async fn status_deadline_includes_queue_and_source_but_does_not_hide_another_unit() {
    let pim = SourceUnit::new(UnitKind::Pim);
    let fda = SourceUnit::new(UnitKind::Fda);
    let holder = lease(&pim).await;
    let (blocked, release) = block();
    let source = Arc::new(Fake {
        status_block: Some(blocked),
        ..Fake::default()
    });
    let status_unit = pim.clone();
    let status_source = source.clone();
    let began = Instant::now();
    let waiting = tokio::spawn(async move { status_unit.status(status_source, gate()).await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(9_999)).await;
    assert!(source.statuses.lock().unwrap().is_empty());
    drop(holder);
    release.0.started.notified().await;
    let other = Arc::new(Fake::default());
    assert_eq!(
        fda.status(other.clone(), gate()).await,
        UnitStatus::Responsive(vec![Token::Messages, Token::Mail])
    );
    tokio::time::advance(SOURCE_LIMIT).await;
    assert_eq!(waiting.await.unwrap(), UnitStatus::SourceUnresponsive);
    assert!(began.elapsed() <= QUEUE_LIMIT + SOURCE_LIMIT);
    assert_eq!(source.statuses.lock().unwrap().len(), 1);
    assert_eq!(other.statuses.lock().unwrap().len(), 1);
    drop(release);
    worker_done(&pim).await;
}

#[tokio::test]
async fn failed_status_marks_only_its_own_tokens_unresponsive() {
    let pim = SourceUnit::new(UnitKind::Pim);
    let fda = SourceUnit::new(UnitKind::Fda);
    let failed = Arc::new(Fake {
        status_failure: AtomicBool::new(true),
        ..Fake::default()
    });
    let healthy = Arc::new(Fake::default());
    let (pim_status, fda_status) = tokio::join!(
        pim.status(failed.clone(), gate()),
        fda.status(healthy.clone(), gate())
    );
    assert_eq!(pim_status, UnitStatus::SourceUnresponsive);
    assert_eq!(
        fda_status,
        UnitStatus::Responsive(vec![Token::Messages, Token::Mail])
    );
    assert_eq!(
        *failed.statuses.lock().unwrap(),
        [vec![Token::Calendar, Token::Reminders, Token::Contacts]]
    );
    assert_eq!(
        *healthy.statuses.lock().unwrap(),
        [vec![Token::Messages, Token::Mail]]
    );
}

#[tokio::test]
async fn source_failure_and_panic_release_the_worker_and_allow_the_next_request() {
    let unit = SourceUnit::new(UnitKind::Eds);
    let source = Arc::new(Fake::default());
    assert_eq!(
        lease(&unit)
            .await
            .request(source.clone(), Request::Fail)
            .await,
        SourceOutcome::Completed(Err(()))
    );
    assert_eq!(
        lease(&unit)
            .await
            .request(source.clone(), Request::Panic)
            .await,
        SourceOutcome::WorkerFailed
    );
    assert!(!unit.quarantined());
    assert_eq!(
        lease(&unit).await.request(source, Request::Read(1)).await,
        SourceOutcome::Completed(Ok(1))
    );
}
