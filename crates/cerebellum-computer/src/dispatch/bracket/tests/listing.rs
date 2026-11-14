//! The bracket with a window-server listing that takes as long to read as it
//! did on a busy desktop, read through the production routing functions: the
//! listing check before the front and the per-event checks of the posts.

use super::*;
use crate::platform::{
    check_listed_before_front, post_event_sequence_with_visibility, PerProcessEventTransport,
    PostCallFailure, PostCallMade, ProcessEventTarget, ProcessGenerationReading, SyntheticStep,
    SyntheticStepRole, VisibilityMemo, WindowServerVisibility, VISIBLE_READING_MAX_AGE,
};

const GENERATION: u64 = 42;
/// One listing read on the desk clock. On a live macOS desktop with about 400
/// windows, 63 to 188 ms passed from the target landing in front to the
/// restore request for a one-chord bracket, and the listing query is the slow
/// step inside that.
const LISTING_READ_MS: u64 = 150;

/// What the listing answers, the memo the desk's posts share with its
/// pre-front check, and every read made.
pub(super) struct Listing {
    listed: WindowServerVisibility,
    memo: VisibilityMemo,
    /// The desk-clock instant of each read, and whether the target was
    /// frontmost when it was made.
    reads: Vec<(u64, bool)>,
}

impl Listing {
    fn new(listed: WindowServerVisibility, memo: VisibilityMemo) -> Self {
        Self {
            listed,
            memo,
            reads: Vec::new(),
        }
    }
}

/// The desk as a per-process transport: a listing read costs
/// `LISTING_READ_MS` on the desk's clock, and every post call returns.
struct DeskTransport<'a> {
    now: &'a mut u64,
    target_frontmost: bool,
    listed: &'a WindowServerVisibility,
    reads: &'a mut Vec<(u64, bool)>,
}

impl PerProcessEventTransport for DeskTransport<'_> {
    type Event = ();

    fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
        ProcessGenerationReading::Started(GENERATION)
    }
    fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
        self.reads.push((*self.now, self.target_frontmost));
        *self.now += LISTING_READ_MS;
        self.listed.clone()
    }
    fn post_to_pid(&mut self, _pid: u32, _event: ()) -> Result<PostCallMade, PostCallFailure> {
        Ok(PostCallMade::public_core_graphics())
    }
}

fn target() -> ProcessEventTarget {
    ProcessEventTarget {
        pid: TARGET,
        start_time_micros: GENERATION,
    }
}

/// The desk's `before_front`: the production listing check, when the desk
/// has a listing.
pub(super) fn before_front(desk: &mut FakeDesk) -> Result<(), SequencePostFailure> {
    let target_frontmost = desk.frontmost == Some(TARGET);
    let FakeDesk { now, listing, .. } = desk;
    let Some(Listing {
        listed,
        memo,
        reads,
    }) = listing.as_mut()
    else {
        return Ok(());
    };
    let mut transport = DeskTransport {
        now,
        target_frontmost,
        listed,
        reads,
    };
    check_listed_before_front(target(), &mut transport, memo).map_err(|refusal| {
        SequencePostFailure {
            posts_returned: 0,
            refusal,
            held_state: HeldStateDisposition::NoneHeld,
        }
    })
}

/// The desk's chord post: a press and its release through the production
/// sequence routing with the desk's listing memo, or the desk's fixed report
/// when it has no listing.
pub(super) fn post_chord(desk: &mut FakeDesk) -> Result<UnitPosted, SequencePostFailure> {
    let target_frontmost = desk.frontmost == Some(TARGET);
    let FakeDesk { now, listing, .. } = desk;
    let Some(Listing {
        listed,
        memo,
        reads,
    }) = listing.as_mut()
    else {
        return Ok(UnitPosted {
            posts_returned: 2,
            generation_verifications: 4,
        });
    };
    let mut transport = DeskTransport {
        now,
        target_frontmost,
        listed,
        reads,
    };
    let steps = vec![
        SyntheticStep {
            role: SyntheticStepRole::Press,
            event: (),
        },
        SyntheticStep {
            role: SyntheticStepRole::Release,
            event: (),
        },
    ];
    let report =
        post_event_sequence_with_visibility(target(), steps, &mut transport, memo, &|| false)?;
    Ok(UnitPosted {
        posts_returned: report.posts_returned,
        generation_verifications: report.generation_verifications,
    })
}

/// The listing is read once, before the front, while the person's
/// application is still in front; the chord's posts reuse that reading, so
/// the 150 ms query is not inside the fronted interval and the bracket holds
/// its bound.
#[test]
fn a_slow_listing_is_read_before_the_front_and_kept_out_of_the_fronted_interval() {
    let mut desk = FakeDesk::new();
    desk.listing = Some(Listing::new(
        WindowServerVisibility::Visible,
        VisibilityMemo::new(VISIBLE_READING_MAX_AGE),
    ));
    let report = run(&mut desk, 1);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.posts_returned, 2, "{report:?}");
    let reads = &desk.listing.as_ref().unwrap().reads;
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(!reads[0].1, "the listing was read with the target in front");
    assert_eq!(
        desk.fronted_intervals.len(),
        1,
        "{:?}",
        desk.fronted_intervals
    );
    assert!(
        desk.fronted_intervals[0] < LISTING_READ_MS,
        "{:?}",
        desk.fronted_intervals
    );
    assert!(
        report.longest_fronted_interval_ms < LISTING_READ_MS,
        "{report:?}"
    );
    assert!(report.held(100), "{report:?}");
}

/// A target the window server does not list, or a listing that cannot be
/// read, refuses before anything is fronted or posted, with the same refusal
/// the post would have made.
#[test]
fn a_target_the_window_server_does_not_list_is_never_fronted() {
    let cases = [
        (
            WindowServerVisibility::NotVisible,
            ProcessEventRefusal::NotVisibleToWindowServer,
        ),
        (
            WindowServerVisibility::Unreadable("no answer".into()),
            ProcessEventRefusal::WindowServerUnreadable {
                reason: "no answer".into(),
            },
        ),
    ];
    for (listed, refusal) in cases {
        let mut desk = FakeDesk::new();
        desk.listing = Some(Listing::new(
            listed,
            VisibilityMemo::new(VISIBLE_READING_MAX_AGE),
        ));
        let report = run(&mut desk, 1);
        assert_eq!(
            report.stop,
            Some(BracketStop::PostFailed(SequencePostFailure {
                posts_returned: 0,
                refusal,
                held_state: HeldStateDisposition::NoneHeld,
            })),
            "{report:?}"
        );
        assert!(desk.front_requests.is_empty(), "{:?}", desk.front_requests);
        assert!(desk.posted.is_empty(), "{:?}", desk.posted);
        assert_eq!(report.chunks, 0, "{report:?}");
        assert_eq!(report.restore, RestoreStatus::NotNeeded, "{report:?}");
        assert_eq!(desk.frontmost, Some(PREVIOUS));
    }
}

/// The check before the front never replaces the post's own check: a reading
/// that has expired by the first post is read again there, and every event
/// keeps its generation checks.
#[test]
fn an_expired_listing_is_read_again_by_the_post() {
    let mut desk = FakeDesk::new();
    // A memo that keeps nothing: every listing reading expires at once.
    desk.listing = Some(Listing::new(
        WindowServerVisibility::Visible,
        VisibilityMemo::uncached(),
    ));
    let report = run(&mut desk, 1);
    let reads = &desk.listing.as_ref().unwrap().reads;
    let frontmost_at_reads: Vec<bool> = reads.iter().map(|(_, front)| *front).collect();
    assert_eq!(frontmost_at_reads, vec![false, true, true], "{reads:?}");
    assert_eq!(report.posts_returned, 2, "{report:?}");
    assert_eq!(report.generation_verifications, 4, "{report:?}");
}
