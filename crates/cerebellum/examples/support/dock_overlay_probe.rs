//! Measure whether a picture bracket's own front dismisses a Dock overlay.

use std::future::Future;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use cerebellum::desk_probe::{
    begin_dock_overlay_bracket_probe, take_fronting_timings, take_picture_bracket_probe,
};
use cerebellum_computer::dispatch::{BracketStop, RestoreStatus};
use cerebellum_macos::dock_overlay_probe::{AlphaSample, DockOverlayWitness};
use cerebellum_macos::{
    frontmost_process_id, screen_is_locked, visible_window_frame, SessionEventTap,
};
use serde_json::{json, Value};

const STATES: [&str; 3] = ["mission_control", "app_expose", "show_desktop"];
const ROUNDS_PER_STATE: usize = 3;
const ROUNDS: usize = STATES.len() * ROUNDS_PER_STATE;
const ATTEMPTS: usize = 12;
const SETTLE: Duration = Duration::from_secs(2);
const WAIT: Duration = Duration::from_secs(45);
const POLL: Duration = Duration::from_millis(100);
const SAMPLE_WAIT: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(1100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alpha {
    Opaque,
    Transparent,
    Mixed,
}

impl Alpha {
    fn as_str(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::Transparent => "transparent",
            Self::Mixed => "mixed",
        }
    }
}

fn classify(total: usize, opaque: usize, transparent: usize) -> Alpha {
    // A small edge or rounding fringe is tolerable, not a partly drawn
    // overlay. Require at least 99% of the rect at the appropriate extreme.
    let required = total - total / 100;
    if total > 0 && opaque >= required {
        Alpha::Opaque
    } else if total > 0 && transparent >= required {
        Alpha::Transparent
    } else {
        Alpha::Mixed
    }
}

fn alpha(sample: &AlphaSample) -> Alpha {
    classify(sample.total, sample.near_opaque, sample.near_transparent)
}

fn reading(sample: &AlphaSample, front: Option<Instant>) -> Value {
    let offset = |at: Instant| {
        front.map(|start| {
            at.checked_duration_since(start).map_or_else(
                || -start.duration_since(at).as_secs_f64() * 1000.0,
                |elapsed| elapsed.as_secs_f64() * 1000.0,
            )
        })
    };
    json!({
        "alpha": alpha(sample).as_str(),
        "pixels": sample.total,
        "near_opaque": sample.near_opaque,
        "near_transparent": sample.near_transparent,
        "requested_ms": offset(sample.requested_at),
        "frame_arrived_ms": offset(sample.frame_arrived_at),
        "returned_ms": offset(sample.returned_at),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Dismissed,
    Survived,
    Uncounted,
    Stop,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dismissed => "dismissed",
            Self::Survived => "survived",
            Self::Uncounted => "uncounted",
            Self::Stop => "unmeasurable",
        }
    }
}

#[derive(Default)]
struct Tally {
    dismissed: usize,
    survived: usize,
    planned_counts: [(usize, usize); STATES.len()],
    records: Vec<Value>,
}

impl Tally {
    fn next(&self) -> Option<(usize, usize)> {
        let complete = self.dismissed + self.survived;
        (complete < ROUNDS && self.records.len() < ATTEMPTS)
            .then_some((complete + 1, self.records.len() + 1))
    }

    fn record(&mut self, verdict: Verdict, record: Value) {
        let state = (self.dismissed + self.survived) / ROUNDS_PER_STATE;
        if verdict == Verdict::Dismissed {
            self.planned_counts[state].0 += 1;
            self.dismissed += 1;
        } else if verdict == Verdict::Survived {
            self.planned_counts[state].1 += 1;
            self.survived += 1;
        }
        self.records.push(record);
    }

    fn summary(&self, stop: Option<&str>) -> (i32, Value) {
        let (code, verdict) = if self.survived > 0 {
            (1, "FAIL")
        } else if stop.is_none() && self.dismissed == ROUNDS {
            (0, "PASS")
        } else {
            (2, "UNMEASURABLE")
        };
        (
            code,
            json!({
                "dock_overlay_summary": verdict,
                "dismissed": self.dismissed,
                "survived": self.survived,
                "attempts": self.records.len(),
                "stop": stop,
                "by_planned_state": STATES.iter().zip(self.planned_counts).map(|(state, (dismissed, survived))| {
                    json!({"state": state, "dismissed": dismissed, "survived": survived})
                }).collect::<Vec<_>>(),
                "rounds": self.records,
            }),
        )
    }
}

struct Desk<'a> {
    witness: DockOverlayWitness,
    pid: u32,
    window: u32,
    rect: [f64; 4],
    person: i32,
    owns_scratch: &'a dyn Fn() -> bool,
}

impl Desk<'_> {
    fn verify(&self) -> Result<(), String> {
        if screen_is_locked() != Some(false) || frontmost_process_id() != Some(self.person) {
            return Err("screen lock or foreground app changed".into());
        }
        if visible_window_frame(self.pid, self.window) != Some(self.rect) {
            return Err("scratch window or its frame changed".into());
        }
        self.witness.verify_window(self.rect)
    }

    async fn wait_for(&self, wanted: Alpha, quiet: bool) -> Result<AlphaSample, String> {
        let deadline = Instant::now() + WAIT;
        let mut last = None;
        while Instant::now() < deadline {
            self.verify()?;
            let sample = self.witness.sample(
                deadline.min(Instant::now() + SAMPLE_WAIT),
                Arc::new(|| true),
            )?;
            let idle = if quiet {
                let (since, input) = SessionEventTap::hardware_input_snapshot()
                    .ok_or("hardware input observer unavailable")?;
                input.map_or(since, |input| input.max(since)).elapsed() >= QUIET
            } else {
                true
            };
            if idle && alpha(&sample) == wanted {
                return Ok(sample);
            }
            last = Some(sample);
            tokio::time::sleep(POLL).await;
        }
        Err(format!(
            "waiting for {} timed out; last reading={}",
            wanted.as_str(),
            last.as_ref()
                .map_or(Value::Null, |sample| reading(sample, None))
        ))
    }
}

struct FrontEvidence {
    record: Value,
    verdict: Verdict,
    reason: Option<String>,
}

impl FrontEvidence {
    fn stop(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

impl Desk<'_> {
    async fn front<F: Future<Output = Value>>(
        &self,
        serve: &impl Fn() -> F,
        before: AlphaSample,
    ) -> FrontEvidence {
        let mut evidence = FrontEvidence {
            record: json!({"before": reading(&before, None), "after": null}),
            verdict: Verdict::Stop,
            reason: None,
        };
        if !(self.owns_scratch)() {
            return evidence.stop("scratch ownership changed");
        }
        if let Err(error) = self.verify() {
            return evidence.stop(error);
        }
        let _ = take_fronting_timings();
        let witness = self.witness.clone();
        let (send, receive) = mpsc::channel();
        begin_dock_overlay_bracket_probe(Box::new(move |cutoff, fence| {
            let result = cutoff
                .ok_or_else(|| "picture bracket has no witness cutoff".to_string())
                .and_then(|cutoff| witness.sample(cutoff, Arc::clone(fence)));
            let _ = send.send(result);
        }));
        let reply = serve().await;
        let bracket = take_picture_bracket_probe().unwrap_or_default();
        let timings = take_fronting_timings();
        let timing = timings.iter().find(|t| t.target_pid == self.pid);
        let start = timing.and_then(|t| t.front_requested_at);
        let confirmed = timing.and_then(|t| t.confirmed_front_ms);
        let restore_requested = timing
            .and_then(|t| t.first_restore_request())
            .map(|(ms, _, _)| ms);
        let after = receive.try_recv().ok();
        let input = reply["fronting"]["person_input_during_fronting"] == true
            || start.is_some_and(|start| {
                SessionEventTap::hardware_input_snapshot().is_none_or(|(since, input)| {
                    since > start || input.is_some_and(|input| input >= start)
                })
            });
        let report = bracket.bracket.as_ref();
        evidence.record = json!({
            "before": reading(&before, start),
            "after": after.as_ref().and_then(|result| result.as_ref().ok()).map(|s| reading(s, start)),
            "after_error": after.as_ref().and_then(|result| result.as_ref().err()),
            "front_confirmed_ms": confirmed,
            "restore_requested_ms": restore_requested,
            "restore_confirmed_ms": timing.and_then(|t| t.restore_confirmed_ms),
            "restore_calibrated": report.map(|r| r.restore_calibrated),
            "restore": report.map(|r| format!("{:?}", r.restore)),
            "bracket_stop": report.and_then(|r| r.stop.as_ref()).map(|stop| format!("{stop:?}")),
            "fronting_reason": reply["fronting"]["not_fronted_reason"],
            "input_interrupted": input,
        });
        if input
            || report.is_some_and(|r| {
                matches!(r.stop, Some(BracketStop::Aborted(_)))
                    || matches!(r.restore, RestoreStatus::SkippedPerson { .. })
            })
        {
            return evidence.stop("front interrupted by input or observer refusal");
        }
        let (Some(report), Some(start), Some(confirmed)) = (report, start, confirmed) else {
            return evidence.stop("picture bracket did not confirm a front");
        };
        if report.previous_frontmost != u32::try_from(self.person).ok()
            || report.restore != RestoreStatus::Restored
        {
            return evidence.stop("picture bracket did not restore the original app");
        }
        if let Err(error) = self.verify() {
            return evidence.stop(error);
        }
        let after = match after {
            None if report.restore_calibrated => {
                evidence.verdict = Verdict::Uncounted;
                evidence.reason = Some("restore calibration had no post-front sample".into());
                return evidence;
            }
            None => return evidence.stop("picture bracket did not invoke the Dock witness"),
            Some(Err(error)) => return evidence.stop(error),
            Some(Ok(after)) => after,
        };
        let offset = |at: Instant| at.saturating_duration_since(start).as_secs_f64() * 1000.0;
        if before.returned_at >= start
            || offset(after.requested_at) < confirmed
            || restore_requested.is_none_or(|restore| offset(after.returned_at) >= restore)
            || report.stop.is_some()
            || report.restore_started_by_cutoff
        {
            return evidence.stop("Dock readings were not bounded by confirmed front and restore");
        }
        evidence.verdict = match alpha(&after) {
            Alpha::Transparent => Verdict::Dismissed,
            Alpha::Opaque => Verdict::Survived,
            Alpha::Mixed => {
                return evidence.stop("post-front alpha was neither transparent nor opaque")
            }
        };
        evidence
    }
}

pub(super) async fn run<F: Future<Output = Value>>(
    pid: u32,
    person: i32,
    owns_scratch: impl Fn() -> bool,
    serve: impl Fn() -> F,
) -> i32 {
    let mut tally = Tally::default();
    let result = rounds(pid, person, &owns_scratch, &serve, &mut tally).await;
    let (code, summary) = tally.summary(result.as_ref().err().map(String::as_str));
    println!("{summary}");
    code
}

async fn rounds<F: Future<Output = Value>>(
    pid: u32,
    person: i32,
    owns_scratch: &dyn Fn() -> bool,
    serve: &impl Fn() -> F,
    tally: &mut Tally,
) -> Result<(), String> {
    if !owns_scratch() {
        return Err("scratch ownership changed".into());
    }
    let window = cerebellum_macos::frontmost_window_id(pid).ok_or("no scratch window on screen")?;
    let rect = visible_window_frame(pid, window).ok_or("no scratch window frame")?;
    let witness = DockOverlayWitness::prepare(rect)?;
    println!(
        "{}",
        json!({"dock_overlay_setup": {
            "dock_pid": witness.dock_pid, "dock_window": witness.window_id,
            "dock_rect": witness.window_rect, "scratch_window": window, "scratch_rect": rect,
        }})
    );
    let desk = Desk {
        witness,
        pid,
        window,
        rect,
        person,
        owns_scratch,
    };
    println!("CALIBRATION: leave Dock overlays closed and stand by");
    let before = desk.wait_for(Alpha::Transparent, true).await?;
    let mut calibration = desk.front(serve, before).await;
    calibration.record["calibration"] = json!(true);
    let calibration_result = match calibration.verdict {
        Verdict::Uncounted => "restore_calibrated",
        Verdict::Dismissed => "transparent",
        Verdict::Survived => "opaque",
        Verdict::Stop => "unmeasurable",
    };
    calibration.record["result"] = json!(calibration_result);
    calibration.record["reason"] = json!(calibration.reason);
    println!("{}", calibration.record);
    if !matches!(calibration.verdict, Verdict::Uncounted | Verdict::Dismissed) {
        return Err(calibration
            .reason
            .unwrap_or_else(|| "calibration did not remain transparent".into()));
    }

    while let Some((round, attempt)) = tally.next() {
        tokio::time::sleep(SETTLE).await;
        println!("WAIT round={round} attempt={attempt}: keep or return to the normal desktop");
        let clear = desk.wait_for(Alpha::Transparent, false).await?;
        println!(
            "{}",
            json!({"dock_overlay_ready": round, "attempt": attempt, "baseline": reading(&clear, None)})
        );
        let before = desk.wait_for(Alpha::Opaque, true).await?;
        let mut front = desk.front(serve, before).await;
        front.record["round"] = json!(round);
        front.record["attempt"] = json!(attempt);
        front.record["result"] = json!(front.verdict.as_str());
        front.record["reason"] = json!(front.reason);
        println!("{}", front.record);
        tally.record(front.verdict, front.record);
        if front.verdict == Verdict::Stop {
            return Err(front
                .reason
                .unwrap_or_else(|| "front not measurable".into()));
        }
    }
    if tally.dismissed + tally.survived < ROUNDS {
        return Err("attempt cap reached before nine measured rounds".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_witness_requires_99_percent_at_one_extreme() {
        assert_eq!(classify(100, 99, 0), Alpha::Opaque);
        assert_eq!(classify(100, 0, 99), Alpha::Transparent);
        assert_eq!(classify(100, 98, 1), Alpha::Mixed);
        assert_eq!(classify(100, 0, 98), Alpha::Mixed);
        assert_eq!(classify(99, 98, 0), Alpha::Mixed);
        assert_eq!(classify(0, 0, 0), Alpha::Mixed);
    }

    #[test]
    fn uncounted_fronts_repeat_the_round_but_use_the_attempt_cap() {
        let mut tally = Tally::default();
        for attempt in 1..=12 {
            assert_eq!(tally.next(), Some((1, attempt)));
            tally.record(Verdict::Uncounted, json!({"round": 1, "attempt": attempt}));
        }
        assert_eq!(tally.next(), None);
        let (code, summary) = tally.summary(Some("attempt cap"));
        assert_eq!(code, 2);
        assert_eq!(summary["dock_overlay_summary"], "UNMEASURABLE");
        assert_eq!(summary["rounds"].as_array().unwrap().len(), 12);
    }

    #[test]
    fn nine_dismissals_pass_but_one_survival_fails_even_if_later_stopped() {
        let mut tally = Tally::default();
        for round in 1..=9 {
            assert_eq!(tally.next(), Some((round, round)));
            tally.record(Verdict::Dismissed, json!({"round": round}));
        }
        assert_eq!(tally.next(), None);
        assert_eq!(tally.summary(None).0, 0);
        assert_eq!(
            tally.summary(None).1["by_planned_state"][1],
            json!({
                "state": "app_expose", "dismissed": 3, "survived": 0,
            })
        );
        let mut tally = Tally::default();
        tally.record(Verdict::Survived, json!({"round": 1}));
        assert_eq!(tally.next(), Some((2, 2)));
        let (code, summary) = tally.summary(Some("input interrupted"));
        assert_eq!(code, 1);
        assert_eq!(summary["dock_overlay_summary"], "FAIL");
        assert_eq!(summary["survived"], 1);
    }
}
