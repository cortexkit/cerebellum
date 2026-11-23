//! Approval, attempt verdicts and text-free output for the probe that
//! photographs its own TextEdit window after the foreground app covers it.

use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use cerebellum::desk_probe::PictureBracketProbe;
use cerebellum_computer::capture::AcquisitionFence;
use cerebellum_computer::dispatch::{AbortReason, BracketStop};
use cerebellum_macos::{WindowOverlapSample, WindowVisibility};
use serde_json::{json, Value};

const ROOT: &str = "/tmp/cereb-desk";
const MAX_CALLS: usize = 12;
const PICTURE_TARGET: usize = 3;
const OVERLAP_INTERVAL: Duration = Duration::from_millis(5);

pub(super) fn sample_overlap(
    pid: u32,
    generation: u64,
    window: u32,
    from: Instant,
    cutoff: Instant,
    fence: AcquisitionFence,
    send: Sender<WindowOverlapSample>,
) {
    let Ok(normal_pid) = i32::try_from(pid) else {
        return;
    };
    let still_target =
        || cerebellum_macos::process_start_time_micros(pid) == Some(generation) && fence();
    sample_overlap_until(
        from,
        cutoff,
        |next| {
            if !fence() {
                return None;
            }
            std::thread::sleep(next.saturating_duration_since(Instant::now()));
            if !still_target() || Instant::now() >= cutoff {
                return None;
            }
            let sample = cerebellum_macos::sample_window_overlap_for_probe(pid, window);
            (sample.frontmost_normal_pid == Some(normal_pid) && still_target()).then_some(sample)
        },
        |sample| send.send(sample).is_ok(),
    );
}

fn sample_overlap_until(
    from: Instant,
    cutoff: Instant,
    mut read_at: impl FnMut(Instant) -> Option<WindowOverlapSample>,
    mut record: impl FnMut(WindowOverlapSample) -> bool,
) {
    let mut next = from + OVERLAP_INTERVAL;
    while next < cutoff {
        let Some(sample) = read_at(next) else { return };
        if sample.returned_at >= cutoff {
            return;
        }
        next = sample.started_at + OVERLAP_INTERVAL;
        let uncovered = sample.visibility == WindowVisibility::FullyVisible;
        if !record(sample) || uncovered {
            return;
        }
    }
}

pub(super) fn overlap_sample_json(
    sample: &WindowOverlapSample,
    offset: impl Fn(Instant) -> Option<f64>,
) -> Value {
    json!({
        "at_ms": offset(sample.started_at),
        "read_ms": (sample.returned_at - sample.started_at).as_secs_f64() * 1000.0,
        "target_pid": sample.pid,
        "window_number": sample.window_number,
        "frontmost_normal_pid": sample.frontmost_normal_pid,
        "state": format!("{:?}", sample.visibility),
        "rule": format!("{:?}", sample.rule),
        "rectangles": sample.rectangles.iter().map(|rectangle| json!({
            "owner_pid": rectangle.owner_pid,
            "owner_name": rectangle.owner_name,
            "window_number": rectangle.window_number,
            "layer": rectangle.layer,
            "bounds": rectangle.bounds,
            "alpha": rectangle.alpha,
            "sharing_state": rectangle.sharing_state,
        })).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AttemptKind {
    IdleRefused,
    Calibration,
    Picture,
    PictureUnitNoMeasurement,
    Other,
}

impl AttemptKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::IdleRefused => "idle_refused",
            Self::Calibration => "calibration",
            Self::Picture => "picture",
            Self::PictureUnitNoMeasurement => "picture_unit_no_measurement",
            Self::Other => "other",
        }
    }
}

pub(super) fn idle_gate_refused(probe: &PictureBracketProbe) -> bool {
    matches!(
        probe.bracket.as_ref().and_then(|report| report.stop.as_ref()),
        Some(BracketStop::Aborted(abort)) if matches!(abort.reason, AbortReason::IdleGateRefused(_))
    )
}

pub(super) fn attempt_kind(probe: &PictureBracketProbe, front_confirmed: bool) -> AttemptKind {
    if idle_gate_refused(probe) {
        AttemptKind::IdleRefused
    } else if probe.bracket.as_ref().is_some_and(|b| b.restore_calibrated) {
        AttemptKind::Calibration
    } else if front_confirmed && probe.before_capture.is_some() {
        // The visibility check is the first stamp from inside the picture
        // callback. Counting it does not require an image to be returned.
        AttemptKind::Picture
    } else if probe.before_capture.is_none()
        && probe.bracket.as_ref().is_some_and(|b| b.units_posted > 0)
    {
        AttemptKind::PictureUnitNoMeasurement
    } else {
        AttemptKind::Other
    }
}

#[derive(Default)]
pub(super) struct AttemptTally {
    idle_refused: usize,
    calibration: usize,
    picture: usize,
    picture_unit_no_measurement: usize,
    other: usize,
}

impl AttemptTally {
    fn total(&self) -> usize {
        self.idle_refused
            + self.calibration
            + self.picture
            + self.picture_unit_no_measurement
            + self.other
    }

    fn reached_target(&self) -> bool {
        self.picture >= PICTURE_TARGET
    }

    pub(super) fn next_attempt(&self) -> Option<usize> {
        let total = self.total();
        (!self.reached_target() && total < MAX_CALLS).then_some(total + 1)
    }

    pub(super) fn record(&mut self, kind: AttemptKind) {
        match kind {
            AttemptKind::IdleRefused => self.idle_refused += 1,
            AttemptKind::Calibration => self.calibration += 1,
            AttemptKind::Picture => self.picture += 1,
            AttemptKind::PictureUnitNoMeasurement => self.picture_unit_no_measurement += 1,
            AttemptKind::Other => self.other += 1,
        }
    }

    pub(super) fn summary(&self) -> Value {
        json!({"picture_summary": {
            "total": self.total(),
            "idle_refused": self.idle_refused,
            "calibration": self.calibration,
            "picture": self.picture,
            "picture_unit_no_measurement": self.picture_unit_no_measurement,
            "other": self.other,
            "reached_three_pictures": self.reached_target(),
        }})
    }
}

unsafe extern "C" {
    fn geteuid() -> u32;
    fn dup2(old: i32, new: i32) -> i32;
}

fn private_directory(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_dir() && m.mode() & 0o7777 == 0o700 && m.uid() == uid)
}

fn private_data_home(root: &Path, path: &Path, uid: u32) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    path.is_absolute()
        && private_directory(path, uid)
        && path.parent().and_then(|p| p.canonicalize().ok()).as_ref() == Some(&root)
        && path.canonicalize().is_ok_and(|p| p.parent() == Some(&root))
}

/// Redirect output before any permission or desktop check. Never reuse an
/// existing file at the log path, even if it is a normal file.
pub(super) fn open_log(approved: bool, log_name: &str) -> Option<PathBuf> {
    let root = Path::new(ROOT);
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { geteuid() };
    if !private_directory(root, uid) {
        return None;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(log_name))
        .ok()?;
    // SAFETY: file owns a live descriptor; dup2 keeps its own references for
    // stdout and stderr. The probe does no further work if either fails.
    if unsafe { dup2(file.as_raw_fd(), 1) < 0 || dup2(file.as_raw_fd(), 2) < 0 } {
        return None;
    }
    let data_home = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    if approved && std::env::var_os("CK_DESK_PROBE_APPROVED").as_deref() == Some("1".as_ref()) {
        if let Some(path) = data_home.filter(|path| private_data_home(root, path, uid)) {
            return Some(path);
        }
    }
    eprintln!("REFUSED: approval flag, CK_DESK_PROBE_APPROVED=1 and private scratch XDG_DATA_HOME required");
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::app_state::image::ImageDecision;
    use cerebellum_computer::dispatch::{
        AbortDecision, BracketReport, IdleGateRefusal, RestoreStatus,
    };

    fn overlap_at(at: Instant, visibility: WindowVisibility) -> WindowOverlapSample {
        WindowOverlapSample {
            pid: 2,
            window_number: 3,
            frontmost_normal_pid: Some(2),
            started_at: at,
            returned_at: at + Duration::from_millis(1),
            visibility,
            rule: match visibility {
                WindowVisibility::FullyVisible => {
                    cerebellum_macos::VisibilityRule::NoLayerZeroOverlap
                }
                _ => cerebellum_macos::VisibilityRule::HigherLayerUnionCoverage,
            },
            rectangles: Vec::new(),
        }
    }

    #[test]
    fn overlap_sampling_records_first_uncovered_sample_and_stops() {
        let start = Instant::now();
        let mut reads = Vec::new();
        let mut recorded = Vec::new();
        sample_overlap_until(
            start,
            start + Duration::from_millis(50),
            |at| {
                reads.push((at - start).as_millis());
                Some(overlap_at(
                    at,
                    if reads.len() == 2 {
                        WindowVisibility::FullyVisible
                    } else {
                        WindowVisibility::Covered
                    },
                ))
            },
            |sample| {
                recorded.push(sample.visibility);
                true
            },
        );
        assert_eq!(reads, [5, 10]);
        assert_eq!(
            recorded,
            [WindowVisibility::Covered, WindowVisibility::FullyVisible]
        );
    }

    #[test]
    fn overlap_sampling_excludes_queries_returned_at_cutoff() {
        let start = Instant::now();
        let mut reads = Vec::new();
        let mut recorded = Vec::new();
        sample_overlap_until(
            start,
            start + Duration::from_millis(11),
            |at| {
                reads.push((at - start).as_millis());
                Some(overlap_at(at, WindowVisibility::Covered))
            },
            |sample| {
                recorded.push((sample.started_at - start).as_millis());
                true
            },
        );
        assert_eq!(reads, [5, 10]);
        assert_eq!(recorded, [5]);
    }

    fn bracket() -> BracketReport {
        BracketReport {
            previous_frontmost: Some(100),
            chunks: 0,
            units_posted: 0,
            posts_returned: 0,
            generation_verifications: 0,
            longest_fronted_interval_ms: 0,
            slowest_unit_ms: 0,
            slowest_restore_ms: 0,
            restore: RestoreStatus::NotNeeded,
            stop: None,
            waiting_out_slow_post: false,
            waiting_out_slow_restore: false,
            restore_calibrated: false,
            restore_started_by_cutoff: false,
        }
    }

    #[test]
    fn idle_refusal_is_distinct_from_other_bracket_aborts() {
        let mut report = bracket();
        let mut abort = AbortDecision {
            reason: AbortReason::IdleGateRefused(IdleGateRefusal::BelowThreshold {
                threshold_ms: 1_000,
                hid_idle_ms: 600,
                user_idle_ms: 600,
            }),
            stopped_action_index: 0,
            detection_latency_ms: None,
            platform_delivery_latency_ms: None,
            sourced_input_kind: None,
            maximum_detection_latency_ms: 50,
            queued_posts_cancelled: 0,
        };
        report.stop = Some(BracketStop::Aborted(abort));
        let mut probe = PictureBracketProbe {
            bracket: Some(report.clone()),
            ..Default::default()
        };
        assert_eq!(attempt_kind(&probe, false), AttemptKind::IdleRefused);

        abort.reason = AbortReason::UserSeizedControl;
        report.stop = Some(BracketStop::Aborted(abort));
        probe.bracket = Some(report);
        assert_eq!(attempt_kind(&probe, false), AttemptKind::Other);
    }

    #[test]
    fn only_a_confirmed_front_with_a_visibility_check_measures_a_picture() {
        let mut probe = PictureBracketProbe {
            bracket: Some(BracketReport {
                chunks: 1,
                restore: RestoreStatus::Restored,
                stop: Some(BracketStop::BoundExceeded),
                restore_calibrated: true,
                ..bracket()
            }),
            ..Default::default()
        };
        assert_eq!(attempt_kind(&probe, true), AttemptKind::Calibration);

        let report = probe.bracket.as_mut().unwrap();
        report.restore_calibrated = false;
        assert_eq!(attempt_kind(&probe, true), AttemptKind::Other);

        probe.bracket.as_mut().unwrap().units_posted = 1;
        assert_eq!(
            attempt_kind(&probe, true),
            AttemptKind::PictureUnitNoMeasurement
        );

        // The visibility check may block capture, so no after-capture marker
        // is needed for a measured attempt.
        probe.before_capture = Some(ImageDecision::CoveredByWindow);
        assert_eq!(attempt_kind(&probe, false), AttemptKind::Other);
        assert_eq!(attempt_kind(&probe, true), AttemptKind::Picture);
    }

    #[test]
    fn covered_picture_continues_after_the_first_four_non_picture_calls() {
        let mut attempts = AttemptTally::default();
        for (index, kind) in [
            AttemptKind::IdleRefused,
            AttemptKind::IdleRefused,
            AttemptKind::IdleRefused,
            AttemptKind::Calibration,
            AttemptKind::PictureUnitNoMeasurement,
            AttemptKind::Picture,
            AttemptKind::Other,
            AttemptKind::Picture,
            AttemptKind::Picture,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(attempts.next_attempt(), Some(index + 1));
            attempts.record(kind);
        }
        assert_eq!(attempts.next_attempt(), None);
        assert_eq!(
            attempts.summary(),
            json!({"picture_summary": {
                "total": 9,
                "idle_refused": 3,
                "calibration": 1,
                "picture": 3,
                "picture_unit_no_measurement": 1,
                "other": 1,
                "reached_three_pictures": true,
            }})
        );
    }

    #[test]
    fn covered_picture_stops_at_twelve_calls_even_if_short_of_three_pictures() {
        let mut attempts = AttemptTally::default();
        for number in 1..=12 {
            assert_eq!(attempts.next_attempt(), Some(number));
            attempts.record(if number <= 2 {
                AttemptKind::Picture
            } else {
                AttemptKind::Other
            });
        }
        assert_eq!(attempts.next_attempt(), None);
        assert_eq!(
            attempts.summary()["picture_summary"]["reached_three_pictures"],
            false
        );
    }
}
