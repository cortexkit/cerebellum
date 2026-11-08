//! Desktop facts observed around a dispatched action, separate from its outcome.

use cerebellum_computer::app_state::source::{AppStateSource, ElementHandle};
use cerebellum_computer::platform::ProcessGrant;
use serde_json::{json, Value};

#[derive(Default)]
pub(crate) struct ActionEffects {
    frontmost: Option<u32>,
    windows: Option<Vec<u32>>,
    target_name: Option<String>,
    pub(super) lines: Vec<String>,
}

impl ActionEffects {
    pub(super) fn before(source: &dyn AppStateSource, grant: &ProcessGrant) -> Self {
        Self {
            frontmost: source.frontmost_pid(),
            windows: source.visible_window_numbers(grant),
            target_name: source.running_apps().ok().and_then(|apps| {
                apps.into_iter()
                    .find(|app| app.pid == grant.pid)
                    .map(|app| app.name)
            }),
            lines: Vec::new(),
        }
    }

    /// Records the desktop facts available now. The caller controls when to
    /// sample; this function never waits for a later change.
    pub(super) fn sample(&mut self, source: &dyn AppStateSource, grant: &ProcessGrant) {
        let frontmost = source.frontmost_pid();
        if let (Some(before), Some(after)) = (self.frontmost, frontmost) {
            if before != after {
                if let Ok(apps) = source.running_apps() {
                    if let Some(app) = apps.iter().find(|app| app.pid == after) {
                        self.push(format!(
                            "This action brought {} to the front.",
                            one_line(&app.name)
                        ));
                    }
                }
            }
        }
        // Keep the last known reading across gaps, rather than treating missing
        // telemetry as a change of application or an empty window set.
        if frontmost.is_some() {
            self.frontmost = frontmost;
        }
        if let Some(windows) = source.visible_window_numbers(grant) {
            let opened = self
                .windows
                .as_ref()
                .is_some_and(|known| windows.iter().any(|id| !known.contains(id)));
            // A previously visible window returning after a redraw is not a
            // new window. Keep every number observed during this action.
            let known = self.windows.get_or_insert_with(Vec::new);
            for id in windows {
                if !known.contains(&id) {
                    known.push(id);
                }
            }
            if opened {
                if let Some(name) = &self.target_name {
                    self.push(format!(
                        "This action opened a new window in {}.",
                        one_line(name)
                    ));
                }
            }
        }
    }

    fn push(&mut self, line: String) {
        if !self.lines.contains(&line) {
            self.lines.push(line);
        }
    }
}

fn one_line(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn append_lines(reply: &mut Value, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let mut text = reply["state_text"].as_str().unwrap_or_default().to_owned();
    for line in lines {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(line);
        text.push('\n');
    }
    reply["state_text"] = json!(text);
}

pub(super) fn has_screen_position(source: &dyn AppStateSource, handle: &ElementHandle) -> bool {
    let Some(frame) = source.element_frame(handle).filter(valid_frame) else {
        return false;
    };
    source.display_frames().is_some_and(|displays| {
        displays.into_iter().filter(valid_frame).any(|display| {
            frame[0] < display[0] + display[2]
                && display[0] < frame[0] + frame[2]
                && frame[1] < display[1] + display[3]
                && display[1] < frame[1] + frame[3]
        })
    })
}

fn valid_frame(frame: &[f64; 4]) -> bool {
    frame.iter().all(|value| value.is_finite())
        && frame[2] > 0.0
        && frame[3] > 0.0
        && (frame[0] + frame[2]).is_finite()
        && (frame[1] + frame[3]).is_finite()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, RawAppState, ReadBounds, RunningApp,
    };
    use std::sync::Mutex;

    struct Desktop(Mutex<(Option<u32>, Option<Vec<u32>>)>);

    impl AppStateSource for Desktop {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            Err(AppStateReadError::UnsupportedOnPlatform)
        }
        fn frontmost_pid(&self) -> Option<u32> {
            self.0.lock().unwrap().0
        }
        fn visible_window_numbers(&self, _: &ProcessGrant) -> Option<Vec<u32>> {
            self.0.lock().unwrap().1.clone()
        }
        fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
            Ok([(1, "Finder"), (2, "Mail")]
                .into_iter()
                .map(|(pid, name)| RunningApp {
                    name: name.into(),
                    bundle_identity: format!("app.{pid}"),
                    pid,
                    frontmost: false,
                })
                .collect())
        }
    }

    fn grant() -> ProcessGrant {
        ProcessGrant {
            bundle_identity: "app.1".into(),
            pid: 1,
            process_generation_evidence: "1".into(),
        }
    }

    #[test]
    fn observed_transient_front_changes_survive_the_return_to_the_original_app() {
        let source = Desktop(Mutex::new((Some(1), Some(vec![10]))));
        let mut effects = ActionEffects::before(&source, &grant());
        *source.0.lock().unwrap() = (Some(2), Some(vec![10, 20]));
        effects.sample(&source, &grant());
        *source.0.lock().unwrap() = (Some(1), Some(vec![20, 10]));
        effects.sample(&source, &grant());
        effects.sample(&source, &grant());
        assert_eq!(
            effects.lines,
            [
                "This action brought Mail to the front.",
                "This action opened a new window in Finder.",
                "This action brought Finder to the front."
            ]
        );
    }

    #[test]
    fn unavailable_telemetry_and_unchanged_desktops_add_no_lines() {
        for (front, windows) in [(None, None), (Some(1), Some(vec![10]))] {
            let source = Desktop(Mutex::new((front, windows)));
            let mut effects = ActionEffects::before(&source, &grant());
            effects.sample(&source, &grant());
            assert!(effects.lines.is_empty());
            let mut reply = json!({"outcome":"completed", "state_text":"No change seen.\n"});
            let before = reply.clone();
            append_lines(&mut reply, &effects.lines);
            assert_eq!(reply, before);
        }
    }

    #[test]
    fn a_preexisting_window_temporarily_leaving_the_visible_set_is_not_new() {
        let source = Desktop(Mutex::new((Some(1), Some(vec![10]))));
        let mut effects = ActionEffects::before(&source, &grant());
        *source.0.lock().unwrap() = (Some(1), Some(vec![]));
        effects.sample(&source, &grant());
        *source.0.lock().unwrap() = (Some(1), Some(vec![10]));
        effects.sample(&source, &grant());
        assert!(effects.lines.is_empty());
    }
}
