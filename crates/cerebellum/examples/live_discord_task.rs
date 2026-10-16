//! Carry out one real task in Discord through the computer plane: open a
//! direct message, attach a file and draft a message, without ever sending
//! it. Every step prints what it sent and what came back, so the operator at
//! the desk sees exactly what an agent would have done.
//!
//! The plane is driven in-process through the same `serve` entry point the
//! module answers requests with, under `ResultSchemaEnforcement::Withhold` and
//! an isolated (in-memory) journal. The probe is its own consent carrier: it
//! prints each question it is asked -- its `grant_kind`, `app` and `message`,
//! which is what a person would be shown -- and answers "allow for this
//! conversation".
//!
//! THIS WRITES INTO THE OPERATOR'S REAL DISCORD. It never presses Send and
//! never posts Return while the composer has focus: every action passes a
//! guard that refuses both before anything is sent to the plane. The draft is
//! left in the composer for the person to send or delete.
//!
//! Steps:
//!
//! 1. Read Discord's state with its window image and report the tree size,
//!    the image, or why there is no image.
//! 2. Press the Direct Messages row, then the link to the named user's direct
//!    message. Either match must be unique, or the probe stops.
//! 3. Find the composer: the settable text area labelled `Message @<user>`.
//! 4. Attach the file: press the composer's upload control, then its
//!    "Upload a File" menu item, and report whether an open panel appeared in
//!    Discord's accessibility tree. Only if it did: `command+shift+g` (which
//!    brings Discord forward briefly, so it raises the takeover question),
//!    write the path into the panel's path field, `return`, and press Open.
//!    If the panel is not in the tree, the attach is skipped: the pointer is
//!    never used to reach it.
//! 5. Write the message into the composer, replacing its value.
//! 6. Read the state again with an image, saved to
//!    `/tmp/live_discord_task-final.jpg`, and report the composer's value and
//!    whether an attachment is staged (a `Remove Attachment` control).
//!
//! With `--dry-read` it performs only the reads: it reports what it would
//! press and write, and acts nowhere.
//!
//! Instruments: a sampler reads the frontmost application every 100 ms from
//! start to finish, and the report names every application that was in front
//! and for how long, and which steps ran while Discord was. Only the attach
//! step's keystrokes should bring Discord forward. A bracket shorter than the
//! sampling interval can fall between two samples, so Discord missing from
//! the attach step's samples is not proof that it never came forward; Discord
//! in front during any other step is a finding. The probe never reads or
//! writes the clipboard: text reaches Discord through accessibility values and
//! posted keystrokes only.
//!
//! The review keys: reading application state, acting on addressed elements
//! and bringing an application forward each ship behind a release review that
//! has not been recorded yet. This probe binds all three for its own build
//! only, and only when it is built with `CEREBELLUM_PROBE_PENDING_REVIEW=1`;
//! any other build binds nothing and refuses to run. The key is read at
//! compile time, like the release attestations, so it cannot be supplied to an
//! already-built binary. The release build script is not involved.
//!
//! Run with:
//!
//! ```text
//! CEREBELLUM_PROBE_PENDING_REVIEW=1 cargo run -p cerebellum \
//!     --example live_discord_task -- --user <name> --file <path> --text <message>
//! CEREBELLUM_PROBE_PENDING_REVIEW=1 cargo run -p cerebellum \
//!     --example live_discord_task -- --user <name> --dry-read
//! ```
//!
//! Exit status: 0 when every step that ran completed, 1 when one did not or a
//! guard refused, 2 with `UNMEASURABLE` when the screen is locked, Discord is
//! not running, or this process may not use accessibility, because nothing a
//! step reported under those conditions would mean anything.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives Discord through macOS accessibility and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macos_probe::run());
}

// The probe's Cingulate, which answers each card with the narrowest grant it
// offers. Declared at the file's top level: a `#[path]` on a mod nested in an
// inline module resolves against `examples/<inline-mod-name>/`, which does not
// exist.
#[cfg(target_os = "macos")]
#[path = "support/allowing_cingulate.rs"]
mod allowing_cingulate;

/// The parts of the probe that decide what to act on and whether an action
/// is allowed. They take text and numbers rather than a live application, so
/// they are unit-tested on every platform; the probe itself only runs on a
/// desk with Discord open.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod task {
    use serde_json::{json, Value};

    /// Discord's bundle identity.
    pub const DISCORD: &str = "com.hnc.Discord";

    /// What the operator asked for on the command line.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Options {
        pub user: String,
        pub file: Option<String>,
        pub text: Option<String>,
        pub dry_read: bool,
    }

    pub fn parse_options(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
        let mut user = None;
        let mut file = None;
        let mut text = None;
        let mut dry_read = false;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--user" => user = Some(args.next().ok_or("--user needs a name")?),
                "--file" => file = Some(args.next().ok_or("--file needs a path")?),
                "--text" => text = Some(args.next().ok_or("--text needs a message")?),
                "--dry-read" => dry_read = true,
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        let user = user
            .filter(|user| !user.trim().is_empty())
            .ok_or("--user <name> is required")?;
        if !dry_read {
            if file.is_none() {
                return Err("--file <path> is required unless --dry-read is given".into());
            }
            if text.is_none() {
                return Err("--text <message> is required unless --dry-read is given".into());
            }
        }
        Ok(Options {
            user,
            file,
            text,
            dry_read,
        })
    }

    /// One line of a `read_state` tree: indent, element id, role in words,
    /// the quoted merged label, then the true markers in brackets. The
    /// indent is dropped: the finders match on what an element is, not
    /// where it sits.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TreeLine {
        pub id: String,
        pub role: String,
        /// The merged label with the tree's escapes undone.
        pub label: String,
        pub markers: Vec<String>,
    }

    impl TreeLine {
        /// The first part of the merged label. The label joins the element's
        /// title, description and value with ` | `, so the head is the
        /// element's own name and the rest is usually its current value.
        pub fn head(&self) -> &str {
            self.label.split(" | ").next().unwrap_or("").trim()
        }

        pub fn has_marker(&self, marker: &str) -> bool {
            self.markers.iter().any(|present| present == marker)
        }

        pub fn describe(&self) -> String {
            let mut text = format!("{} {} {:?}", self.id, self.role, self.label);
            if !self.markers.is_empty() {
                text.push_str(&format!(" [{}]", self.markers.join(" ")));
            }
            text
        }
    }

    pub fn parse_tree(tree: &str) -> Vec<TreeLine> {
        tree.lines().filter_map(parse_line).collect()
    }

    pub fn parse_line(line: &str) -> Option<TreeLine> {
        let (id, rest) = line.trim_start_matches(' ').split_once(' ')?;
        let quote = rest.find('"')?;
        let role = rest[..quote].trim().to_string();
        let (label, after) = unquote(&rest[quote + 1..])?;
        let after = after.trim_start();
        let markers = match after.strip_prefix('[') {
            Some(inside) => inside
                .split_once(']')
                .map(|(markers, _)| markers.split_whitespace().map(String::from).collect())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        if id.is_empty() || role.is_empty() {
            return None;
        }
        Some(TreeLine {
            id: id.to_string(),
            role,
            label,
            markers,
        })
    }

    /// Read a quoted label up to its closing quote, undoing the tree's
    /// escapes; returns the label and what follows the closing quote.
    fn unquote(text: &str) -> Option<(String, &str)> {
        let mut label = String::new();
        let mut characters = text.char_indices();
        while let Some((index, character)) = characters.next() {
            match character {
                '"' => return Some((label, &text[index + 1..])),
                '\\' => match characters.next()?.1 {
                    'n' => label.push('\n'),
                    'r' => label.push('\r'),
                    't' => label.push('\t'),
                    'u' => {
                        // `\u{hex}`, written for control characters.
                        if characters.next()?.1 != '{' {
                            return None;
                        }
                        let mut hex = String::new();
                        for (_, digit) in characters.by_ref() {
                            if digit == '}' {
                                break;
                            }
                            hex.push(digit);
                        }
                        label.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    other => label.push(other),
                },
                other => label.push(other),
            }
        }
        None
    }

    /// Why a finder did not produce exactly one element.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FindFailure {
        Missing,
        /// More than one element matched; acting on any one of them would
        /// be a guess, so the probe acts on none.
        Ambiguous(Vec<String>),
    }

    impl std::fmt::Display for FindFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FindFailure::Missing => write!(formatter, "no element matched"),
                FindFailure::Ambiguous(lines) => {
                    write!(
                        formatter,
                        "{} elements matched: {}",
                        lines.len(),
                        lines.join("; ")
                    )
                }
            }
        }
    }

    pub fn unique(
        lines: &[TreeLine],
        wanted: impl Fn(&TreeLine) -> bool,
    ) -> Result<TreeLine, FindFailure> {
        let matches: Vec<&TreeLine> = lines.iter().filter(|line| wanted(line)).collect();
        match matches.as_slice() {
            [] => Err(FindFailure::Missing),
            [only] => Ok((*only).clone()),
            many => Err(FindFailure::Ambiguous(
                many.iter().map(|line| line.describe()).collect(),
            )),
        }
    }

    /// Roles that only show text or hold other elements. A heading reading
    /// "Direct Messages" is not the row that opens them.
    const NON_ACTING_ROLES: [&str; 7] = [
        "static text",
        "text",
        "heading",
        "group",
        "list",
        "scroll area",
        "web area",
    ];

    /// The row in Discord's server list that opens the direct messages.
    pub fn find_direct_messages(lines: &[TreeLine]) -> Result<TreeLine, FindFailure> {
        unique(lines, |line| {
            line.head().eq_ignore_ascii_case("Direct Messages")
                && !NON_ACTING_ROLES.contains(&line.role.as_str())
        })
    }

    /// The link that opens the direct message with `user`. Discord labels it
    /// `<user> (direct message)`, followed by status text that varies.
    pub fn find_dm_link(lines: &[TreeLine], user: &str) -> Result<TreeLine, FindFailure> {
        let prefix = format!("{user} (direct message)");
        unique(lines, |line| {
            line.role == "link" && line.label.starts_with(&prefix)
        })
    }

    /// The composer label Discord gives the direct message with `user`.
    pub fn composer_label(user: &str) -> String {
        format!("Message @{user}")
    }

    /// The composer: a settable text area named `Message @<user>`. The head
    /// is compared, not the whole label, because a draft already in the
    /// composer is merged into the label after it.
    pub fn find_composer(lines: &[TreeLine], user: &str) -> Result<TreeLine, FindFailure> {
        let label = composer_label(user);
        unique(lines, |line| {
            line.role == "text area" && line.head() == label && line.has_marker("settable")
        })
    }

    /// Labels Discord has given the button beside the composer that opens
    /// its upload menu. Discord exposes "More message options" as a pop-up
    /// button (AXPopUpButton), not a plain button.
    const UPLOAD_CONTROL_LABELS: [&str; 3] = ["More message options", "Upload a File", "Upload"];
    pub const UPLOAD_CONTROL_ROLES: [&str; 2] = ["button", "pop up button"];

    pub fn find_upload_control(lines: &[TreeLine]) -> Result<TreeLine, FindFailure> {
        unique(lines, |line| {
            UPLOAD_CONTROL_ROLES.contains(&line.role.as_str())
                && UPLOAD_CONTROL_LABELS
                    .iter()
                    .any(|label| line.head().eq_ignore_ascii_case(label))
        })
    }

    pub fn find_upload_menu_item(lines: &[TreeLine]) -> Result<TreeLine, FindFailure> {
        unique(lines, |line| {
            line.role == "menu item" && line.head().starts_with("Upload a File")
        })
    }

    /// Roles an open panel can appear under in the tree.
    const PANEL_ROLES: [&str; 3] = ["sheet", "dialog", "window"];

    /// The windows, sheets and dialogs present after an action that were
    /// not there before it: where an open panel would show up.
    pub fn new_panels(before: &[TreeLine], after: &[TreeLine]) -> Vec<TreeLine> {
        after
            .iter()
            .filter(|line| PANEL_ROLES.contains(&line.role.as_str()))
            .filter(|line| !before.iter().any(|earlier| earlier.id == line.id))
            .cloned()
            .collect()
    }

    /// The field an open panel's "go to folder" sheet takes a path in. The
    /// panel also has a search field, which is settable too, so search fields
    /// are excluded and a focused field wins when there is more than one.
    pub fn find_path_field(lines: &[TreeLine], composer_id: &str) -> Result<TreeLine, FindFailure> {
        let candidate = |line: &TreeLine| {
            matches!(line.role.as_str(), "text field" | "combo box")
                && line.has_marker("settable")
                && line.id != composer_id
        };
        match unique(lines, |line| candidate(line) && line.has_marker("focused")) {
            Err(FindFailure::Missing) => unique(lines, candidate),
            found => found,
        }
    }

    pub fn find_open_button(lines: &[TreeLine]) -> Result<TreeLine, FindFailure> {
        unique(lines, |line| line.role == "button" && line.head() == "Open")
    }

    /// Whether a staged attachment is showing: Discord gives each one a
    /// `Remove Attachment` control.
    pub fn has_remove_attachment(lines: &[TreeLine]) -> bool {
        lines
            .iter()
            .any(|line| line.label.to_lowercase().contains("remove attachment"))
    }

    /// An action the probe is about to take, with what it knows about the
    /// target. The only way to turn one into a request is
    /// [`checked_request`], so every action passes the guard.
    #[derive(Debug, Clone, Copy)]
    pub enum Planned<'a> {
        Press(&'a TreeLine),
        WriteText {
            element: &'a TreeLine,
            text: &'a str,
        },
        Keys {
            keys: &'a [&'a str],
            /// The focused element in Discord as last read, if known.
            focused: Option<&'a str>,
            /// The composer's element id, if it has been found.
            composer: Option<&'a str>,
        },
    }

    /// Whether a label names a Send control. Every part of the merged label
    /// is checked, and "Send ..." counts as well as "Send": refusing a
    /// harmless button costs a rerun, pressing the wrong one sends a message.
    pub fn is_send_label(label: &str) -> bool {
        label.split(" | ").any(|part| {
            let part = part.trim().to_lowercase();
            part == "send" || part.starts_with("send ")
        })
    }

    /// Keys that submit whatever has focus.
    const SUBMIT_KEYS: [&str; 3] = ["return", "keypad_enter", "enter"];

    /// Refuse the two actions that could send the draft: pressing a Send
    /// control, and Return or Enter while the composer has focus. Focus that
    /// is unknown, or a composer that has not been found, counts as the
    /// composer having focus, because neither can be ruled out.
    pub fn guard(planned: &Planned<'_>) -> Result<(), String> {
        match planned {
            Planned::Press(element) | Planned::WriteText { element, .. } => {
                if is_send_label(&element.label) {
                    return Err(format!(
                        "refused to act on {}: its label names Send",
                        element.describe()
                    ));
                }
                Ok(())
            }
            Planned::Keys {
                keys,
                focused,
                composer,
            } => {
                let submits = keys
                    .iter()
                    .any(|key| SUBMIT_KEYS.contains(&key.to_lowercase().as_str()));
                if !submits {
                    return Ok(());
                }
                match (focused, composer) {
                    (Some(focused), Some(composer)) if focused != composer => Ok(()),
                    (Some(_), Some(_)) => Err(format!(
                        "refused {keys:?}: the composer has focus, so it would send the draft"
                    )),
                    (None, _) => Err(format!(
                        "refused {keys:?}: Discord's focused element is unknown, so it may be \
                         the composer"
                    )),
                    (_, None) => Err(format!(
                        "refused {keys:?}: the composer has not been found, so it cannot be \
                         ruled out as the focused element"
                    )),
                }
            }
        }
    }

    /// The capability and arguments for a planned action, or the guard's
    /// refusal. Keys always go to Discord.
    /// The write mode the probe asks for: `replace_value` unless
    /// `CEREBELLUM_PROBE_WRITE_MODE` names another, so the modes can be
    /// compared on the same composer without a rebuild.
    fn write_mode() -> String {
        std::env::var("CEREBELLUM_PROBE_WRITE_MODE").unwrap_or_else(|_| "replace_value".to_string())
    }

    pub fn checked_request(planned: &Planned<'_>) -> Result<(&'static str, Value), String> {
        guard(planned)?;
        Ok(match planned {
            Planned::Press(element) => {
                ("computer.press_element", json!({"element_id": element.id}))
            }
            Planned::WriteText { element, text } => (
                "computer.write_text",
                json!({"element_id": element.id, "text": text, "write_mode": write_mode()}),
            ),
            Planned::Keys { keys, .. } => {
                ("computer.keys", json!({"target": DISCORD, "keys": keys}))
            }
        })
    }

    /// One line summarising a reply: the outcome and the facts a reader
    /// needs to judge it, leaving out the tree and image themselves.
    pub fn reply_summary(reply: &Value) -> String {
        let mut parts = vec![format!(
            "outcome {}",
            reply["outcome"].as_str().unwrap_or("(none)")
        )];
        for field in ["changed", "added", "removed"] {
            if let Some(items) = reply[field].as_array() {
                parts.push(format!("{field} {}", items.len()));
            }
        }
        for field in [
            "effect_status",
            "focused_element_id",
            "containment_rung",
            "containment_forfeited_because",
            "reason",
            "field",
            "remedy",
            "bundle_identity",
            "error",
        ] {
            if let Some(text) = reply[field].as_str() {
                parts.push(format!("{field} {text}"));
            }
        }
        if let Some(fronted) = reply["target_fronted"].as_bool() {
            parts.push(format!("target_fronted {fronted}"));
        }
        if let Some(reason) = reply["image_unavailable"]["reason"].as_str() {
            parts.push(format!("image_unavailable {reason}"));
        }
        if let Some(truncation) = reply["truncation"].as_object() {
            parts.push(format!("truncation {}", Value::Object(truncation.clone())));
        }
        parts.join(", ")
    }

    /// Whether the probe may bind the review keys: only when this build was
    /// compiled with the pending-review switch set to exactly `1`.
    pub fn pending_review_admitted(switch: Option<&str>) -> bool {
        switch == Some("1")
    }

    /// Why the desk cannot be measured, if it cannot.
    pub fn readiness(
        screen_locked: Option<bool>,
        accessibility_live: bool,
        discord_running: bool,
    ) -> Result<(), String> {
        match screen_locked {
            Some(false) => {}
            Some(true) => {
                return Err("the screen is locked, so windows are hidden from accessibility".into())
            }
            None => {
                return Err("there is no graphical session, so there is no screen to act on".into())
            }
        }
        if !accessibility_live {
            return Err("this process may not use accessibility".into());
        }
        if !discord_running {
            return Err(format!("{DISCORD} is not running as exactly one process"));
        }
        Ok(())
    }

    /// One frontmost reading: milliseconds since the probe started, and the
    /// frontmost pid.
    pub type Sample = (u128, Option<i32>);

    /// When one step ran, in milliseconds since the probe started.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Span {
        pub step: String,
        pub start_ms: u128,
        pub end_ms: u128,
    }

    /// How long each pid was frontmost, in the order they were first seen.
    /// Each sample stands until the next one; the last stands until `end_ms`.
    pub fn frontmost_durations(samples: &[Sample], end_ms: u128) -> Vec<(Option<i32>, u128)> {
        let mut durations: Vec<(Option<i32>, u128)> = Vec::new();
        for (index, (at, pid)) in samples.iter().enumerate() {
            let until = samples.get(index + 1).map_or(end_ms, |next| next.0);
            let held = until.saturating_sub(*at);
            match durations.iter_mut().find(|(seen, _)| seen == pid) {
                Some((_, total)) => *total += held,
                None => durations.push((*pid, held)),
            }
        }
        durations
    }

    /// Which steps had `pid` frontmost in at least one sample, and how many
    /// samples showed it frontmost outside every step.
    pub fn steps_with_frontmost(
        samples: &[Sample],
        spans: &[Span],
        pid: i32,
    ) -> (Vec<String>, usize) {
        let mut steps: Vec<String> = Vec::new();
        let mut outside = 0;
        for (at, _) in samples.iter().filter(|(_, sampled)| *sampled == Some(pid)) {
            match spans
                .iter()
                .find(|span| span.start_ms <= *at && *at <= span.end_ms)
            {
                Some(span) if !steps.contains(&span.step) => steps.push(span.step.clone()),
                Some(_) => {}
                None => outside += 1,
            }
        }
        (steps, outside)
    }

    /// An application's name from its executable path: the innermost
    /// `.app` bundle, or the executable's file name outside one.
    pub fn app_name_from_path(path: &str) -> String {
        path.split('/')
            .rfind(|part| part.ends_with(".app"))
            .map(|bundle| bundle.trim_end_matches(".app"))
            .or_else(|| path.rsplit('/').next())
            .unwrap_or(path)
            .to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn line(id: &str, role: &str, label: &str, markers: &[&str]) -> TreeLine {
            TreeLine {
                id: id.into(),
                role: role.into(),
                label: label.into(),
                markers: markers.iter().map(|marker| marker.to_string()).collect(),
            }
        }

        #[test]
        fn a_tree_line_parses_into_id_role_label_and_markers() {
            let parsed = parse_line(
                "    sab-12 text area \"Message @IceTea | draft \\\"quoted\\\"\\n\" [settable focused]",
            )
            .expect("the line parses");
            assert_eq!(parsed.id, "sab-12");
            assert_eq!(parsed.role, "text area");
            assert_eq!(parsed.label, "Message @IceTea | draft \"quoted\"\n");
            assert_eq!(parsed.head(), "Message @IceTea");
            assert_eq!(parsed.markers, vec!["settable", "focused"]);
        }

        #[test]
        fn a_label_escape_for_a_control_character_is_undone() {
            let parsed = parse_line("s-1 button \"a\\u{7}b\" value=3").expect("the line parses");
            assert_eq!(parsed.label, "a\u{7}b");
            assert!(parsed.markers.is_empty());
        }

        #[test]
        fn a_label_containing_a_bracket_is_not_read_as_markers() {
            let parsed = parse_line("s-1 button \"[settable]\"").expect("the line parses");
            assert_eq!(parsed.label, "[settable]");
            assert!(!parsed.has_marker("settable"));
        }

        #[test]
        fn the_direct_messages_row_must_be_unique_and_not_a_heading() {
            let lines = vec![
                line("s-1", "heading", "Direct Messages", &[]),
                line("s-2", "tree item", "Direct Messages", &[]),
            ];
            assert_eq!(find_direct_messages(&lines).unwrap().id, "s-2");

            let twice = vec![
                line("s-2", "tree item", "Direct Messages", &[]),
                line("s-3", "link", "direct messages", &[]),
            ];
            assert!(matches!(
                find_direct_messages(&twice),
                Err(FindFailure::Ambiguous(found)) if found.len() == 2
            ));
            assert_eq!(find_direct_messages(&[]), Err(FindFailure::Missing));
        }

        #[test]
        fn the_dm_link_matches_on_its_label_prefix_and_role() {
            let lines = vec![
                line("s-4", "link", "IceTea (direct message) | Online", &[]),
                line("s-5", "static text", "IceTea (direct message)", &[]),
                line("s-6", "link", "IceTeaFan (direct message)", &[]),
                line("s-7", "link", "Friend of IceTea (direct message)", &[]),
            ];
            assert_eq!(find_dm_link(&lines, "IceTea").unwrap().id, "s-4");

            let two = vec![
                line("s-4", "link", "IceTea (direct message)", &[]),
                line("s-8", "link", "IceTea (direct message) | Idle", &[]),
            ];
            assert!(matches!(
                find_dm_link(&two, "IceTea"),
                Err(FindFailure::Ambiguous(_))
            ));
        }

        #[test]
        fn the_composer_needs_its_label_and_the_settable_marker() {
            let lines = vec![
                line("s-9", "text area", "Message @IceTea", &[]),
                line("s-10", "text area", "Message #general", &["settable"]),
            ];
            assert_eq!(find_composer(&lines, "IceTea"), Err(FindFailure::Missing));

            let with_draft = vec![
                line(
                    "s-9",
                    "text area",
                    "Message @IceTea | old draft",
                    &["settable"],
                ),
                line("s-10", "text area", "Message @IceTeaFan", &["settable"]),
            ];
            assert_eq!(find_composer(&with_draft, "IceTea").unwrap().id, "s-9");
        }

        #[test]
        fn the_upload_path_finds_the_control_the_menu_item_and_the_open_button() {
            let lines = vec![
                line("s-11", "button", "More message options", &[]),
                line(
                    "s-12",
                    "menu item",
                    "Upload a File | Tip: double click",
                    &[],
                ),
                line("s-13", "button", "Open", &[]),
                line("s-14", "button", "Open in browser", &[]),
            ];
            assert_eq!(find_upload_control(&lines).unwrap().id, "s-11");
            assert_eq!(find_upload_menu_item(&lines).unwrap().id, "s-12");
            assert_eq!(find_open_button(&lines).unwrap().id, "s-13");
        }

        #[test]
        fn the_path_field_prefers_the_focused_field_and_never_the_composer_or_search() {
            let lines = vec![
                line(
                    "s-9",
                    "text area",
                    "Message @IceTea",
                    &["settable", "focused"],
                ),
                line("s-20", "search field", "Search", &["settable"]),
                line("s-21", "text field", "", &["settable"]),
                line(
                    "s-22",
                    "combo box",
                    "Go to the folder:",
                    &["settable", "focused"],
                ),
            ];
            assert_eq!(find_path_field(&lines, "s-9").unwrap().id, "s-22");

            let unfocused = vec![
                line("s-20", "search field", "Search", &["settable"]),
                line("s-21", "text field", "", &["settable"]),
            ];
            assert_eq!(find_path_field(&unfocused, "s-9").unwrap().id, "s-21");

            let composer_only = vec![line("s-9", "text field", "Message @IceTea", &["settable"])];
            assert_eq!(
                find_path_field(&composer_only, "s-9"),
                Err(FindFailure::Missing)
            );
        }

        #[test]
        fn only_windows_sheets_and_dialogs_that_are_new_count_as_panels() {
            let before = vec![line("s-1", "window", "Discord", &[])];
            let after = vec![
                line("s-1", "window", "Discord", &[]),
                line("s-30", "sheet", "", &[]),
                line("s-31", "button", "Open", &[]),
            ];
            let panels = new_panels(&before, &after);
            assert_eq!(panels.len(), 1);
            assert_eq!(panels[0].id, "s-30");
            assert!(new_panels(&after, &after).is_empty());
        }

        #[test]
        fn a_staged_attachment_is_recognised_by_its_remove_control() {
            assert!(has_remove_attachment(&[line(
                "s-40",
                "button",
                "Remove Attachment",
                &[]
            )]));
            assert!(!has_remove_attachment(&[line(
                "s-40",
                "button",
                "Upload a File",
                &[]
            )]));
        }

        #[test]
        fn the_guard_refuses_any_action_on_a_send_control() {
            for label in ["Send", "send", "Send Message", "Emoji | Send", " Send "] {
                let send = line("s-50", "button", label, &[]);
                assert!(guard(&Planned::Press(&send)).is_err(), "{label:?}");
                assert!(
                    guard(&Planned::WriteText {
                        element: &send,
                        text: "x"
                    })
                    .is_err(),
                    "{label:?}"
                );
            }
            for label in ["Sender settings", "Upload a File", "Open"] {
                let other = line("s-51", "button", label, &[]);
                assert!(guard(&Planned::Press(&other)).is_ok(), "{label:?}");
            }
        }

        #[test]
        fn the_guard_refuses_return_unless_focus_is_known_to_be_off_the_composer() {
            let keys: &[&str] = &["return"];
            let refused = |focused, composer| {
                guard(&Planned::Keys {
                    keys,
                    focused,
                    composer,
                })
                .is_err()
            };
            assert!(refused(Some("s-9"), Some("s-9")), "composer focused");
            assert!(refused(None, Some("s-9")), "focus unknown");
            assert!(refused(Some("s-22"), None), "composer unknown");
            assert!(!refused(Some("s-22"), Some("s-9")), "path field focused");

            for submit in [
                &["keypad_enter"][..],
                &["Return"][..],
                &["command", "return"][..],
            ] {
                assert!(guard(&Planned::Keys {
                    keys: submit,
                    focused: Some("s-9"),
                    composer: Some("s-9"),
                })
                .is_err());
            }
            // A chord that submits nothing passes even with the composer
            // focused.
            assert!(guard(&Planned::Keys {
                keys: &["command", "shift", "g"],
                focused: Some("s-9"),
                composer: Some("s-9"),
            })
            .is_ok());
        }

        #[test]
        fn a_refused_action_produces_no_request() {
            let send = line("s-50", "button", "Send", &[]);
            assert!(checked_request(&Planned::Press(&send)).is_err());

            let composer = line("s-9", "text area", "Message @IceTea", &["settable"]);
            let (name, arguments) = checked_request(&Planned::WriteText {
                element: &composer,
                text: "hello",
            })
            .expect("writing into the composer is allowed");
            assert_eq!(name, "computer.write_text");
            assert_eq!(
                arguments,
                json!({"element_id": "s-9", "text": "hello", "write_mode": "replace_value"})
            );

            let (name, arguments) = checked_request(&Planned::Keys {
                keys: &["command", "shift", "g"],
                focused: None,
                composer: None,
            })
            .expect("a chord that submits nothing is allowed");
            assert_eq!(name, "computer.keys");
            assert_eq!(
                arguments,
                json!({"target": DISCORD, "keys": ["command", "shift", "g"]})
            );
        }

        #[test]
        fn the_sampler_summary_attributes_time_and_steps() {
            let discord = 42;
            let samples: Vec<Sample> = vec![
                (0, Some(7)),
                (100, Some(7)),
                (200, Some(discord)),
                (300, Some(7)),
                (400, None),
                (500, Some(discord)),
            ];
            assert_eq!(
                frontmost_durations(&samples, 650),
                vec![(Some(7), 300), (Some(discord), 250), (None, 100)]
            );

            let spans = vec![
                Span {
                    step: "2 open DM".into(),
                    start_ms: 0,
                    end_ms: 150,
                },
                Span {
                    step: "4 attach".into(),
                    start_ms: 150,
                    end_ms: 450,
                },
            ];
            assert_eq!(
                steps_with_frontmost(&samples, &spans, discord),
                (vec!["4 attach".to_string()], 1)
            );
            assert!(frontmost_durations(&[], 10).is_empty());
        }

        #[test]
        fn readiness_is_refused_for_a_locked_or_absent_screen_no_accessibility_or_no_discord() {
            assert!(readiness(Some(false), true, true).is_ok());
            assert!(readiness(Some(true), true, true).is_err());
            assert!(readiness(None, true, true).is_err());
            assert!(readiness(Some(false), false, true).is_err());
            assert!(readiness(Some(false), true, false).is_err());
        }

        #[test]
        fn only_the_switch_set_to_one_admits_the_pending_review_keys() {
            assert!(pending_review_admitted(Some("1")));
            for other in [None, Some(""), Some("0"), Some("true"), Some("1 ")] {
                assert!(!pending_review_admitted(other), "{other:?}");
            }
        }

        #[test]
        fn options_need_a_user_and_for_acting_a_file_and_text() {
            let parse = |args: &[&str]| parse_options(args.iter().map(|arg| arg.to_string()));
            assert!(parse(&[]).is_err());
            assert!(parse(&["--user", "IceTea"]).is_err());
            assert_eq!(
                parse(&["--user", "IceTea", "--dry-read"]).unwrap(),
                Options {
                    user: "IceTea".into(),
                    file: None,
                    text: None,
                    dry_read: true
                }
            );
            let acting =
                parse(&["--user", "IceTea", "--file", "/tmp/a.png", "--text", "hi"]).unwrap();
            assert!(!acting.dry_read);
            assert_eq!(acting.file.as_deref(), Some("/tmp/a.png"));
            assert!(parse(&["--user", "IceTea", "--send"]).is_err());
        }

        #[test]
        fn a_reply_summary_names_outcome_diff_sizes_focus_and_refusal() {
            let summary = reply_summary(&json!({
                "outcome": "completed",
                "changed": [{"element_id": "a"}],
                "added": [],
                "removed": [{"element_id": "b"}, {"element_id": "c"}],
                "focused_element_id": "s-9",
            }));
            assert_eq!(
                summary,
                "outcome completed, changed 1, added 0, removed 2, focused_element_id s-9"
            );
            let refusal = reply_summary(&json!({
                "outcome": "keystrokes_need_foreground",
                "remedy": "grant takeover",
            }));
            assert_eq!(
                refusal,
                "outcome keystrokes_need_foreground, remedy grant takeover"
            );
        }

        #[test]
        fn an_application_is_named_by_its_bundle() {
            assert_eq!(
                app_name_from_path("/Applications/Discord.app/Contents/MacOS/Discord"),
                "Discord"
            );
            assert_eq!(app_name_from_path("/usr/bin/login"), "login");
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use cerebellum::cingulate_client::desk::ConsentDesk;
    use cerebellum::cingulate_client::live_call::{LiveCall, NotLive};
    use cerebellum::computer_capability::{
        computer_audit, servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
    };
    use cerebellum::computer_grants::{
        AlwaysOpenRoute, ConsentContext, GrantCaller, QuestionCarrier,
    };
    use cerebellum::management::{ManagementPlane, PlatformResolver};
    use cerebellum::{JournalPersistence, PlaneJournalStorage};
    use cerebellum_computer::audit::redaction::ExcludeApplicationText;
    use cerebellum_computer::platform::native::NativeCaptureBackend;
    use cerebellum_computer::platform::{MacOs26PlatformDriver, TargetResolution};
    use cerebellum_core::clock::SystemClock;
    use cerebellum_core::dispatch::{DispatchTimingState, InFlightGuard};
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::{JournalIdentity, ValidatedSeverityTaxonomy};
    use serde_json::{json, Value};
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    use subc_protocol::Principal;

    use super::task::{self, FindFailure, Planned, Sample, Span, TreeLine, DISCORD};

    /// The pending-review switch, read when this example was compiled.
    const PENDING_REVIEW_SWITCH: Option<&str> = option_env!("CEREBELLUM_PROBE_PENDING_REVIEW");

    /// The value every key this probe binds carries. It names the state of
    /// the keys honestly: nothing has reviewed them.
    const PENDING_REVIEW_REVISION: &str = "live-discord-probe-pending-review";

    /// The review keys this probe binds for its own build. Only the takeover
    /// key is consulted in-process -- the platform driver will not bring an
    /// application forward without it. The other two decide whether the
    /// module advertises its rows over the wire, which this probe does not
    /// use; they are listed so the report states every key the probe relies
    /// on.
    const PROBE_REVIEW_KEYS: [&str; 3] = [
        "app_state_review_revision",
        "element_addressed_review_revision",
        "takeover_dispatch_review_revision",
    ];

    const FINAL_IMAGE_PATH: &str = "/tmp/live_discord_task-final.jpg";

    /// How long Discord is given to redraw after an action before the next
    /// read, and how many reads a finder makes before giving up.
    const SETTLE: Duration = Duration::from_millis(800);
    const FIND_ATTEMPTS: usize = 3;

    type Plane = ComputerPlane<
        NativeCaptureBackend,
        ExcludeApplicationText,
        ValidatedSeverityTaxonomy,
        PlaneJournalStorage,
        MacOs26PlatformDriver,
    >;

    /// Prints each question the way a person would see its parts, then
    /// answers "allow for this conversation": running this probe with its
    /// arguments is the operator's consent to what it does.
    struct AnsweringCarrier {
        desk: Arc<ConsentDesk>,
        guard: Arc<InFlightGuard>,
        stamp: ScopeStamp,
    }

    impl AnsweringCarrier {
        fn new() -> Self {
            let clock = SystemClock::new();
            let timing = Arc::new(DispatchTimingState::new(&clock));
            Self {
                desk: Arc::new(ConsentDesk::new(Arc::new(
                    crate::allowing_cingulate::AllowingCingulate::new("el_discord_probe_"),
                ))),
                guard: Arc::new(timing.enter(&clock)),
                stamp: ScopeStamp::new(
                    Principal::Reserved {
                        module_id: "prefrontal-core".into(),
                    },
                    identity().conversation_key,
                    1,
                    ScopeKind::Ephemeral,
                )
                .with_attributes(
                    ScopeAttributes::new().with_agent_id(Some(identity().agent_project_id)),
                )
                .with_owner_authorized(true),
            }
        }
    }

    impl QuestionCarrier for AnsweringCarrier {
        fn desk(&self) -> Arc<ConsentDesk> {
            self.desk.clone()
        }
        fn live(&self) -> Result<LiveCall, NotLive> {
            LiveCall::from_inbound(Some(&self.stamp), &self.guard, Arc::new(AlwaysOpenRoute))
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "live-probe".into(),
            conversation_key: "live-discord-task".into(),
            agent_project_id: "live-probe".into(),
            session_kind: SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        }
    }

    fn consent() -> ConsentContext {
        let (drain_sender, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(drain_sender);
        ConsentContext::new(
            GrantCaller::new(
                identity().conversation_key,
                identity().agent_project_id,
                false,
            ),
            Some(Arc::new(AnsweringCarrier::new()) as Arc<dyn QuestionCarrier>),
            Arc::new(AlwaysOpenRoute),
            drain,
            None,
        )
    }

    #[cfg(test)]
    #[tokio::test]
    async fn answering_carrier_answers_repeated_cards_through_the_desk() {
        use cerebellum::computer_grants::{ComputerGrants, GrantNeed};
        let grants = Arc::new(ComputerGrants::in_memory());
        let mut context = consent();
        let carrier = context.carrier.as_ref().unwrap().clone();
        let cancel = cerebellum::CancelHandle::pending();
        grants
            .require(&GrantNeed::Takeover, &context, &cancel)
            .await
            .unwrap();
        assert!(grants.holds(&context.caller, &GrantNeed::Takeover));
        // Grants belong to the agent, so another conversation of the same
        // agent reuses the first approval and raises no second card.
        context.caller.conversation_key.push_str(":second");
        grants
            .require(&GrantNeed::Takeover, &context, &cancel)
            .await
            .unwrap();
        assert!(grants.holds(&context.caller, &GrantNeed::Takeover));
        assert!(carrier.desk().raised("el_discord_probe_1").unwrap().applied);
        assert!(carrier.desk().raised("el_discord_probe_2").is_none());
    }

    /// The frontmost application, sampled every 100 ms until stopped.
    struct Sampler {
        samples: Arc<Mutex<Vec<Sample>>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Sampler {
        fn start(started: Instant) -> Self {
            let samples = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let samples = samples.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        samples.lock().unwrap().push((
                            started.elapsed().as_millis(),
                            cerebellum_macos::frontmost_process_id(),
                        ));
                        std::thread::sleep(Duration::from_millis(100));
                    }
                })
            };
            Self {
                samples,
                stop,
                thread: Some(thread),
            }
        }

        fn finish(mut self) -> Vec<Sample> {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let samples = self.samples.lock().unwrap().clone();
            samples
        }
    }

    /// What a `read_state` asks for.
    #[derive(Default, Clone)]
    struct Read {
        image: bool,
        text: Option<String>,
        roles: &'static [&'static str],
        subtree: Option<String>,
    }

    /// The plane, and the record of what the probe did with it.
    struct Desk {
        plane: Plane,
        management: Arc<ManagementPlane>,
        clock: SystemClock,
        started: Instant,
        spans: Vec<Span>,
        failures: Vec<String>,
        dry_read: bool,
    }

    impl Desk {
        fn elapsed_ms(&self) -> u128 {
            self.started.elapsed().as_millis()
        }

        fn begin(&self, step: &str) -> u128 {
            println!();
            println!("STEP {step}");
            self.elapsed_ms()
        }

        fn end(&mut self, step: &str, start_ms: u128) {
            self.spans.push(Span {
                step: step.to_string(),
                start_ms,
                end_ms: self.elapsed_ms(),
            });
        }

        fn fail(&mut self, problem: String) {
            println!("  FAILED: {problem}");
            self.failures.push(problem);
        }

        async fn serve(&self, name: &'static str, arguments: Value) -> Value {
            println!("  -> {name} {arguments}");
            let reply = self
                .plane
                .serve(
                    servable(name).expect("the capability is served"),
                    &arguments,
                    ServeContext {
                        cancel: cerebellum::CancelHandle::pending(),
                        grantee: "live-probe",
                        identity: identity(),
                        management: &self.management,
                        consent: consent(),
                        clock: &self.clock,
                        now_ms: 0,
                    },
                    |_| NativeCaptureBackend::new(Duration::from_secs(10)),
                )
                .await
                .unwrap_or_else(
                    |error| json!({"outcome": "withheld", "error": format!("{error:?}")}),
                );
            println!("  <- {}", task::reply_summary(&reply));
            reply
        }

        async fn read(&self, read: Read) -> (Value, Vec<TreeLine>) {
            let mut arguments = json!({"target": DISCORD, "include_image": read.image});
            if let Some(text) = &read.text {
                arguments["text_filter"] = json!(text);
            }
            if !read.roles.is_empty() {
                arguments["role_filter"] = json!(read.roles);
            }
            if let Some(subtree) = &read.subtree {
                arguments["subtree_element_id"] = json!(subtree);
            }
            let reply = self.serve("computer.read_state", arguments).await;
            let lines = task::parse_tree(reply["tree"].as_str().unwrap_or_default());
            (reply, lines)
        }

        /// Read and look for one element, allowing Discord a few redraws to
        /// show it.
        async fn find(
            &self,
            what: &str,
            read: Read,
            finder: impl Fn(&[TreeLine]) -> Result<TreeLine, FindFailure>,
        ) -> Result<TreeLine, FindFailure> {
            let mut last = Err(FindFailure::Missing);
            for attempt in 0..FIND_ATTEMPTS {
                if attempt > 0 {
                    tokio::time::sleep(SETTLE).await;
                }
                let (_, lines) = self.read(read.clone()).await;
                last = finder(&lines);
                if !matches!(last, Err(FindFailure::Missing)) {
                    break;
                }
            }
            match &last {
                Ok(line) => println!("  found {what}: {}", line.describe()),
                Err(failure) => println!("  {what}: {failure}"),
            }
            last
        }

        /// Take one action. The guard runs first and a refusal sends nothing;
        /// in a dry read nothing is sent either, and the planned request is
        /// printed instead.
        async fn act(&mut self, planned: Planned<'_>) -> Option<Value> {
            let (name, arguments) = match task::checked_request(&planned) {
                Ok(request) => request,
                Err(refusal) => {
                    self.fail(format!("GUARD {refusal}"));
                    return None;
                }
            };
            if self.dry_read {
                println!("  (dry read) would send {name} {arguments}");
                return None;
            }
            let reply = self.serve(name, arguments).await;
            let completed = matches!(reply["outcome"].as_str(), Some("completed"));
            // A chord changes no value that could confirm it arrived, so the
            // plane answers delivery_unconfirmed for every keys call that
            // posted; that is the keys row's success.
            let keys_posted = name == "computer.keys" && reply["outcome"] == "delivery_unconfirmed";
            if !completed && !keys_posted {
                self.fail(format!("{name} answered {}", task::reply_summary(&reply)));
            }
            Some(reply)
        }
    }

    pub fn run() -> i32 {
        if !task::pending_review_admitted(PENDING_REVIEW_SWITCH) {
            println!(
                "REFUSED: this build binds no review keys. Rebuild with \
                 CEREBELLUM_PROBE_PENDING_REVIEW=1 to bind {} for this probe only; they are \
                 pending review",
                PROBE_REVIEW_KEYS.join(", ")
            );
            return 1;
        }
        let options = match task::parse_options(std::env::args().skip(1)) {
            Ok(options) => options,
            Err(problem) => {
                println!("FAILED: {problem}");
                return 1;
            }
        };
        let file = match &options.file {
            Some(file) => match std::fs::canonicalize(file) {
                Ok(path) if path.is_file() => Some(path.display().to_string()),
                _ => {
                    println!("FAILED: {file} is not a readable file");
                    return 1;
                }
            },
            None => None,
        };
        let target = match cerebellum_computer::platform::native::resolve_target(
            DISCORD,
            Duration::from_secs(3),
        ) {
            TargetResolution::Resolved(grant) => Some(grant),
            _ => None,
        };
        if let Err(problem) = task::readiness(
            cerebellum_macos::screen_is_locked(),
            cerebellum_macos::accessibility_is_permitted(),
            target.is_some(),
        ) {
            println!("UNMEASURABLE: {problem}");
            return 2;
        }
        let Some(target) = target else {
            return 2;
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                println!("FAILED: no runtime: {error}");
                return 1;
            }
        };
        runtime.block_on(probe(options, file, target))
    }

    async fn probe(
        options: task::Options,
        file: Option<String>,
        target: cerebellum_computer::platform::ProcessGrant,
    ) -> i32 {
        println!(
            "PENDING REVIEW: this build binds {} to {PENDING_REVIEW_REVISION:?}. No review has \
             approved them; they hold for this probe's build only.",
            PROBE_REVIEW_KEYS.join(", ")
        );
        let audit = match computer_audit(JournalPersistence::Isolated) {
            Ok(audit) => audit,
            Err(error) => {
                println!("FAILED: no isolated journal: {error}");
                return 1;
            }
        };
        let plane = ComputerPlane::<NativeCaptureBackend, _, _, _, _>::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            || {
                MacOs26PlatformDriver::default()
                    .without_expected_post_condition()
                    .with_takeover_dispatch_review_revision(Some(
                        PENDING_REVIEW_REVISION.to_string(),
                    ))
            },
        )
        .with_fronting_bracket_admitted(true);
        let started = Instant::now();
        let mut desk = Desk {
            plane,
            management: Arc::new(ManagementPlane::new(Arc::new(PlatformResolver::new()))),
            clock: SystemClock::new(),
            started,
            spans: Vec::new(),
            failures: Vec::new(),
            dry_read: options.dry_read,
        };
        let discord_pid = i32::try_from(target.pid).unwrap_or(i32::MAX);
        println!(
            "application: {} (pid {}){}",
            target.bundle_identity,
            target.pid,
            if options.dry_read {
                ", dry read: nothing is pressed, written or typed"
            } else {
                ""
            }
        );
        let sampler = Sampler::start(started);
        let frontmost_at_start = cerebellum_macos::frontmost_process_id();

        let stopped = steps(&mut desk, &options, file.as_deref()).await;
        if let Err(reason) = &stopped {
            println!();
            println!("STOPPED: {reason}");
        }

        let end_ms = desk.elapsed_ms();
        let samples = sampler.finish();
        report_frontmost(&mut desk, &samples, end_ms, discord_pid, frontmost_at_start);

        println!();
        if stopped.is_err() || !desk.failures.is_empty() {
            println!(
                "FAILED: {} problem(s)",
                desk.failures.len() + usize::from(stopped.is_err())
            );
            for failure in &desk.failures {
                println!("  {failure}");
            }
            return 1;
        }
        println!("PASS");
        0
    }

    /// The six steps. An `Err` stops the run where a step could not go on
    /// without guessing.
    async fn steps(
        desk: &mut Desk,
        options: &task::Options,
        file: Option<&str>,
    ) -> Result<(), String> {
        let user = options.user.clone();

        let step = "1 read_state";
        let start = desk.begin(step);
        let (read, lines) = desk
            .read(Read {
                image: true,
                ..Read::default()
            })
            .await;
        let tree = read["tree"].as_str().unwrap_or_default();
        println!(
            "  tree: {} elements, {} bytes{}",
            lines.len(),
            tree.len(),
            read.get("truncation")
                .map(|truncation| format!(", truncation {truncation}"))
                .unwrap_or_default()
        );
        report_image(&read, None);
        desk.end(step, start);
        if read["outcome"] != "completed" {
            return Err(format!(
                "the first read answered {}",
                task::reply_summary(&read)
            ));
        }

        // Cleanup mode: close an open panel a previous run left attached to
        // Discord's window, through the same accessibility path, and stop.
        if std::env::var_os("CEREBELLUM_PROBE_CANCEL_PANEL").is_some() {
            let cancel = desk
                .find(
                    "panel Cancel button",
                    Read {
                        roles: &["button"],
                        text: Some("Cancel".into()),
                        ..Read::default()
                    },
                    |lines| {
                        task::unique(lines, |line| {
                            line.role == "button" && line.head() == "Cancel"
                        })
                    },
                )
                .await
                .map_err(|failure| format!("the panel's Cancel button: {failure}"))?;
            desk.act(Planned::Press(&cancel)).await;
            return Ok(());
        }

        let step = "2 open the direct message";
        let start = desk.begin(step);
        let opened = open_direct_message(desk, &user).await;
        desk.end(step, start);
        if !options.dry_read {
            opened?;
        }

        let step = "3 find the composer";
        let start = desk.begin(step);
        let composer_user = user.clone();
        let composer = desk
            .find(
                "composer",
                Read {
                    roles: &["text area"],
                    ..Read::default()
                },
                move |lines| task::find_composer(lines, &composer_user),
            )
            .await;
        desk.end(step, start);
        let composer = match composer {
            Ok(composer) => Some(composer),
            Err(failure) if options.dry_read => {
                println!("  (dry read) no composer to act on: {failure}");
                None
            }
            Err(failure) => return Err(format!("the composer: {failure}")),
        };

        let skip_attach = std::env::var_os("CEREBELLUM_PROBE_SKIP_ATTACH").is_some();
        if let (Some(file), Some(composer), false) = (file, composer.as_ref(), skip_attach) {
            let step = "4 attach";
            let start = desk.begin(step);
            let attached = attach(desk, composer, file).await;
            desk.end(step, start);
            attached?;
        }

        if let (Some(text), Some(composer)) = (options.text.as_deref(), composer.as_ref()) {
            let step = "5 write the message";
            let start = desk.begin(step);
            // Pressing the composer first gives it focus inside the app, which
            // some editors need before they accept an accessibility write.
            if std::env::var_os("CEREBELLUM_PROBE_PRESS_COMPOSER").is_some() {
                desk.act(Planned::Press(composer)).await;
                tokio::time::sleep(SETTLE).await;
            }
            if let Some(reply) = desk
                .act(Planned::WriteText {
                    element: composer,
                    text,
                })
                .await
            {
                println!(
                    "  read-back: {} ({})",
                    reply["outcome"].as_str().unwrap_or("(none)"),
                    reply["effect_status"]
                        .as_str()
                        .unwrap_or("no effect_status")
                );
            }
            desk.end(step, start);
        }

        let step = "6 final read";
        let start = desk.begin(step);
        let (read, _) = desk
            .read(Read {
                image: true,
                ..Read::default()
            })
            .await;
        report_image(&read, Some(FINAL_IMAGE_PATH));
        let (_, composer_lines) = desk
            .read(Read {
                roles: &["text area"],
                ..Read::default()
            })
            .await;
        match composer
            .as_ref()
            .and_then(|composer| composer_lines.iter().find(|line| line.id == composer.id))
        {
            Some(line) => println!("  composer now: {:?}", line.label),
            None => println!("  composer now: not in the tree"),
        }
        let (_, attachment_lines) = desk
            .read(Read {
                text: Some("Remove Attachment".into()),
                ..Read::default()
            })
            .await;
        println!(
            "  attachment staged (Remove Attachment control present): {}",
            task::has_remove_attachment(&attachment_lines)
        );
        desk.end(step, start);
        Ok(())
    }

    async fn open_direct_message(desk: &mut Desk, user: &str) -> Result<(), String> {
        let row = desk
            .find(
                "Direct Messages row",
                Read {
                    text: Some("Direct Messages".into()),
                    ..Read::default()
                },
                task::find_direct_messages,
            )
            .await
            .map_err(|failure| format!("the Direct Messages row: {failure}"))?;
        desk.act(Planned::Press(&row)).await;
        tokio::time::sleep(SETTLE).await;

        let link_user = user.to_string();
        let link = desk
            .find(
                "direct message link",
                Read {
                    text: Some(format!("{user} (direct message)")),
                    ..Read::default()
                },
                move |lines| task::find_dm_link(lines, &link_user),
            )
            .await
            .map_err(|failure| format!("the link to {user}'s direct message: {failure}"))?;
        desk.act(Planned::Press(&link)).await;
        tokio::time::sleep(SETTLE).await;
        Ok(())
    }

    /// Stage the file through Discord's own open panel, reached through
    /// accessibility only. Returns `Err` only when the probe cannot go on
    /// safely; a panel that is not in the tree is a finding, not a stop.
    async fn attach(desk: &mut Desk, composer: &TreeLine, file: &str) -> Result<(), String> {
        const WINDOW_ROLES: &[&str] = &["window", "sheet", "dialog"];
        let (_, windows_before) = desk
            .read(Read {
                roles: WINDOW_ROLES,
                ..Read::default()
            })
            .await;

        let control = desk
            .find(
                "upload control",
                Read {
                    roles: &task::UPLOAD_CONTROL_ROLES,
                    ..Read::default()
                },
                task::find_upload_control,
            )
            .await
            .map_err(|failure| format!("the upload control: {failure}"))?;
        desk.act(Planned::Press(&control)).await;
        tokio::time::sleep(SETTLE).await;

        let item = match desk
            .find(
                "Upload a File menu item",
                Read {
                    text: Some("Upload a File".into()),
                    ..Read::default()
                },
                task::find_upload_menu_item,
            )
            .await
        {
            Ok(item) => item,
            Err(failure) => {
                // Like a missing panel, a missing menu is a reach finding: the
                // rest of the task does not depend on the attachment.
                println!(
                    "  REACH: the upload menu did not appear in Discord's accessibility tree \
                     after pressing the upload control ({failure}); the attach is skipped"
                );
                return Ok(());
            }
        };
        desk.act(Planned::Press(&item)).await;
        tokio::time::sleep(SETTLE * 2).await;

        let (_, windows_after) = desk
            .read(Read {
                roles: WINDOW_ROLES,
                ..Read::default()
            })
            .await;
        let panels = task::new_panels(&windows_before, &windows_after);
        let panel = match panels.as_slice() {
            [] => {
                println!(
                    "  REACH: no open panel appeared in Discord's accessibility tree after \
                     \"Upload a File\"; the attach is skipped and the pointer is not used"
                );
                return Ok(());
            }
            [panel] => panel.clone(),
            many => {
                return Err(format!(
                    "{} new windows appeared after \"Upload a File\": {}",
                    many.len(),
                    many.iter()
                        .map(TreeLine::describe)
                        .collect::<Vec<_>>()
                        .join("; ")
                ))
            }
        };
        println!(
            "  REACH: an open panel is in Discord's tree: {}",
            panel.describe()
        );
        let in_panel = Read {
            subtree: Some(panel.id.clone()),
            ..Read::default()
        };
        let (_, inside) = desk.read(in_panel.clone()).await;
        println!(
            "  panel: settable path field {}, Open button {}",
            match task::find_path_field(&inside, &composer.id) {
                Ok(field) => field.describe(),
                Err(failure) => format!("not found ({failure})"),
            },
            match task::find_open_button(&inside) {
                Ok(button) => button.describe(),
                Err(failure) => format!("not found ({failure})"),
            }
        );

        // Discord is in the background, and keystrokes reach a background
        // application only by the plane bringing it to the front for at most
        // 100 ms and then putting the previous application back. Doing that
        // can take the person's own keystrokes, so it needs the takeover
        // grant, and this call raises the takeover question.
        desk.act(Planned::Keys {
            keys: &["command", "shift", "g"],
            focused: None,
            composer: Some(&composer.id),
        })
        .await;
        tokio::time::sleep(SETTLE).await;

        let composer_id = composer.id.clone();
        let field = desk
            .find("path field", in_panel.clone(), move |lines| {
                task::find_path_field(lines, &composer_id)
            })
            .await
            .map_err(|failure| format!("the panel's path field: {failure}"))?;
        desk.act(Planned::WriteText {
            element: &field,
            text: file,
        })
        .await;

        // Return is sent only when a fresh read shows focus off the composer.
        let (focus_read, _) = desk.read(in_panel.clone()).await;
        desk.act(Planned::Keys {
            keys: &["return"],
            focused: focus_read["focused_element_id"].as_str(),
            composer: Some(&composer.id),
        })
        .await;
        tokio::time::sleep(SETTLE).await;

        let open = desk
            .find("Open button", in_panel, task::find_open_button)
            .await;
        match open {
            Ok(open) => {
                desk.act(Planned::Press(&open)).await;
                tokio::time::sleep(SETTLE).await;
            }
            Err(failure) => {
                desk.fail(format!("the panel's Open button: {failure}"));
            }
        }
        Ok(())
    }

    /// Print what a read returned in place of, or as, its image, and save
    /// it when `save_to` names a path.
    fn report_image(read: &Value, save_to: Option<&str>) {
        let image = &read["image"];
        let Some(data) = image["data_b64"].as_str() else {
            println!(
                "  image: none, image_unavailable {}",
                read["image_unavailable"]["reason"]
                    .as_str()
                    .unwrap_or("(no reason given)")
            );
            return;
        };
        let bytes = match cerebellum_core::serde_base64::decode(data) {
            Ok(bytes) => bytes,
            Err(problem) => {
                println!("  image: returned but not decodable: {problem}");
                return;
            }
        };
        println!(
            "  image: {} x {} px, {} bytes, {}",
            image["width_px"],
            image["height_px"],
            bytes.len(),
            image["image_id"].as_str().unwrap_or("(no id)")
        );
        if let Some(path) = save_to {
            match std::fs::write(path, &bytes) {
                Ok(()) => println!("  image saved to {path}"),
                Err(error) => println!("  image not saved to {path}: {error}"),
            }
        }
    }

    fn app_name(pid: Option<i32>) -> String {
        let Some(pid) = pid else {
            return "(no frontmost window)".to_string();
        };
        match u32::try_from(pid).ok().and_then(|pid| {
            cerebellum_macos::process_executable_path(pid)
                .ok()
                .flatten()
        }) {
            Some(path) => format!(
                "{} (pid {pid})",
                task::app_name_from_path(&path.to_string_lossy())
            ),
            None => format!("pid {pid}"),
        }
    }

    fn report_frontmost(
        desk: &mut Desk,
        samples: &[Sample],
        end_ms: u128,
        discord_pid: i32,
        frontmost_at_start: Option<i32>,
    ) {
        println!();
        println!(
            "FRONTMOST ({} samples every 100 ms over {end_ms} ms)",
            samples.len()
        );
        for (pid, held_ms) in task::frontmost_durations(samples, end_ms) {
            println!("  {}: {held_ms} ms", app_name(pid));
        }
        let (steps, outside) = task::steps_with_frontmost(samples, &desk.spans, discord_pid);
        println!("  steps that ran with Discord frontmost: {steps:?}");
        if outside > 0 {
            println!("  samples with Discord frontmost between steps: {outside}");
        }
        if frontmost_at_start == Some(discord_pid) {
            println!(
                "  Discord was frontmost when the probe started, so these samples cannot show \
                 which steps brought it forward"
            );
            return;
        }
        let unexpected: Vec<&String> = steps.iter().filter(|step| *step != "4 attach").collect();
        if !unexpected.is_empty() || outside > 0 {
            desk.fail(format!(
                "Discord came to the front outside the attach step's keystrokes: {unexpected:?}, \
                 {outside} sample(s) between steps"
            ));
        }
    }
}
