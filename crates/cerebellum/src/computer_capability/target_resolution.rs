use super::*;

impl<B, R, T, S, D> ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    /// The bundle identity a request's `target` names, which may be the
    /// application's display name, or the refusal for a name that matches
    /// no running application or several.
    ///
    /// A target spelled like a bundle identity (dotted, no spaces) is returned
    /// as it is, without listing anything, so the process lookup that follows
    /// still refuses one nobody runs as `not_running`. A display name is
    /// matched against the running applications; when they cannot be listed,
    /// the name is returned as it is and the process lookup refuses it as it
    /// would any unknown bundle identity.
    pub(crate) async fn resolve_target_name(&self, target: &str) -> Result<String, Value> {
        self.resolve_target_name_holding(target, None).await
    }

    /// [`Self::resolve_target_name`] with the listing query holding `hold`, a
    /// blocking-worker permit, until the query really ends.
    pub(crate) async fn resolve_target_name_holding(
        &self,
        target: &str,
        hold: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    ) -> Result<String, Value> {
        if looks_like_bundle_identity(target) {
            crate::tool_display::app(target);
            return Ok(target.to_string());
        }
        let source = self.app_state_source.clone();
        let listed = tokio::task::spawn_blocking(move || {
            let _permit = hold;
            source.running_apps()
        })
        .await
        .unwrap_or(Err(AppStateReadError::Unreadable));
        match listed {
            Ok(apps) => match_target_name(target, &apps).map(|matched| {
                crate::tool_display::app(&matched.bundle_identity);
                // `serve` writes this name on the reply as matched_app, so the
                // caller learns which application a partial name was taken to
                // mean. The queueing step that resolves a target before
                // `serve` runs has no MATCHED_APP slot, so it records nothing.
                if let Some(name) = matched.partial_name {
                    let _ = MATCHED_APP.try_with(|slot| {
                        *slot.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(name);
                    });
                }
                matched.bundle_identity
            }),
            Err(_) => Ok(target.to_string()),
        }
    }
}

/// Whether a target is spelled like a bundle identity (`com.apple.Safari`)
/// rather than a display name (`Safari`): dotted, with no spaces.
pub(crate) fn looks_like_bundle_identity(target: &str) -> bool {
    let target = target.trim();
    target.contains('.') && !target.contains(char::is_whitespace)
}

/// A target name resolved to a running application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MatchedTarget {
    pub(super) bundle_identity: String,
    /// The application's full name when the target named it only in part
    /// (a prefix or whole words of its name); `None` for an exact match.
    partial_name: Option<String>,
}

tokio::task_local! {
    /// Where name resolution leaves the full name of an application a call's
    /// target matched only in part, for `serve` to say on the reply.
    pub(super) static MATCHED_APP: Arc<std::sync::Mutex<Option<String>>>;
}

/// Whether `wanted` names `name` in part: the name starts with it, or it is
/// one or more whole words of the name in order ("Context Dashboard" in
/// "Magic Context Dashboard"). Case is ignored. An empty `wanted` names
/// nothing, so it can never match every application at once.
fn names_in_part(name: &str, wanted: &str) -> bool {
    let name = name.trim().to_lowercase();
    let wanted = wanted.trim().to_lowercase();
    if wanted.is_empty() {
        return false;
    }
    if name.starts_with(&wanted) {
        return true;
    }
    let name_words: Vec<&str> = name.split_whitespace().collect();
    let wanted_words: Vec<&str> = wanted.split_whitespace().collect();
    name_words
        .windows(wanted_words.len())
        .any(|window| window == wanted_words.as_slice())
}

/// The candidates a refusal lists: each running application once per
/// process, as name, bundle identity and pid.
fn candidate_list(apps: &[&RunningApp]) -> Vec<Value> {
    apps.iter()
        .map(|app| {
            json!({
                "name": app.name,
                "bundle_identity": app.bundle_identity,
                "pid": app.pid,
            })
        })
        .collect()
}

/// The distinct bundle identities among `apps`, sorted.
fn distinct_identities<'a>(apps: &[&'a RunningApp]) -> Vec<&'a str> {
    let mut identities: Vec<&str> = apps
        .iter()
        .map(|app| app.bundle_identity.as_str())
        .collect();
    identities.sort_unstable();
    identities.dedup();
    identities
}

/// What a `target` given as a name resolves to among the running
/// applications: the one bundle identity carrying that name, or the refusal
/// that says why there is not exactly one.
///
/// A name is matched whole and without regard to case first. Only when no
/// application has exactly that name is it matched in part (see
/// [`names_in_part`]), so a model that shortens "Magic Context Dashboard"
/// to "Magic Context" still reaches it; the reply then names the application
/// it picked. A partial name fitting several applications is refused with
/// all of them listed, never guessed between. Several processes of one
/// application are one match here; resolving the bundle identity then
/// refuses them as `ambiguous` exactly as it always has.
pub(super) fn match_target_name(target: &str, apps: &[RunningApp]) -> Result<MatchedTarget, Value> {
    let wanted = target.trim();
    if let Some(app) = apps
        .iter()
        .find(|app| app.bundle_identity.eq_ignore_ascii_case(wanted))
    {
        return Ok(MatchedTarget {
            bundle_identity: app.bundle_identity.clone(),
            partial_name: None,
        });
    }
    let named: Vec<&RunningApp> = apps
        .iter()
        .filter(|app| app.name.trim().eq_ignore_ascii_case(wanted))
        .collect();
    match distinct_identities(&named).as_slice() {
        [only] => {
            return Ok(MatchedTarget {
                bundle_identity: (*only).to_string(),
                partial_name: None,
            })
        }
        [] => {}
        _ => {
            return Err(json!({
                "outcome": "ambiguous_app",
                "target": wanted,
                "candidates": candidate_list(&named),
                // Named rather than chosen between: picking one would act on an
                // application the caller did not single out.
                "remedy": "several running applications have this name; retry with the app \
                           identity (a bundle id on macOS) of the one you mean",
            }));
        }
    }
    let partly: Vec<&RunningApp> = apps
        .iter()
        .filter(|app| names_in_part(&app.name, wanted))
        .collect();
    match distinct_identities(&partly).as_slice() {
        [only] => Ok(MatchedTarget {
            bundle_identity: (*only).to_string(),
            partial_name: partly
                .iter()
                .find(|app| app.bundle_identity == *only)
                .map(|app| app.name.trim().to_string()),
        }),
        [] => Err(json!({
            "outcome": "no_running_app_named",
            "target": wanted,
            "remedy": "no running application has this name or app identity; list_apps shows \
                       the running applications, and any of their names or app identities \
                       (bundle ids on macOS) is a target",
        })),
        _ => Err(json!({
            "outcome": "ambiguous_app",
            "target": wanted,
            "candidates": candidate_list(&partly),
            "remedy": "this name fits several running applications; retry with the full name or \
                       the app identity (a bundle id on macOS) of the one you mean",
        })),
    }
}

#[cfg(test)]
mod name_match_tests {
    use super::*;

    fn app(name: &str, bundle_identity: &str, pid: u32) -> RunningApp {
        RunningApp {
            name: name.into(),
            bundle_identity: bundle_identity.into(),
            pid,
            frontmost: false,
        }
    }

    fn desk() -> Vec<RunningApp> {
        vec![
            app("Magic Context Dashboard", "com.example.dashboard", 1),
            app("Magic Mouse Utility", "com.example.mouse", 2),
            app("Mail", "com.apple.mail", 3),
            app("Mailspring", "com.example.mailspring", 4),
        ]
    }

    #[test]
    fn a_partial_name_fitting_one_app_resolves_and_names_it() {
        for wanted in [
            "Magic Context",
            "magic context dash",
            "Context Dashboard",
            "dashboard",
        ] {
            assert_eq!(
                match_target_name(wanted, &desk()).unwrap(),
                MatchedTarget {
                    bundle_identity: "com.example.dashboard".into(),
                    partial_name: Some("Magic Context Dashboard".into()),
                },
                "{wanted}"
            );
        }
    }

    #[test]
    fn an_exact_name_wins_over_a_longer_one_it_prefixes() {
        assert_eq!(
            match_target_name("mail", &desk()).unwrap(),
            MatchedTarget {
                bundle_identity: "com.apple.mail".into(),
                partial_name: None,
            }
        );
    }

    #[test]
    fn a_partial_name_fitting_several_apps_refuses_listing_them() {
        let refusal = match_target_name("Magic", &desk()).unwrap_err();
        assert_eq!(refusal["outcome"], "ambiguous_app");
        assert_eq!(refusal["target"], "Magic");
        assert_eq!(refusal["remedy"], "this name fits several running applications; retry with the full name or the app identity (a bundle id on macOS) of the one you mean");
        let names: Vec<_> = refusal["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Magic Context Dashboard", "Magic Mouse Utility"]);
    }

    #[test]
    fn a_word_inside_another_word_or_an_empty_name_matches_nothing() {
        for wanted in ["agic", "ontext Dash", "", "   "] {
            assert_eq!(
                match_target_name(wanted, &desk()).unwrap_err()["outcome"],
                "no_running_app_named",
                "{wanted:?}"
            );
        }
    }

    #[test]
    fn an_accessibility_regrant_remedy_names_macos() {
        let reply = unreadable_application_reply(AppStateReadError::AccessibilityNotPermitted);
        assert_eq!(reply["remedy"], "On macOS, this module may not read other applications' accessibility trees; the Accessibility permission must be granted to it again");
    }

    #[test]
    fn list_apps_takes_only_an_optional_text_filter() {
        assert_eq!(parse_list_apps_request(&json!({})), Ok(None));
        assert_eq!(
            parse_list_apps_request(&json!({"text_filter":"  Mail "})),
            Ok(Some("Mail".into()))
        );
        assert_eq!(
            parse_list_apps_request(&json!({"text_filter":" "})),
            Ok(None)
        );
        assert_eq!(
            parse_list_apps_request(&json!({"text_filter":3})).unwrap_err()["field"],
            "text_filter"
        );
        assert_eq!(
            parse_list_apps_request(&json!({"zoom":"x"})).unwrap_err()["field"],
            "zoom"
        );
        assert!(listed_by_filter(
            Some("MAIL"),
            "Mailspring",
            "com.example.mailspring"
        ));
        assert!(listed_by_filter(Some("apple.ma"), "Mail", "com.apple.mail"));
        assert!(!listed_by_filter(
            Some("mail"),
            "Calendar",
            "com.apple.iCal"
        ));
        assert!(listed_by_filter(None, "Calendar", "com.apple.iCal"));
    }
}
