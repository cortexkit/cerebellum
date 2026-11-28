use super::{AppStateSource, AppUse, InstalledApp, ResolvedInstalled, Value};
use crate::computer_capability::{
    fronting::{Fronting, Restore},
    target_resolution::names_in_part,
};
use cerebellum_computer::platform::windows::{identity::Principal, launch::foreground_sample};
use serde_json::json;

pub(super) fn consent_name(app: &InstalledApp) -> String {
    match app.bundle_identity.parse::<Principal>() {
        Ok(Principal::Signed {
            cn,
            organization,
            program,
            ..
        }) => {
            let subject = [cn, organization]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{} (any program this publisher, {}, signs as {})",
                app.name, subject, program
            )
        }
        _ => app.name.clone(),
    }
}

pub(super) fn sample() -> (Option<u32>, Option<u32>) {
    foreground_sample()
}

pub(super) fn foreground_change(before: (Option<u32>, Option<u32>)) -> Option<Fronting> {
    let (after, last_input) = sample();
    if before.0 == after {
        return None;
    }
    let person = matches!((before.1, last_input), (Some(old), Some(now)) if old != now);
    let mut report = Fronting::untouched(AppUse::Background);
    report.person_input_during_fronting = person;
    // It is safe to report the change without asking Windows to restore focus.
    report.restore = if person {
        Restore::SkippedPerson
    } else {
        Restore::LeftInFront
    };
    Some(report)
}

pub(super) fn resolve(
    target: &str,
    apps: &[InstalledApp],
    source: &dyn AppStateSource,
) -> Result<ResolvedInstalled, Value> {
    let wanted = target.trim();
    let canonical = wanted.parse::<Principal>().ok();
    let mut matches: Vec<_> = apps
        .iter()
        .filter(|app| {
            let Some(entry) = &app.windows_entry else {
                return false;
            };
            let Ok(principal) = app.bundle_identity.parse::<Principal>() else {
                return false;
            };
            if let Some(canonical) = &canonical {
                return canonical == &principal;
            }
            app.name.trim().eq_ignore_ascii_case(wanted)
                || entry
                    .executable_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
                || principal
                    .executable()
                    .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
        })
        .collect();
    if canonical.is_none() && matches.is_empty() {
        matches = apps
            .iter()
            .filter(|app| app.windows_entry.is_some() && names_in_part(&app.name, wanted))
            .collect();
    }
    match matches.as_slice() {
        [] => Err(
            json!({"outcome":"no_installed_app_named", "target":wanted, "remedy":"list_apps shows installed applications; use an exact name or app identity"}),
        ),
        [app] => {
            let instances = source.running_app_instances(&app.bundle_identity)
                .map_err(|_| json!({"outcome":"launch_failed", "remedy":"Running applications could not be checked; use list_apps before retrying."}))?;
            match instances.as_slice() {
                [] => Ok(ResolvedInstalled {
                    app: (*app).clone(),
                    running: None,
                }),
                [instance] => Ok(ResolvedInstalled {
                    app: (*app).clone(),
                    running: Some(instance.process.clone()),
                }),
                _ => Err(
                    json!({"outcome":"ambiguous_app", "target":wanted, "candidates":[{"name":app.name,"bundle_identity":app.bundle_identity}], "remedy":"Multiple instances are running. Ask the person to close extra instances, then retry."}),
                ),
            }
        }
        _ => Err(
            json!({"outcome":"ambiguous_app", "target":wanted, "candidates":matches.iter().map(|app| json!({"name":app.name,"bundle_identity":app.bundle_identity})).collect::<Vec<_>>(), "remedy":"Several installed applications match. Use a unique app identity or ask the person which to open."}),
        ),
    }
}
