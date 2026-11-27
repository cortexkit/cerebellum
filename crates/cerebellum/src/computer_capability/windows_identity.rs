use super::{operator_apps, target_resolution::names_in_part};
use crate::computer_grants::{AppCode, AppIdentity, AppIdentityUnreadable};
use cerebellum_computer::platform::{
    windows::identity::{
        identity_inventory, live_identity, resolve_principal, shell_image, IdentityError,
        IdentityInventory, LiveIdentity, Principal, RunningIdentity, IDENTITY_BOUND,
    },
    ProcessGrant, TargetResolution,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Instant;

fn shell_target(target: &str) -> bool {
    shell_image(target.rsplit(['/', '\\']).next().unwrap_or(target))
        || ["Start", "Taskbar", "Run dialog"]
            .iter()
            .any(|name| target.eq_ignore_ascii_case(name))
}

pub(super) fn blocked(identity: &LiveIdentity) -> bool {
    shell_image(&identity.image_name)
        || operator_apps::identity_blocked(&identity.image_name)
        || identity
            .original_filename
            .as_deref()
            .is_some_and(|program| shell_image(program) || operator_apps::identity_blocked(program))
        || operator_apps::identity_blocked(&identity.principal.to_string())
}

fn unreadable() -> Value {
    json!({
        "outcome": "consent_unavailable",
        "detail": { "reason": "app_identity_unreadable" },
        "remedy": "the application's identity could not be read; nothing was done, retry"
    })
}

fn matching_names(app: &RunningIdentity, target: &str) -> bool {
    app.identity
        .display_name
        .trim()
        .eq_ignore_ascii_case(target)
        || app.identity.image_name.eq_ignore_ascii_case(target)
        || app
            .identity
            .principal
            .executable()
            .is_some_and(|name| name.eq_ignore_ascii_case(target))
}

pub(super) fn resolve_in_inventory(
    target: &str,
    inventory: &IdentityInventory,
) -> Result<TargetResolution, Value> {
    let target = target.trim();
    if shell_target(target) || operator_apps::identity_blocked(target) {
        return Err(operator_apps::refusal());
    }
    if let Ok(principal) = target.parse::<Principal>() {
        if inventory
            .apps
            .iter()
            .any(|app| app.identity.principal == principal && blocked(&app.identity))
        {
            return Err(operator_apps::refusal());
        }
        let resolution = resolve_principal(&principal, inventory);
        return if matches!(resolution, TargetResolution::Unreadable(_)) {
            Err(unreadable())
        } else {
            Ok(resolution)
        };
    }
    let named = |name: &str| name.eq_ignore_ascii_case(target) || names_in_part(name, target);
    if inventory.blocked.iter().any(|name| named(name)) {
        return Err(operator_apps::refusal());
    }
    let mut matches: Vec<_> = inventory
        .apps
        .iter()
        .filter(|app| matching_names(app, target))
        .collect();
    if matches.is_empty() {
        matches = inventory
            .apps
            .iter()
            .filter(|app| names_in_part(&app.identity.display_name, target))
            .collect();
    }
    if matches.iter().any(|app| blocked(&app.identity)) {
        return Err(operator_apps::refusal());
    }
    let mut unread = inventory
        .unreadable
        .iter()
        .filter(|name| named(name))
        .peekable();
    if unread.peek().is_some() {
        return if operator_apps::title_names_operator_app(target)
            || unread.any(|name| operator_apps::title_names_operator_app(name))
        {
            Err(operator_apps::refusal())
        } else {
            Err(unreadable())
        };
    }
    let principals: BTreeSet<_> = matches
        .iter()
        .map(|app| app.identity.principal.to_string())
        .collect();
    match principals.len() {
        0 if inventory.unattributed_windows > 0 => Err(unreadable()),
        0 => Ok(TargetResolution::NotRunning),
        1 => {
            let principal = &matches[0].identity.principal;
            if inventory
                .apps
                .iter()
                .any(|app| &app.identity.principal == principal && blocked(&app.identity))
            {
                return Err(operator_apps::refusal());
            }
            Ok(resolve_principal(principal, inventory))
        }
        _ => Err(json!({
            "outcome": "ambiguous_app",
            "target": target,
            "candidates": matches.iter().map(|app| json!({
                "pid": app.pid,
                "bundle_identity": app.identity.principal.to_string(),
                "name": app.identity.display_name,
            })).collect::<Vec<_>>(),
            "remedy": "several running applications have this name; retry with the canonical app identity of the one you mean"
        })),
    }
}

pub(crate) fn resolve_target(target: &str) -> Result<TargetResolution, Value> {
    if shell_target(target) || operator_apps::identity_blocked(target) {
        return Err(operator_apps::refusal());
    }
    let inventory = match identity_inventory(Instant::now() + IDENTITY_BOUND) {
        Ok(inventory) => inventory,
        Err(_) if operator_apps::title_names_operator_app(target) => {
            return Err(operator_apps::refusal())
        }
        Err(_) => return Err(unreadable()),
    };
    resolve_in_inventory(target, &inventory)
}

fn read(grant: &ProcessGrant) -> Result<LiveIdentity, AppIdentityUnreadable> {
    let identity = live_identity(grant.pid, Instant::now() + IDENTITY_BOUND).map_err(|error| {
        let detail = match error {
            IdentityError::ImageMappingStatus(status) => {
                format!("process image mapping returned NT status {status:#010x}")
            }
            IdentityError::AuthenticodeStatus(status) => {
                format!("Authenticode returned {status:#010x}")
            }
            other => format!("Windows app identity: {other:?}"),
        };
        AppIdentityUnreadable::Failed { detail }
    })?;
    if !identity.matches_grant(grant) || blocked(&identity) {
        return Err(AppIdentityUnreadable::Failed {
            detail: "the resolved application changed or is blocked".into(),
        });
    }
    Ok(identity)
}

pub(crate) fn grant_for_pid(pid: u32) -> Option<ProcessGrant> {
    let identity = live_identity(pid, Instant::now() + IDENTITY_BOUND).ok()?;
    (!blocked(&identity)).then(|| identity.grant(pid))
}

pub(crate) fn consent_name(grant: &ProcessGrant) -> Option<String> {
    let identity = read(grant).ok()?;
    Some(match identity.principal {
        Principal::Signed {
            cn,
            organization,
            program,
            ..
        } => {
            let subject = [cn, organization]
                .into_iter()
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{} (any program this publisher, {}, signs as {})",
                identity.display_name, subject, program
            )
        }
        _ => identity.display_name,
    })
}

pub(crate) struct RunningCode(pub(crate) ProcessGrant);

impl AppCode for RunningCode {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        app_identity(&read(&self.0)?)
    }

    fn satisfies(&self, requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        Ok(self.identity()?.designated_requirement == requirement)
    }
}

fn app_identity(identity: &LiveIdentity) -> Result<AppIdentity, AppIdentityUnreadable> {
    let mut requirement = identity.principal.to_string();
    let ad_hoc = matches!(identity.principal, Principal::Unsigned { .. });
    if ad_hoc {
        // The canonical name contains the digest, but only this exact path
        // has the person's approval. Paths are not part of durable grants.
        let path = identity
            .image_path
            .to_str()
            .ok_or_else(|| AppIdentityUnreadable::Failed {
                detail: "the unsigned image path cannot be recorded losslessly".into(),
            })?;
        requirement.push('\n');
        requirement.push_str(path);
    }
    Ok(AppIdentity {
        team_id: None,
        designated_requirement: requirement,
        ad_hoc,
        apple_anchored: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(pid: u32, root: u8, original: &str, display: &str) -> RunningIdentity {
        RunningIdentity {
            pid,
            window_count: 2,
            identity: LiveIdentity {
                principal: Principal::Signed {
                    root: [root; 32],
                    cn: "Publisher".into(),
                    organization: "CortexKit".into(),
                    program: original.into(),
                },
                image_path: r"C:\test\renamed.exe".into(),
                image_name: "renamed.exe".into(),
                original_filename: Some(original.into()),
                display_name: display.into(),
                generation: 100 + u64::from(pid),
            },
        }
    }

    #[test]
    fn canonical_target_never_resolves_a_matching_display_name() {
        let one = fixture(1, 1, "one.exe", "Ordinary");
        let canonical = one.identity.principal.to_string();
        let two = fixture(2, 2, "two.exe", &canonical);
        let mut inventory = IdentityInventory {
            apps: vec![two, one],
            ..Default::default()
        };
        assert!(
            matches!(resolve_in_inventory(&canonical, &inventory), Ok(TargetResolution::Resolved(grant)) if grant.pid == 1)
        );
        inventory.apps.pop();
        assert!(matches!(
            resolve_in_inventory(&canonical, &inventory),
            Ok(TargetResolution::NotRunning)
        ));
    }

    #[test]
    fn ambiguous_names_and_instances_are_distinct() {
        let first = fixture(41, 1, "one.exe", "Shared");
        let second = fixture(42, 2, "two.exe", "Shared");
        let expected = [
            first.identity.principal.to_string(),
            second.identity.principal.to_string(),
        ];
        let mut inventory = IdentityInventory {
            apps: vec![first, second],
            ..Default::default()
        };
        let result = resolve_in_inventory("shared", &inventory).unwrap_err();
        assert_eq!(result["outcome"], "ambiguous_app");
        assert_eq!(result["candidates"][0]["bundle_identity"], expected[0]);
        assert_eq!(result["candidates"][1]["bundle_identity"], expected[1]);
        inventory.apps[1] = fixture(42, 1, "one.exe", "Shared");
        let TargetResolution::Ambiguous(instances) =
            resolve_in_inventory("ONE.EXE", &inventory).unwrap()
        else {
            panic!("expected two instances");
        };
        assert_eq!(
            instances
                .iter()
                .map(|app| (app.pid, app.window_count))
                .collect::<Vec<_>>(),
            [(41, 2), (42, 2)]
        );
    }

    #[test]
    fn shell_operator_and_unreadable_identity_return_named_refusals() {
        let mut inventory = IdentityInventory {
            unreadable: vec!["Alfonso Project".into(), "Other App".into()],
            ..Default::default()
        };
        for target in [
            "explorer.exe",
            "Start",
            "Taskbar",
            "Run dialog",
            "ApplicationFrameHost.exe",
            "Alfonso Project",
            "alfonso-desktop",
        ] {
            assert_eq!(
                resolve_in_inventory(target, &inventory).unwrap_err()["reason"],
                "operator_app_blocked",
                "{target}"
            );
        }
        let mut signed = fixture(9, 1, "Other.exe", "Ordinary");
        signed.identity.image_name = "Alfonso.exe".into();
        inventory.apps.push(signed);
        assert_eq!(
            resolve_in_inventory("Ordinary", &inventory).unwrap_err()["reason"],
            "operator_app_blocked"
        );
        assert_eq!(
            resolve_in_inventory("Other App", &inventory).unwrap_err()["detail"]["reason"],
            "app_identity_unreadable"
        );
    }

    #[test]
    fn requirements_distinguish_publisher_program_and_unsigned_path() {
        let initial = fixture(1, 1, "first.exe", "First").identity;
        let update = fixture(2, 1, "first.exe", "New First").identity;
        let different_root = fixture(3, 2, "first.exe", "First").identity;
        let different_program = fixture(4, 1, "other.exe", "First").identity;
        assert_eq!(app_identity(&initial), app_identity(&update));
        assert_ne!(app_identity(&initial), app_identity(&different_root));
        assert_ne!(app_identity(&initial), app_identity(&different_program));
        let mut unsigned = initial;
        unsigned.principal = Principal::Unsigned {
            sha256: [7; 32],
            image_name: "renamed.exe".into(),
        };
        let requirement = app_identity(&unsigned).unwrap();
        assert!(requirement.ad_hoc);
        assert!(!requirement.names_a_lasting_signer());
        assert!(requirement
            .designated_requirement
            .ends_with(r"C:\test\renamed.exe"));
        unsigned.image_path = r"C:\different\renamed.exe".into();
        assert_ne!(app_identity(&unsigned).unwrap(), requirement);
    }
}
