use super::super::{
    app_state::windows::{eligible_state, is_default_desktop},
    identity::{
        frame_proof, frame_target_pid, retained_identity, LiveIdentity, Principal, IDENTITY_BOUND,
    },
};
use super::inventory::{Fresh, InstallKind, LaunchInventory};
use crate::app_state::source::{InstalledApp, OpenAppBounds, OpenAppError, OpenedApp};
use crate::platform::ProcessGrant;
use cerebellum_windows::{
    activate_application, desktop_window_numbers, file_identity, process_parents,
    retain_image_process, suspended_process, window_identity_facts, ImageMappingReading,
    RetainedProcessHandle,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const ELEVATION_REQUIRED: i32 = 740;
const HRESULT_ELEVATION_REQUIRED: i32 = 0x8007_02e4_u32 as i32;
const POLL: Duration = Duration::from_millis(40);

fn launch_error(error: std::io::Error) -> OpenAppError {
    match error.raw_os_error() {
        Some(ELEVATION_REQUIRED | HRESULT_ELEVATION_REQUIRED) => OpenAppError::ElevationRequired,
        _ => OpenAppError::Failed,
    }
}

fn may_start() -> bool {
    is_default_desktop()
        && cerebellum_windows::current_process_token_facts()
            .is_some_and(|token| !token.elevated && token.integrity_rid == 0x2000)
}

fn may_target(process: &RetainedProcessHandle) -> bool {
    process
        .token_facts()
        .is_some_and(|token| !token.elevated && token.integrity_rid <= 0x2000)
}

fn start(fresh: &Fresh, end: Instant) -> Result<RetainedProcessHandle, OpenAppError> {
    if !may_start() {
        return Err(OpenAppError::Failed);
    }
    if Instant::now() >= end {
        return Err(OpenAppError::TimedOut);
    }
    match &fresh.kind {
        InstallKind::Shortcut => {
            let expected = file_identity(fresh.file.read_only_handle()).map_err(launch_error)?;
            let child = suspended_process(&fresh.final_path).map_err(launch_error)?;
            if !matches!(child.process().image_mapping(&fresh.file), Ok(ImageMappingReading::SameFile(actual)) if actual == expected)
            {
                return Err(OpenAppError::IdentityMismatch);
            }
            if !matches!(child.process().in_job(), Ok(false)) || !may_target(child.process()) {
                return Err(OpenAppError::Failed);
            }
            if Instant::now() >= end {
                return Err(OpenAppError::TimedOut);
            }
            child.resume().map_err(launch_error)
        }
        InstallKind::Package {
            registration,
            application,
        } => {
            let pid = activate_application(&application.aumid).map_err(launch_error)?;
            let process = retain_image_process(pid).map_err(|_| OpenAppError::IdentityMismatch)?;
            if !package_matches(&process, &registration.full_name, &application.aumid)
                || !may_target(&process)
            {
                return Err(OpenAppError::IdentityMismatch);
            }
            Ok(process)
        }
    }
}

fn package_matches(process: &RetainedProcessHandle, full_name: &str, aumid: &str) -> bool {
    process
        .package_full_name()
        .is_ok_and(|value| value.as_deref() == Some(full_name))
        && process
            .package_fields()
            .is_ok_and(|value| value.is_some_and(|package| package.aumid == aumid))
}

pub(in crate::platform::windows) fn open(
    inventory: &LaunchInventory,
    app: &InstalledApp,
    bounds: OpenAppBounds,
    app_blocked: fn(&LiveIdentity) -> bool,
) -> Result<OpenedApp, OpenAppError> {
    let began = Instant::now();
    let ready = began + bounds.ready_timeout;
    let process_end = ready.min(began + bounds.process_timeout);
    if !may_start() || bounds.activates {
        return Err(OpenAppError::Failed);
    }
    let fresh = inventory
        .fresh(app.clone(), process_end.min(began + IDENTITY_BOUND))
        .ok_or(OpenAppError::Failed)?;
    if matches!(fresh.principal, Principal::Unsigned { .. }) {
        return Err(OpenAppError::Failed);
    }
    let previous: HashSet<_> = desktop_window_numbers()
        .map_err(launch_error)?
        .into_iter()
        .collect();
    let launched = start(&fresh, process_end)?;
    if Instant::now() >= process_end {
        return Err(OpenAppError::TimedOut);
    }
    let started = Instant::now();
    let end = ready.min(started + bounds.window_timeout);
    let mut opened = OpenedApp {
        pid: launched.pid(),
        already_running: false,
        has_window: false,
        frontmost: false,
        process_started_ms: (started - began).as_millis() as u64,
        first_window_ms: None,
    };
    while Instant::now() < end && is_default_desktop() {
        if let Some((owner, number)) =
            launched_window(&fresh, &launched, &previous, app_blocked, end)
        {
            opened.pid = owner.pid();
            opened.has_window = true;
            opened.frontmost = super::foreground_window() == Some(number);
            opened.first_window_ms = Some(began.elapsed().as_millis() as u64);
            return Ok(opened);
        }
        std::thread::sleep(POLL.min(end.saturating_duration_since(Instant::now())));
    }
    Ok(opened)
}

fn launched_window(
    fresh: &Fresh,
    launched: &RetainedProcessHandle,
    previous: &HashSet<u32>,
    app_blocked: fn(&LiveIdentity) -> bool,
    end: Instant,
) -> Option<(RetainedProcessHandle, u32)> {
    let parents: HashMap<_, _> = match fresh.kind {
        InstallKind::Shortcut => process_parents().ok()?.into_iter().collect(),
        _ => HashMap::new(),
    };
    for number in desktop_window_numbers().ok()? {
        if Instant::now() >= end {
            break;
        }
        let observed = (|| {
            let facts = window_identity_facts(number).ok()?;
            eligible_state(&facts).ok()??;
            let pid = frame_target_pid(&facts).ok()?;
            // Only the activation service attests that it returned a running
            // single-instance app. A Win32 stub's exit alone is not a handoff proof.
            if previous.contains(&number)
                && !(matches!(fresh.kind, InstallKind::Package { .. }) && pid == launched.pid())
            {
                return None;
            }
            let owner = retain_image_process(pid).ok()?;
            if !may_target(&owner) {
                return None;
            }
            match &fresh.kind {
                InstallKind::Shortcut if !descendant(&owner, launched, &parents) => return None,
                InstallKind::Package {
                    registration,
                    application,
                } if !package_matches(&owner, &registration.full_name, &application.aumid) => {
                    return None
                }
                _ => (),
            }
            let proof = frame_proof(&owner, pid, number).ok()??;
            let (owner, identity) =
                retained_identity(owner, end.min(Instant::now() + IDENTITY_BOUND)).ok()?;
            if identity.principal != fresh.principal
                || app_blocked(&identity)
                || Instant::now() >= end
            {
                return None;
            }
            let now = window_identity_facts(number).ok()?;
            eligible_state(&now).ok()??;
            (is_default_desktop()
                && may_target(&owner)
                && frame_proof(&owner, pid, number).ok()?? == proof)
                .then_some((owner, number))
        })();
        if observed.is_some() {
            return observed;
        }
    }
    None
}

fn descendant(
    owner: &RetainedProcessHandle,
    root: &RetainedProcessHandle,
    parents: &HashMap<u32, u32>,
) -> bool {
    let Ok((root_start, root_exit)) = root.lifetime_ticks() else {
        return false;
    };
    let Ok((mut start, _)) = owner.lifetime_ticks() else {
        return false;
    };
    let mut pid = owner.pid();
    if pid == root.pid() {
        return start == root_start;
    }
    let mut seen = HashSet::new();
    while seen.insert(pid) {
        let Some(&parent) = parents.get(&pid) else {
            break;
        };
        if parent == root.pid() {
            return lived_before(root_start, root_exit, start);
        }
        let Ok(retained) = retain_image_process(parent) else {
            break;
        };
        let Ok((parent_start, parent_exit)) = retained.lifetime_ticks() else {
            break;
        };
        if parent_start < root_start || !lived_before(parent_start, parent_exit, start) {
            break;
        }
        (pid, start) = (parent, parent_start);
    }
    false
}

fn lived_before(start: u64, exit: Option<u64>, child: u64) -> bool {
    start <= child && exit.is_none_or(|exit| child <= exit)
}

pub(in crate::platform::windows) fn observe_running(
    app: &InstalledApp,
    grant: &ProcessGrant,
    app_blocked: fn(&LiveIdentity) -> bool,
) -> Result<OpenedApp, OpenAppError> {
    let end = Instant::now() + IDENTITY_BOUND;
    let principal = app
        .bundle_identity
        .parse::<Principal>()
        .map_err(|_| OpenAppError::RunningChanged)?;
    if !is_default_desktop() {
        return Err(OpenAppError::RunningChanged);
    }
    let owner = retain_image_process(grant.pid).map_err(|_| OpenAppError::RunningChanged)?;
    let (owner, live) = retained_identity(owner, end).map_err(|_| OpenAppError::RunningChanged)?;
    if !live.matches_grant(grant)
        || live.principal != principal
        || app_blocked(&live)
        || !may_target(&owner)
    {
        return Err(OpenAppError::RunningChanged);
    }
    let mut opened = OpenedApp {
        pid: owner.pid(),
        already_running: true,
        has_window: false,
        frontmost: false,
        process_started_ms: 0,
        first_window_ms: None,
    };
    let foreground = super::foreground_window();
    for number in desktop_window_numbers().map_err(launch_error)? {
        if Instant::now() >= end {
            break;
        }
        if window_identity_facts(number)
            .is_ok_and(|facts| eligible_state(&facts).is_ok_and(|state| state.is_some()))
            && frame_proof(&owner, grant.pid, number).is_ok_and(|proof| proof.is_some())
        {
            opened.has_window = true;
            opened.frontmost |= foreground == Some(number);
        }
    }
    if !owner.process_wait_pending() {
        return Err(OpenAppError::RunningChanged);
    }
    Ok(opened)
}
