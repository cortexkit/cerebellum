//! Windows application state and addressed actions. AppStateSessions assigns the public element IDs.

use crate::app_state::source::*;
use crate::platform::ProcessGrant;
use cerebellum_windows::{
    foreground_window_number, window_identity_facts, with_scoped_uia, AccessibilityReadFailure,
    RetainedProcessHandle, ScopedUia,
};
use std::{
    any::Any,
    collections::{hash_map::DefaultHasher, BTreeMap},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use self::{uia::UiWindow, windows::*};
use super::identity::{
    frame_proof, frame_target_pid, identity_inventory, running_list, FrameProof, LiveIdentity,
    Principal, IDENTITY_BOUND,
};
use super::launch::LaunchInventory;

mod actions;
mod uia;
mod wait;
pub(super) mod windows;
pub use wait::WindowsAppStatePoller;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadError {
    Gone,
    Replaced,
    Permission,
    NotInspectable,
    Deadline,
    Bound,
    Unsupported,
    Unreadable,
}

type ReadResult<T> = Result<T, ReadError>;

impl From<AccessibilityReadFailure> for ReadError {
    fn from(value: AccessibilityReadFailure) -> Self {
        match value {
            AccessibilityReadFailure::TargetGone => Self::Gone,
            AccessibilityReadFailure::TargetReplaced => Self::Replaced,
            AccessibilityReadFailure::PermissionRequired => Self::Permission,
            AccessibilityReadFailure::TargetNotInspectable => Self::NotInspectable,
            AccessibilityReadFailure::RetryableDeadlineExceeded => Self::Deadline,
            AccessibilityReadFailure::TreeExceedsBound => Self::Bound,
            _ => Self::Unreadable,
        }
    }
}

impl From<ReadError> for AppStateReadError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Gone | ReadError::Replaced => Self::TargetGone,
            ReadError::Permission => Self::AccessibilityNotPermitted,
            _ => Self::Unreadable,
        }
    }
}

impl From<ReadError> for ElementReadError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Gone | ReadError::Replaced => Self::Gone,
            _ => Self::Unreadable,
        }
    }
}

impl From<ReadError> for ElementActionError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Gone | ReadError::Replaced => Self::Gone,
            ReadError::Permission | ReadError::NotInspectable => Self::NotPermitted,
            ReadError::Unsupported => Self::Unsupported,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Fingerprint {
    control_type: i32,
    automation_id: String,
    class_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ElementKey {
    pid: u32,
    generation: u64,
    hwnd: u32,
    runtime_id: Vec<i32>,
    fingerprint: Fingerprint,
}

#[derive(Clone, Debug)]
struct Element {
    key: ElementKey,
    proof: FrameProof,
    // A title can change without changing the underlying element.
    name: String,
}

impl ElementToken for Element {
    fn same_element(&self, other: &dyn ElementToken) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.key == other.key && self.proof == other.proof)
    }

    fn identity_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.key.hash(&mut hasher);
        hasher.finish()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn uses_windows_menu_titles(&self) -> bool {
        true
    }
}

fn element_token(handle: &ElementHandle) -> ReadResult<&Element> {
    handle.as_any().downcast_ref().ok_or(ReadError::Gone)
}

fn grant_generation(target: &ProcessGrant) -> ReadResult<u64> {
    target
        .process_generation_evidence
        .parse()
        .map_err(|_| ReadError::Unreadable)
}

fn operation<T: Send + 'static>(
    pid: u32,
    generation: u64,
    end: Instant,
    work: impl FnOnce(&ScopedUia, &RetainedProcessHandle) -> ReadResult<T> + Send + 'static,
) -> ReadResult<T> {
    require_default_desktop()?;
    with_scoped_uia(pid, generation, end, move |uia| {
        let process = retain(pid, generation)?;
        let result = work(uia, &process)?;
        current(&process, generation)?;
        if !is_default_desktop() {
            return Err(ReadError::NotInspectable);
        }
        Ok(result)
    })
}

#[derive(Clone)]
pub struct WindowsAppStateSource {
    cache: Arc<Mutex<WindowCache>>,
    app_blocked: fn(&LiveIdentity) -> bool,
    launch: Option<LaunchInventory>,
}

#[derive(Default)]
struct WindowCache {
    trees: BTreeMap<u32, CachedTree>,
    serial: u64,
}

struct CachedTree {
    pid: u32,
    generation: u64,
    serial: u64,
    root: RawElement,
}

impl WindowCache {
    fn replace(&mut self, pid: u32, generation: u64, roots: &[RawElement]) {
        self.trees.retain(|_, cached| cached.pid != pid);
        self.serial = self.serial.wrapping_add(1);
        for root in roots {
            if let Ok(element) = element_token(&root.handle) {
                self.trees.insert(
                    element.key.hwnd,
                    CachedTree {
                        pid,
                        generation,
                        serial: self.serial,
                        root: root.clone(),
                    },
                );
            }
        }
        while self.trees.len() > 64 {
            let oldest = self
                .trees
                .iter()
                .min_by_key(|(_, entry)| entry.serial)
                .map(|(hwnd, _)| *hwnd);
            if let Some(oldest) = oldest {
                self.trees.remove(&oldest);
            }
        }
    }
}

impl WindowsAppStateSource {
    /// Exclude applications reserved for the operator from running-app listings.
    pub fn new(app_blocked: fn(&LiveIdentity) -> bool) -> Self {
        Self {
            cache: Arc::default(),
            app_blocked,
            launch: None,
        }
    }

    /// Start the inventory verifier after the serving layer admits launch.
    pub fn with_launch_inventory(
        mut self,
        name_blocked: fn(&str) -> bool,
    ) -> std::io::Result<Self> {
        self.launch = Some(LaunchInventory::start(name_blocked)?);
        Ok(self)
    }
    /// Test the same client setup used for reads, without opening an application window.
    pub fn client_available() -> bool {
        with_scoped_uia(
            std::process::id(),
            0,
            Instant::now() + Duration::from_secs(1),
            |_| Ok::<_, AccessibilityReadFailure>(()),
        )
        .is_ok()
    }

    fn with_element<T: Send + 'static>(
        &self,
        element: &ElementHandle,
        end: Instant,
        read: impl FnOnce(&UiWindow<'_>, &cerebellum_windows::UiaElementRef) -> ReadResult<T>
            + Send
            + 'static,
    ) -> ReadResult<T> {
        let element = element_token(element)?.clone();
        let ElementKey {
            pid,
            generation,
            hwnd,
            ..
        } = element.key;
        operation(pid, generation, end, move |uia, process| {
            let window = bound_window(process, pid, hwnd)?.ok_or(ReadError::Gone)?;
            if element.proof != window.proof {
                return Err(ReadError::Gone);
            }
            let scope = UiWindow::new(uia, process, pid, generation, &window)?;
            let found = scope.find(&element.key)?;
            let result = read(&scope, &found)?;
            scope.confirm()?;
            Ok(result)
        })
    }

    fn read_forest(
        &self,
        grant: &ProcessGrant,
        bounds: ReadBounds,
        end: Instant,
        values: bool,
    ) -> ReadResult<RawAppState> {
        let generation = grant_generation(grant)?;
        let pid = grant.pid;
        let raw = operation(pid, generation, end, move |uia, process| {
            let windows = windows(process, pid, end)?;
            let active = values
                .then(|| active_window(&windows).ok().flatten())
                .flatten();
            let mut raw = RawAppState {
                roots: Vec::new(),
                focused: None,
                unreadable_subtrees: windows.unreadable,
                read_bound_reached: false,
            };
            let mut count = bounds.max_elements;
            for window in &windows.eligible {
                let scope = UiWindow::new(uia, process, pid, generation, window);
                let tree = scope.and_then(|scope| {
                    let mut root =
                        scope.tree(scope.root(), bounds.max_depth, &mut count, values)?;
                    let is_active =
                        active.is_some_and(|(active, _)| active.root.number == window.root.number);
                    root.focused_window = is_active;
                    if values && is_active {
                        if let Some((_, info)) = active {
                            raw.focused = scope.focused(info.focus).ok().flatten();
                        }
                    }
                    scope.confirm()?;
                    Ok(root)
                });
                match tree {
                    Ok(root) => {
                        raw.unreadable_subtrees += unreadable_children(&root);
                        raw.roots.push(root);
                    }
                    Err(ReadError::Bound) => {
                        raw.read_bound_reached = true;
                        break;
                    }
                    Err(
                        error @ (ReadError::Deadline
                        | ReadError::Gone
                        | ReadError::Replaced
                        | ReadError::Permission),
                    ) => return Err(error),
                    Err(_) => raw.unreadable_subtrees += 1,
                }
            }
            Ok(raw)
        })?;
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.replace(pid, generation, &raw.roots);
        // The readback is assembled from the entries for this exact observation.
        // A retained element never uses these snapshots as evidence of current facts.
        let roots = raw
            .roots
            .iter()
            .filter_map(|root| {
                let hwnd = element_token(&root.handle).ok()?.key.hwnd;
                cache
                    .trees
                    .get(&hwnd)
                    .filter(|entry| entry.generation == generation)
                    .map(|entry| entry.root.clone())
                    .or_else(|| Some(root.clone()))
            })
            .collect();
        Ok(RawAppState { roots, ..raw })
    }
}

fn unreadable_children(root: &RawElement) -> usize {
    root.unreadable_children + root.children.iter().map(unreadable_children).sum::<usize>()
}

fn focused_mark(
    target: &ProcessGrant,
    read_focus: bool,
    end: Instant,
) -> ReadResult<Option<(WindowMark, Option<ElementHandle>)>> {
    let (pid, generation) = (target.pid, grant_generation(target)?);
    operation(pid, generation, end, move |uia, process| {
        let windows = windows(process, pid, end)?;
        let Some((active, info)) = active_window(&windows)? else {
            return Ok(None);
        };
        let ui = UiWindow::new(uia, process, pid, generation, active)?;
        let mark = WindowMark {
            handle: ui.node(ui.root())?.handle(),
            title: Some(active.root.title.clone()).filter(|title| !title.is_empty()),
        };
        let focus = if read_focus {
            ui.focused(info.focus)?
        } else {
            None
        };
        let now = active_window(&windows)?;
        if !now.is_some_and(|(window, current)| {
            window.root.number == active.root.number && current == info
        }) {
            return Err(ReadError::Unreadable);
        }
        ui.confirm()?;
        Ok(Some((mark, focus)))
    })
}

fn bound_hit(
    pid: u32,
    generation: u64,
    point: (f64, f64),
) -> ReadResult<Option<(ElementHandle, Option<u32>)>> {
    let end = Instant::now() + ReadBounds::default().timeout;
    operation(pid, generation, end, move |uia, process| {
        let windows = windows(process, pid, end)?;
        if windows.unreadable != 0 {
            return Err(ReadError::Unreadable);
        }
        let candidates: BTreeMap<_, _> = windows
            .eligible
            .iter()
            .filter(|window| contains(window.state.bounds, point))
            .map(|window| (window.root.number, window))
            .collect();
        if candidates.is_empty() {
            return Ok(None);
        }
        let order = cerebellum_windows::desktop_z_order().map_err(|_| ReadError::Unreadable)?;
        let mut ordered = order.iter().filter_map(|id| candidates.get(id));
        let window = ordered.next().ok_or(ReadError::Unreadable)?;
        if ordered.count() + 1 != candidates.len() {
            return Err(ReadError::Unreadable);
        }
        let ui = UiWindow::new(uia, process, pid, generation, window)?;
        let result = ui.hit(point)?;
        ui.confirm()?;
        Ok(result.map(|element| (element, Some(pid))))
    })
}

fn read_foreground_pid() -> Option<u32> {
    if !is_default_desktop() {
        return None;
    }
    let hwnd = foreground_window_number()?;
    let root = window_identity_facts(hwnd).ok()?;
    let pid = frame_target_pid(&root).ok()?;
    let process = cerebellum_windows::retain_image_process(pid).ok()?;
    frame_proof(&process, pid, hwnd).ok().flatten()?;
    (foreground_window_number()? == hwnd).then_some(pid)
}

impl AppStateSource for WindowsAppStateSource {
    fn read_app_state(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        Ok(self.read_forest(target, bounds, Instant::now() + bounds.timeout, true)?)
    }

    fn read_element_state(
        &self,
        target: &ProcessGrant,
        element: &ElementHandle,
        bounds: ReadBounds,
        _expand_menus: bool,
    ) -> Result<RawAppState, ElementReadError> {
        let token = element_token(element)?;
        if token.key.pid != target.pid || token.key.generation != grant_generation(target)? {
            return Err(ElementReadError::Gone);
        }
        let root = self.with_element(
            element,
            Instant::now() + bounds.timeout,
            move |scope, found| {
                let mut remaining = bounds.max_elements;
                scope.tree(found, bounds.max_depth, &mut remaining, true)
            },
        )?;
        Ok(RawAppState {
            unreadable_subtrees: unreadable_children(&root),
            roots: vec![root],
            focused: None,
            read_bound_reached: false,
        })
    }

    fn element_facts(&self, element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        Ok(self.with_element(element, read_deadline(), |ui, found| ui.facts(found))?)
    }

    fn element_parent(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Ok(self.with_element(element, read_deadline(), |ui, found| ui.parent(found))?)
    }

    fn element_enabled(&self, element: &ElementHandle) -> Option<bool> {
        self.with_element(element, read_deadline(), |ui, found| ui.enabled(found))
            .ok()
    }

    fn press(&self, element: &ElementHandle) -> Result<(), ElementActionError> {
        let key = element_token(element)?.key.clone();
        self.with_element(element, read_deadline(), move |ui, found| {
            ui.press(found, &key)
        })
        .map_err(actions::mutation_error)
    }

    fn write_text(
        &self,
        element: &ElementHandle,
        attribute: TextAttribute,
        text: &str,
    ) -> Result<(), ElementActionError> {
        if !matches!(attribute, TextAttribute::Value) {
            return Err(ElementActionError::Unsupported);
        }
        let text = text.to_owned();
        let key = element_token(element)?.key.clone();
        self.with_element(element, read_deadline(), move |ui, _| {
            ui.set_value(&key, &text)
        })
        .map_err(actions::mutation_error)
    }

    fn focused_window(
        &self,
        target: &ProcessGrant,
    ) -> Result<Option<WindowMark>, ElementActionError> {
        Ok(focused_mark(target, false, read_deadline())?.map(|(window, _)| window))
    }

    fn focused_element(
        &self,
        target: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Ok(focused_mark(target, true, read_deadline())?.and_then(|(_, focus)| focus))
    }

    fn text_value(&self, element: &ElementHandle) -> Result<Option<String>, ElementActionError> {
        Ok(self.with_element(element, read_deadline(), |ui, found| ui.value(found))?)
    }

    fn selected_range(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<(usize, usize)>, ElementActionError> {
        Ok(self.with_element(element, read_deadline(), |ui, found| {
            ui.selected_range(found)
        })?)
    }

    fn element_at(
        &self,
        scope: HitScope,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        let HitScope::Application { pid } = scope else {
            return Err(ElementActionError::UnsupportedOnPlatform);
        };
        let generation = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .trees
            .values()
            .find(|tree| tree.pid == pid)
            .map(|tree| tree.generation)
            .ok_or(ElementActionError::Gone)?;
        Ok(bound_hit(pid, generation, point)?)
    }

    fn element_at_for_target(
        &self,
        target: &ProcessGrant,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        Ok(bound_hit(target.pid, grant_generation(target)?, point)?)
    }

    fn visible_window_numbers(&self, target: &ProcessGrant) -> Option<Vec<u32>> {
        let generation = grant_generation(target).ok()?;
        let pid = target.pid;
        let end = read_deadline();
        operation(pid, generation, end, move |_, process| {
            let reading = windows(process, pid, end)?;
            if reading.unreadable != 0 {
                return Err(ReadError::Unreadable);
            }
            Ok(reading
                .eligible
                .into_iter()
                .map(|window| window.root.number)
                .collect())
        })
        .ok()
    }

    fn window_frame(&self, target: &ProcessGrant, window: u32) -> Option<[f64; 4]> {
        let pid = target.pid;
        operation(
            pid,
            grant_generation(target).ok()?,
            read_deadline(),
            move |_, process| {
                let window = bound_window(process, pid, window)?.ok_or(ReadError::Gone)?;
                Ok(frame(window.state.bounds))
            },
        )
        .ok()
    }

    fn element_window_number(&self, element: &ElementHandle) -> Option<u32> {
        let hwnd = element_token(element).ok()?.key.hwnd;
        self.with_element(element, read_deadline(), move |_, _| Ok(hwnd))
            .ok()
    }

    fn frontmost_pid(&self) -> Option<u32> {
        read_foreground_pid()
    }

    fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
        let inventory = running_list(Instant::now() + IDENTITY_BOUND)
            .map_err(|_| AppStateReadError::Unreadable)?;
        Ok(inventory
            .into_iter()
            .filter(|(_, identity, _)| !(self.app_blocked)(identity))
            .map(|(pid, identity, frontmost)| RunningApp {
                name: identity.display_name,
                bundle_identity: identity.principal.to_string(),
                pid,
                frontmost,
            })
            .collect())
    }

    fn running_app_instances(
        &self,
        bundle: &str,
    ) -> Result<Vec<RunningAppInstance>, AppStateReadError> {
        let principal = bundle
            .parse::<Principal>()
            .map_err(|_| AppStateReadError::Unreadable)?;
        let inventory = identity_inventory(Instant::now() + IDENTITY_BOUND)
            .map_err(|_| AppStateReadError::Unreadable)?;
        Ok(inventory
            .apps
            .into_iter()
            .filter(|app| app.identity.principal == principal && !(self.app_blocked)(&app.identity))
            .map(|app| RunningAppInstance {
                process: app.identity.grant(app.pid),
                executable_path: app.identity.image_path,
            })
            .collect())
    }

    fn installed_apps(&self, timeout: Duration) -> InstalledApps {
        self.launch
            .as_ref()
            .map(|launch| launch.listed(timeout))
            .unwrap_or_default()
    }

    fn bundle_signature(&self, app: &InstalledApp) -> Result<BundleSignature, AppStateReadError> {
        self.launch
            .as_ref()
            .ok_or(AppStateReadError::UnsupportedOnPlatform)?
            .signature(app)
    }

    fn bundle_satisfies(&self, app: &InstalledApp, requirement: &str) -> bool {
        self.bundle_signature(app)
            .is_ok_and(|facts| facts.designated_requirement.as_deref() == Some(requirement))
    }

    fn open_app(
        &self,
        app: &InstalledApp,
        bounds: OpenAppBounds,
    ) -> Result<OpenedApp, OpenAppError> {
        super::launch::open(
            self.launch.as_ref().ok_or(OpenAppError::Failed)?,
            app,
            bounds,
            self.app_blocked,
        )
    }

    fn opened_running_app(
        &self,
        app: &InstalledApp,
        grant: &ProcessGrant,
    ) -> Result<OpenedApp, OpenAppError> {
        self.bundle_signature(app)
            .map_err(|_| OpenAppError::RunningChanged)?;
        super::launch::observe_running(app, grant, self.app_blocked)
    }
}

fn read_deadline() -> Instant {
    Instant::now() + ReadBounds::default().timeout
}
