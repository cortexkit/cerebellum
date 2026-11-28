//! Grant-bound XComposite pictures. Pixels never come from the root image.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cerebellum_linux::x11::{self, Connection, Reading, Rect, WindowFacts};

use crate::app_state::image::{ImageDecision, ImageUnavailable as Missing, WindowImageCapture};
use crate::capture::{
    AcquisitionFence, BackendError, BackendTeardownProgress, BroadDisplayCaptureRequest,
    CaptureArtifact, CaptureBackend, DesktopIndependentWindowFilter, EnumeratedWindow,
    PendingVisionWindowFrame, VisionWindowFrame, WindowCaptureFrame, WindowCaptureRequest,
    WindowChange, FENCE_CLOSED,
};
use crate::platform::{PermissionLiveness, ProcessGrant};

const REPAINT_LIMIT: Duration = Duration::from_millis(200);
const MAX_REGION_PARTS: usize = 4096;
const MAX_WINDOW_ANCESTORS: usize = 64;
const MAX_PENDING_EVENTS: usize = 4096;

/// One connection per session epoch. The picture lane owns its event queue
/// while it tracks DestroyNotify and client Damage. It does not own the seat.
pub struct Desktop {
    pub connection: Connection,
    picture_lane: Mutex<()>,
}

impl Desktop {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            picture_lane: Mutex::new(()),
        }
    }

    pub fn active_pid(&self) -> Option<u32> {
        let id = self.connection.active_window().ok()??;
        eligible_pid(&self.connection, id).ok()?
    }

    pub fn window_owner_pids(&self) -> Result<BTreeSet<u32>, x11::Error> {
        let mut pids = BTreeSet::new();
        for id in self.connection.client_stack()? {
            match eligible_pid(&self.connection, id) {
                Ok(Some(pid)) => {
                    pids.insert(pid);
                }
                Ok(None) | Err(x11::Error::WindowGone) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(pids)
    }
}

fn eligible_pid(x: &Connection, window: u32) -> Result<Option<u32>, x11::Error> {
    let facts = x.facts(window)?;
    if facts.input_output && !facts.override_redirect {
        x.owner_pid(window)
    } else {
        Ok(None)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Selection {
    client: u32,
    chain: Vec<u32>,
    frame_facts: WindowFacts,
    client_facts: WindowFacts,
    root_frame: Rect,
    crop: Rect,
}

impl Selection {
    fn top(&self) -> u32 {
        *self
            .chain
            .last()
            .expect("the target is in its own ancestry")
    }

    fn select(x: &Connection, pid: u32, fence: &AcquisitionFence) -> Result<Self, BackendError> {
        for client in x.client_stack()?.into_iter().rev() {
            check_fence(fence)?;
            match eligible_pid(x, client) {
                Ok(Some(owner)) if owner == pid => return Self::read(x, pid, client),
                Ok(_) | Err(x11::Error::WindowGone) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(missing(Missing::NoWindowCaptured))
    }

    fn read(x: &Connection, pid: u32, client: u32) -> Result<Self, BackendError> {
        let client_facts = x.facts(client).map_err(|error| match error {
            x11::Error::WindowGone => missing(Missing::WindowNotMapped),
            other => other.into(),
        })?;
        if !client_facts.input_output
            || client_facts.override_redirect
            || x.owner_pid(client)? != Some(pid)
        {
            return Err(missing(Missing::PictureUnattributable));
        }
        if !client_facts.viewable {
            return Err(missing(Missing::WindowNotMapped));
        }
        let mut chain = vec![client];
        loop {
            let &id = chain.last().expect("the target is in its own ancestry");
            let tree = x.tree(id)?;
            if tree.root != x.root() || tree.parent == 0 || chain.contains(&tree.parent) {
                return Err(missing(Missing::PictureUnattributable));
            }
            if tree.parent == tree.root {
                break;
            }
            if chain.len() == MAX_WINDOW_ANCESTORS {
                return Err(missing(Missing::PictureUnattributable));
            }
            chain.push(tree.parent);
        }
        let top = *chain.last().expect("the target is in its own ancestry");
        let frame_facts = if top == client {
            client_facts
        } else {
            x.facts(top)?
        };
        if !frame_facts.viewable {
            return Err(missing(Missing::WindowNotMapped));
        }
        let (root_x, root_y) = x.translate(client, x.root())?;
        let (client_x, client_y) = x.translate(client, top)?;
        let client_rect = Rect {
            x: root_x,
            y: root_y,
            ..client_facts.rect
        };
        let crop = Rect {
            x: client_x + i32::from(frame_facts.border),
            y: client_y + i32::from(frame_facts.border),
            ..client_facts.rect
        };
        Ok(Self {
            client,
            chain,
            frame_facts,
            client_facts,
            root_frame: client_rect,
            crop,
        })
    }

    fn verify(&self, x: &Connection, pid: u32) -> Result<(), BackendError> {
        if Self::read(x, pid, self.client)? != *self {
            return Err(missing(Missing::PictureUnattributable));
        }
        Ok(())
    }
}

fn missing(reason: Missing) -> BackendError {
    BackendError::LinuxImage(reason)
}

impl From<x11::Error> for BackendError {
    fn from(error: x11::Error) -> Self {
        missing(match error {
            x11::Error::Connection => Missing::BackendUnavailable,
            x11::Error::WindowGone | x11::Error::Unreadable => Missing::PictureUnattributable,
        })
    }
}

pub fn unavailable(error: BackendError) -> Missing {
    match error {
        BackendError::LinuxImage(reason) => reason,
        BackendError::UnsupportedOnPlatform => Missing::BackendUnavailable,
        _ => Missing::CaptureFailed,
    }
}

fn check_fence(fence: &AcquisitionFence) -> Result<(), BackendError> {
    if fence() {
        Ok(())
    } else {
        Err(BackendError::Capture(FENCE_CLOSED.into()))
    }
}

/// Edges use wide signed coordinates so X11 borders and translated positions
/// can be intersected without wrapping or truncation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Area {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl From<Rect> for Area {
    fn from(r: Rect) -> Self {
        Self {
            left: r.x,
            top: r.y,
            right: r.x + i32::from(r.width),
            bottom: r.y + i32::from(r.height),
        }
    }
}

impl Area {
    fn nonempty(self) -> Option<Self> {
        (self.left < self.right && self.top < self.bottom).then_some(self)
    }

    fn intersect(self, other: Self) -> Option<Self> {
        Self {
            left: self.left.max(other.left),
            top: self.top.max(other.top),
            right: self.right.min(other.right),
            bottom: self.bottom.min(other.bottom),
        }
        .nonempty()
    }

    fn subtract(self, cut: Self) -> impl Iterator<Item = Self> {
        let parts = if let Some(hit) = self.intersect(cut) {
            [
                Self {
                    bottom: hit.top,
                    ..self
                }
                .nonempty(),
                Self {
                    top: hit.bottom,
                    ..self
                }
                .nonempty(),
                Self {
                    right: hit.left,
                    bottom: hit.bottom,
                    top: hit.top,
                    ..self
                }
                .nonempty(),
                Self {
                    left: hit.right,
                    bottom: hit.bottom,
                    top: hit.top,
                    ..self
                }
                .nonempty(),
            ]
        } else {
            [Some(self), None, None, None]
        };
        parts.into_iter().flatten()
    }

    fn translated(self, x: i32, y: i32) -> Self {
        Self {
            left: self.left + x,
            right: self.right + x,
            top: self.top + y,
            bottom: self.bottom + y,
        }
    }
}

fn subtract_from(region: &mut Vec<Area>, cut: Area) -> Result<(), BackendError> {
    let mut remaining = Vec::new();
    for part in region.iter().flat_map(|part| part.subtract(cut)) {
        if remaining.len() == MAX_REGION_PARTS {
            return Err(missing(Missing::WindowCoveredMayBeStale));
        }
        remaining.push(part);
    }
    *region = remaining;
    Ok(())
}

fn shape_areas(
    x: &Connection,
    window: u32,
    facts: WindowFacts,
    clip: bool,
) -> Result<Vec<Area>, BackendError> {
    let border = if clip { 0 } else { i32::from(facts.border) };
    let full = Area {
        left: -border,
        top: -border,
        right: i32::from(facts.rect.width) + border,
        bottom: i32::from(facts.rect.height) + border,
    };
    Ok(match x.shape(window, clip)? {
        None => vec![full],
        Some(rectangles) => rectangles
            .into_iter()
            .filter_map(|r| full.intersect(r.into()))
            .collect(),
    })
}

fn covered(
    x: &Connection,
    selected: &Selection,
    fence: &AcquisitionFence,
) -> Result<Vec<Area>, BackendError> {
    let client = Area::from(selected.root_frame);
    let mut parts: Vec<_> = client.subtract(x.root_bounds()?.into()).collect();
    let stack = x.tree(x.root())?.children;
    let position = stack
        .iter()
        .position(|&id| id == selected.top())
        .ok_or_else(|| missing(Missing::PictureUnattributable))?;
    for &id in &stack[position + 1..] {
        check_fence(fence)?;
        let facts = x.facts(id)?;
        if !facts.input_output || !facts.viewable {
            continue;
        }
        let (rx, ry) = x.translate(id, x.root())?;
        let border = i32::from(facts.border);
        let outer = Area {
            left: rx - border,
            top: ry - border,
            right: rx + i32::from(facts.rect.width) + border,
            bottom: ry + i32::from(facts.rect.height) + border,
        };
        if outer.intersect(client).is_none() {
            continue;
        }
        for overlap in shape_areas(x, id, facts, false)?
            .into_iter()
            .filter_map(|part| client.intersect(part.translated(rx, ry)))
        {
            if parts.len() == MAX_REGION_PARTS {
                return Err(missing(Missing::WindowCoveredMayBeStale));
            }
            parts.push(overlap);
        }
    }
    // XDamage's areas are relative to the client, not to the WM's frame.
    Ok(parts
        .into_iter()
        .map(|a| a.translated(-selected.root_frame.x, -selected.root_frame.y))
        .collect())
}

fn reject_change(event: &Reading, chain: &[u32]) -> Result<(), BackendError> {
    match event {
        Reading::Destroyed(id) if chain.contains(id) => Err(missing(Missing::WindowNotMapped)),
        Reading::Destroyed(_) | Reading::StructureChanged => {
            Err(missing(Missing::PictureUnattributable))
        }
        _ => Ok(()),
    }
}

fn drain(x: &Connection, watching: Option<&[u32]>) -> Result<(), BackendError> {
    for _ in 0..MAX_PENDING_EVENTS {
        let Some(event) = x.poll_event()? else {
            return Ok(());
        };
        if let Some(chain) = watching {
            reject_change(&event, chain)?;
        }
    }
    Err(missing(Missing::PictureUnattributable))
}

fn wait_repaint(
    x: &Connection,
    selected: &Selection,
    mut missing_area: Vec<Area>,
    damage: u32,
    redirected: u64,
    end: Instant,
    fence: &AcquisitionFence,
) -> Result<(), BackendError> {
    while !missing_area.is_empty() {
        check_fence(fence)?;
        if Instant::now() >= end {
            return Err(missing(Missing::WindowCoveredMayBeStale));
        }
        let Some(event) = x.poll_event()? else {
            std::thread::sleep(
                Duration::from_millis(2).min(end.saturating_duration_since(Instant::now())),
            );
            continue;
        };
        reject_change(&event, &selected.chain)?;
        if let Reading::Damaged {
            sequence,
            damage: id,
            drawable,
            rect,
        } = event
        {
            if id == damage && drawable == selected.client && sequence >= redirected {
                subtract_from(&mut missing_area, rect.into())?;
            }
        }
    }
    Ok(())
}

/// Optional portion of a read_state call. A refusing instance always carries
/// the reason for withholding its image; it never tries another backend.
pub struct Backend {
    desktop: Result<Arc<Desktop>, Missing>,
    verify: Box<Verification>,
    selected: Option<Selection>,
    acquired: Option<(u32, Rect)>,
    decision: ImageDecision,
}

impl Backend {
    pub fn new(
        desktop: Result<Arc<Desktop>, Missing>,
        verify: impl Fn(&ProcessGrant) -> Result<(), &'static str> + Send + 'static,
    ) -> Self {
        Self {
            desktop,
            verify: Box::new(verify),
            selected: None,
            acquired: None,
            decision: ImageDecision::Unknown,
        }
    }

    pub fn can_capture(&self) -> bool {
        self.desktop.is_ok()
    }

    pub fn decision(&self) -> ImageDecision {
        self.decision
    }

    pub fn select_and_acquire(
        &mut self,
        target: &ProcessGrant,
        now_ms: u64,
        fence: &AcquisitionFence,
    ) -> Result<PendingVisionWindowFrame, BackendError> {
        self.acquired = None;
        let desktop = self.desktop.as_ref().map_err(|&reason| missing(reason))?;
        check_fence(fence)?;
        (self.verify)(target).map_err(verify_error)?;
        let selected = Selection::select(&desktop.connection, target.pid, fence)?;
        let filter = DesktopIndependentWindowFilter::new(selected.client.to_string());
        self.selected = Some(selected);
        self.capture_window_unencoded_for_vision_fenced(
            &WindowCaptureRequest {
                target: target.clone(),
                filter,
                captured_at_ms: now_ms,
                region: None,
            },
            fence,
        )
    }

    pub fn finish(
        &mut self,
        pending: PendingVisionWindowFrame,
    ) -> Result<WindowImageCapture, Missing> {
        let (client, rect) = self.acquired.take().ok_or(Missing::CaptureFailed)?;
        let frame = self
            .encode_window_for_vision(pending)
            .map_err(unavailable)?;
        Ok(WindowImageCapture {
            window_id: client.to_string(),
            owning_pid: frame.owner_identity.pid,
            window_origin: (f64::from(rect.x), f64::from(rect.y)),
            window_points: (f64::from(rect.width), f64::from(rect.height)),
            captured_px: (frame.captured_width_px, frame.captured_height_px),
            exact_axes: true,
            jpeg: frame.jpeg,
        })
    }
}

fn verify_error(reason: &'static str) -> BackendError {
    missing(match reason {
        "no_supported_session" | "backend_unavailable" => Missing::BackendUnavailable,
        _ => Missing::PictureUnattributable,
    })
}

type Verification = dyn Fn(&ProcessGrant) -> Result<(), &'static str> + Send;

struct Acquisition<'a> {
    desktop: &'a Desktop,
    selection: Selection,
    target: &'a ProcessGrant,
    verify: &'a Verification,
    fence: &'a AcquisitionFence,
}

impl Acquisition<'_> {
    fn read(self) -> Result<(Vec<u8>, ImageDecision), BackendError> {
        let x = &self.desktop.connection;
        let _lane = self
            .desktop
            .picture_lane
            .try_lock()
            .map_err(|_| missing(Missing::BackendUnavailable))?;
        let selected = &self.selection;
        let fence = self.fence;
        drain(x, None)?;
        let _watches: Vec<_> = selected
            .chain
            .iter()
            .map(|&id| x.watch(id))
            .collect::<Result<_, _>>()?;
        selected.verify(x, self.target.pid)?;
        let manager = x.compositor()?;
        let mut decision = ImageDecision::Unknown;
        let (_damage, _redirect, cover) = if manager.is_none() {
            let before = covered(x, selected, fence)?;
            check_fence(fence)?;
            let damage = x.damage(selected.client)?;
            let redirect = x.redirect_automatic(selected.top())?;
            let end = Instant::now() + REPAINT_LIMIT;
            if !before.is_empty() {
                decision = ImageDecision::CoveredByWindow;
                // The server itself damages the client while it initializes
                // the redirected backing store, including during the round
                // trip that checks RedirectWindow. Start counting only at
                // a subsequent round trip, not at the redirect's sequence.
                let redirected = x.sync_sequence()?;
                wait_repaint(
                    x,
                    selected,
                    before.clone(),
                    damage.id(),
                    redirected,
                    end,
                    fence,
                )?;
            } else {
                decision = ImageDecision::FullyVisible;
            }
            (Some(damage), Some(redirect), before)
        } else {
            (None, None, Vec::new())
        };
        // Verify the process and geometry again after the repaint wait. Hold
        // the pixmap's own reference across GetImage; a changed window must
        // not replace the drawable that was checked.
        (self.verify)(self.target).map_err(verify_error)?;
        selected.verify(x, self.target.pid)?;
        if x.compositor()? != manager {
            return Err(missing(Missing::PictureUnattributable));
        }
        if manager.is_none() && covered(x, selected, fence)? != cover {
            return Err(missing(Missing::WindowCoveredMayBeStale));
        }
        let mut watched = BTreeSet::from_iter(selected.chain.iter().copied());
        let mut watches = Vec::new();
        check_client_pixels(x, selected, self.target.pid, fence, |id| {
            if watched.insert(id) {
                watches.push(x.watch(id)?);
            }
            Ok(())
        })?;
        let pixmap = x.name_pixmap(selected.top())?;
        let image = pixmap.prepare(selected.crop, selected.frame_facts)?;
        drain(x, Some(&selected.chain))?;
        let bgra = fenced_read(fence, || image.read().map_err(Into::into))?;
        drain(x, Some(&selected.chain))?;
        selected.verify(x, self.target.pid)?;
        check_client_pixels(x, selected, self.target.pid, fence, |id| {
            if !watched.contains(&id) {
                return Err(missing(Missing::PictureUnattributable));
            }
            Ok(())
        })?;
        if x.compositor()? != manager {
            return Err(missing(Missing::PictureUnattributable));
        }
        drain(x, Some(&selected.chain))?;
        // Discard already-read bytes if cancellation, a session swap or a
        // change to the bound window ended the authority to return them.
        (self.verify)(self.target).map_err(verify_error)?;
        check_fence(fence)?;
        Ok((bgra, decision))
    }
}

fn fenced_read<T>(
    fence: &AcquisitionFence,
    read: impl FnOnce() -> Result<T, BackendError>,
) -> Result<T, BackendError> {
    check_fence(fence)?;
    read()
}

/// Composite's top-level pixmap includes its descendants. A crop must not
/// include frame pixels outside the client shape or pixels painted by a
/// sibling or a foreign embedded child.
fn check_client_pixels(
    x: &Connection,
    selected: &Selection,
    pid: u32,
    fence: &AcquisitionFence,
    mut watch: impl FnMut(u32) -> Result<(), BackendError>,
) -> Result<(), BackendError> {
    let client = Area::from(selected.root_frame);
    verify_shape(x, selected.client, selected.client_facts, client)?;
    for pair in selected.chain.windows(2) {
        let [child, parent] = pair else {
            unreachable!()
        };
        let parent_facts = x.facts(*parent)?;
        verify_shape(x, *parent, parent_facts, client)?;
        let children = x.tree(*parent)?.children;
        let index = children
            .iter()
            .position(|id| id == child)
            .ok_or_else(|| missing(Missing::PictureUnattributable))?;
        for &sibling in &children[index + 1..] {
            check_fence(fence)?;
            watch(sibling)?;
            if intersects_client(x, sibling, client)? {
                return Err(missing(Missing::PictureUnattributable));
            }
        }
    }
    let mut descendants = x.tree(selected.client)?.children;
    let mut seen = 0;
    while let Some(window) = descendants.pop() {
        seen += 1;
        if seen + descendants.len() > MAX_REGION_PARTS {
            return Err(missing(Missing::PictureUnattributable));
        }
        check_fence(fence)?;
        watch(window)?;
        if intersects_client(x, window, client)? {
            if x.owner_pid(window)? != Some(pid) {
                return Err(missing(Missing::PictureUnattributable));
            }
            descendants.extend(x.tree(window)?.children);
        }
    }
    Ok(())
}

fn verify_shape(
    x: &Connection,
    window: u32,
    facts: WindowFacts,
    client: Area,
) -> Result<(), BackendError> {
    let (rx, ry) = x.translate(window, x.root())?;
    for clip in [false, true] {
        let mut outside = vec![client];
        for part in shape_areas(x, window, facts, clip)? {
            subtract_from(&mut outside, part.translated(rx, ry))?;
        }
        if !outside.is_empty() {
            return Err(missing(Missing::PictureUnattributable));
        }
    }
    Ok(())
}

fn intersects_client(x: &Connection, window: u32, client: Area) -> Result<bool, BackendError> {
    let facts = x.facts(window)?;
    if !facts.viewable || !facts.input_output {
        return Ok(false);
    }
    let (rx, ry) = x.translate(window, x.root())?;
    Ok(shape_areas(x, window, facts, false)?
        .into_iter()
        .any(|area| client.intersect(area.translated(rx, ry)).is_some()))
}

impl CaptureBackend for Backend {
    fn screen_recording_liveness(&self) -> PermissionLiveness {
        if self.can_capture() {
            PermissionLiveness::Live
        } else {
            PermissionLiveness::Unavailable
        }
    }

    fn capture_window_unencoded_for_vision_fenced(
        &mut self,
        request: &WindowCaptureRequest,
        fence: &AcquisitionFence,
    ) -> Result<PendingVisionWindowFrame, BackendError> {
        self.acquired = None;
        self.decision = ImageDecision::Unknown;
        let desktop = self.desktop.as_ref().map_err(|&reason| missing(reason))?;
        let client = request
            .filter
            .window_id
            .parse()
            .map_err(|_| missing(Missing::PictureUnattributable))?;
        if request.filter.include_cursor || request.region.is_some() {
            return Err(BackendError::UnsupportedOnPlatform);
        }
        let selected = match self.selected.take() {
            Some(selected) if selected.client == client => selected,
            Some(_) => return Err(missing(Missing::PictureUnattributable)),
            None => Selection::read(&desktop.connection, request.target.pid, client)?,
        };
        let rect = selected.root_frame;
        let (bgra, decision) = Acquisition {
            desktop,
            selection: selected,
            target: &request.target,
            verify: &self.verify,
            fence,
        }
        .read()?;
        self.acquired = Some((client, rect));
        self.decision = decision;
        Ok(PendingVisionWindowFrame {
            frame: VisionWindowFrame {
                owner_identity: request.target.clone(),
                owner_identity_verified: true,
                captured_width_px: rect.width.into(),
                captured_height_px: rect.height.into(),
                jpeg: Vec::new(),
                captured_at_ms: request.captured_at_ms,
            },
            bgra: Some(bgra),
        })
    }

    fn encode_window_for_vision(
        &mut self,
        pending: PendingVisionWindowFrame,
    ) -> Result<VisionWindowFrame, BackendError> {
        let mut frame = pending.frame;
        let source = (frame.captured_width_px, frame.captured_height_px);
        let dest = cerebellum_core::vision::fit_within_vision_limits(source.0, source.1)
            .ok_or_else(|| missing(Missing::ImageNotScalable))?;
        let bgra = pending
            .bgra
            .ok_or_else(|| missing(Missing::CaptureFailed))?;
        frame.jpeg = x11::encode_bgra_jpeg(&bgra, source, dest)
            .map_err(|_| missing(Missing::CaptureFailed))?;
        Ok(frame)
    }

    fn enumerate_windows(
        &mut self,
        _: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn poll_window_change(
        &mut self,
        _: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn capture_window(
        &mut self,
        _: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn capture_display(
        &mut self,
        _: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError> {
        Ok(BackendTeardownProgress::Complete)
    }

    fn poll_teardown(&mut self, _: u64) -> Result<BackendTeardownProgress, BackendError> {
        Ok(BackendTeardownProgress::Complete)
    }
}
