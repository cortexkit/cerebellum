//! Raw readings and scoped resource requests for a local X11 connection.
//!
//! The caller owns window selection, pixel attribution, freshness, and the
//! acquisition fence. This module never falls back to reading the root image.

use std::fs::OpenOptions;
use std::io::{self, IoSlice, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::errors::{ReplyError, ReplyOrIdError};
use x11rb::protocol::composite::{self, ConnectionExt as _};
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::res::{self, ConnectionExt as _};
use x11rb::protocol::shape::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{self, ConnectionExt as _};
use x11rb::protocol::{ErrorKind, Event};
use x11rb::reexports::x11rb_protocol::xauth::Family;
use x11rb::rust_connection::{DefaultStream, PollMode, RustConnection, Stream};
use x11rb::utils::RawFdContainer;

const MAX_PROPERTY_WINDOWS: u32 = 4096;
const MAX_CAPTURE_PIXELS: u32 = 16 * 1024 * 1024;
const IO_LIMIT: Duration = Duration::from_millis(75);
const MIT_COOKIE: &[u8] = b"MIT-MAGIC-COOKIE-1";

#[cfg(feature = "x11-test-support")]
pub mod fixture;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Connection,
    WindowGone,
    Unreadable,
}

impl From<x11rb::errors::ConnectionError> for Error {
    fn from(_: x11rb::errors::ConnectionError) -> Self {
        Self::Connection
    }
}

impl From<ReplyError> for Error {
    fn from(error: ReplyError) -> Self {
        match error {
            ReplyError::X11Error(e) if e.error_kind == ErrorKind::Window => Self::WindowGone,
            ReplyError::X11Error(_) => Self::Unreadable,
            ReplyError::ConnectionError(_) => Self::Connection,
        }
    }
}

impl From<ReplyOrIdError> for Error {
    fn from(error: ReplyOrIdError) -> Self {
        match error {
            ReplyOrIdError::ConnectionError(_) => Self::Connection,
            _ => Self::Unreadable,
        }
    }
}

struct BoundedStream(DefaultStream);

impl Stream for BoundedStream {
    fn poll(&self, mode: PollMode) -> io::Result<()> {
        let deadline = Instant::now() + IO_LIMIT;
        let mut fd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: (if mode.readable() { libc::POLLIN } else { 0 })
                | (if mode.writable() { libc::POLLOUT } else { 0 }),
            revents: 0,
        };
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            // SAFETY: `fd` is a live, initialized one-member poll array. The
            // stream owns its descriptor for at least the duration of poll.
            let n = unsafe { libc::poll(&mut fd, 1, left.as_millis() as libc::c_int) };
            if n > 0 {
                return Ok(());
            }
            if n == 0 || left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn read(&self, buf: &mut [u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        self.0.read(buf, fds)
    }

    fn write(&self, buf: &[u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        self.0.write(buf, fds)
    }

    fn write_vectored(
        &self,
        buf: &[IoSlice<'_>],
        fds: &mut Vec<RawFdContainer>,
    ) -> io::Result<usize> {
        self.0.write_vectored(buf, fds)
    }
}

fn local_display(display: &str) -> Result<(u16, usize), Error> {
    let display = display
        .strip_prefix(':')
        .or_else(|| display.strip_prefix("unix/:"))
        .or_else(|| display.strip_prefix("unix:"))
        .ok_or(Error::Connection)?;
    let (number, screen) = display.split_once('.').unwrap_or((display, "0"));
    Ok((
        number.parse().map_err(|_| Error::Connection)?,
        screen.parse().map_err(|_| Error::Connection)?,
    ))
}

fn connect_local(path: &[u8], abstract_name: bool) -> io::Result<UnixStream> {
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as _,
        sun_path: [0; 108],
    };
    let offset = usize::from(abstract_name);
    if path.len() + 1 > address.sun_path.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (dest, &byte) in address.sun_path[offset..].iter_mut().zip(path) {
        *dest = byte as _;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
    // SAFETY: socket takes only values. A nonnegative result transfers one
    // fresh descriptor, owned here exactly once, even on connect failure.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: address is initialized and len lies within its storage. A full
    // backlog returns EAGAIN on the nonblocking socket rather than stalling.
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const address).cast(),
            len as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut peer = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
    // SAFETY: both output pointers name initialized writable storage of the
    // supplied size. getuid has no pointer arguments.
    let uid = unsafe { libc::getuid() };
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut peer).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of_val(&peer)
        || peer.pid <= 0
        || (peer.uid != 0 && peer.uid != uid)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(UnixStream::from(fd))
}

fn auth_cookie(
    path: &Path,
    family: Family,
    host: &[u8],
    number: u16,
) -> io::Result<Option<Vec<u8>>> {
    const MAX_AUTHORITY: u64 = 1024 * 1024;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_AUTHORITY + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_AUTHORITY {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(find_cookie(&bytes, family, host, number))
}

fn find_cookie(mut bytes: &[u8], family: Family, host: &[u8], number: u16) -> Option<Vec<u8>> {
    fn word(bytes: &mut &[u8]) -> Option<u16> {
        let (prefix, remaining) = bytes.split_at_checked(2)?;
        *bytes = remaining;
        Some(u16::from_be_bytes([prefix[0], prefix[1]]))
    }
    fn field<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
        let len = word(bytes)?;
        let (prefix, remaining) = bytes.split_at_checked(usize::from(len))?;
        *bytes = remaining;
        Some(prefix)
    }
    let number = number.to_string();
    let mut wildcard = None;
    while !bytes.is_empty() {
        let entry_family = Family::from(word(&mut bytes)?);
        let entry_host = field(&mut bytes)?;
        let entry_display = field(&mut bytes)?;
        let protocol = field(&mut bytes)?;
        let secret = field(&mut bytes)?;
        if protocol != MIT_COOKIE
            || secret.len() != 16
            || !(entry_display.is_empty() || entry_display == number.as_bytes())
        {
            continue;
        }
        if entry_family == family && entry_host == host {
            return Some(secret.to_vec());
        }
        if entry_family == Family::WILD {
            wildcard.get_or_insert_with(|| secret.to_vec());
        }
    }
    wildcard
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u16,
    pub height: u16,
}

impl From<xproto::Rectangle> for Rect {
    fn from(r: xproto::Rectangle) -> Self {
        Self {
            x: r.x.into(),
            y: r.y.into(),
            width: r.width,
            height: r.height,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowFacts {
    pub input_output: bool,
    pub override_redirect: bool,
    pub viewable: bool,
    pub visual: u32,
    pub depth: u8,
    pub border: u16,
    pub rect: Rect,
}

pub struct Tree {
    pub root: u32,
    pub parent: u32,
    /// Bottom to top, the order returned by QueryTree.
    pub children: Vec<u32>,
}

#[derive(Clone, Copy)]
pub struct Facilities {
    pub composite: bool,
    pub damage: bool,
    pub resource: bool,
}

struct Atoms {
    clients: u32,
    active: u32,
    compositor: u32,
}

pub struct Connection {
    wire: RustConnection<BoundedStream>,
    screen: usize,
    atoms: Atoms,
    facilities: Facilities,
    shape: bool,
    #[cfg(feature = "x11-test-support")]
    read_count: std::sync::atomic::AtomicUsize,
    #[cfg(feature = "x11-test-support")]
    before_image_read: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Connection {
    /// Use only the local socket and explicitly supplied session authority;
    /// never take DISPLAY or XAUTHORITY from cerebellum's own environment.
    pub fn open(display: &str, authority: Option<&Path>) -> Result<Self, Error> {
        let (number, screen) = local_display(display)?;
        let path = format!("/tmp/.X11-unix/X{number}");
        let stream = connect_local(path.as_bytes(), false)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    connect_local(path.as_bytes(), true)
                } else {
                    Err(e)
                }
            })
            .map_err(|_| Error::Connection)?;
        let (stream, (family, host)) =
            DefaultStream::from_unix_stream(stream).map_err(|_| Error::Connection)?;
        let cookie =
            authority.and_then(|path| auth_cookie(path, family, &host, number).ok().flatten());
        let name = if cookie.is_some() {
            MIT_COOKIE.to_vec()
        } else {
            Vec::new()
        };
        let wire = RustConnection::connect_to_stream_with_auth_info(
            BoundedStream(stream),
            screen,
            name,
            cookie.unwrap_or_default(),
        )
        .map_err(|_| Error::Connection)?;
        let atom = |name: &[u8]| -> Result<u32, Error> {
            Ok(wire.intern_atom(false, name)?.reply()?.atom)
        };
        let atoms = Atoms {
            clients: atom(b"_NET_CLIENT_LIST_STACKING")?,
            active: atom(b"_NET_ACTIVE_WINDOW")?,
            compositor: atom(format!("_NET_WM_CM_S{screen}").as_bytes())?,
        };
        let has =
            |name| -> Result<bool, Error> { Ok(wire.query_extension(name)?.reply()?.present) };
        let facilities = Facilities {
            composite: has(composite::X11_EXTENSION_NAME.as_bytes())?
                && wire
                    .composite_query_version(0, 4)?
                    .reply()
                    .is_ok_and(|v| (v.major_version, v.minor_version) >= (0, 2)),
            damage: has(damage::X11_EXTENSION_NAME.as_bytes())?
                && wire
                    .damage_query_version(1, 1)?
                    .reply()
                    .is_ok_and(|v| v.major_version == 1),
            resource: has(res::X11_EXTENSION_NAME.as_bytes())?
                && wire
                    .res_query_version(1, 2)?
                    .reply()
                    .is_ok_and(|v| (v.server_major, v.server_minor) >= (1, 2)),
        };
        let shape = has(shape::X11_EXTENSION_NAME.as_bytes())?;
        Ok(Self {
            wire,
            screen,
            atoms,
            facilities,
            shape,
            #[cfg(feature = "x11-test-support")]
            read_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "x11-test-support")]
            before_image_read: std::sync::Mutex::new(None),
        })
    }

    pub fn check(&self) -> Result<(), Error> {
        self.sync_sequence().map(|_| ())
    }

    pub fn sync_sequence(&self) -> Result<u64, Error> {
        let request = self.wire.get_input_focus()?;
        let sequence = request.sequence_number();
        request.reply()?;
        Ok(sequence)
    }

    pub fn root(&self) -> u32 {
        self.wire.setup().roots[self.screen].root
    }

    pub fn root_bounds(&self) -> Result<Rect, Error> {
        let g = self.wire.get_geometry(self.root())?.reply()?;
        Ok(Rect {
            x: 0,
            y: 0,
            width: g.width,
            height: g.height,
        })
    }

    pub fn facilities(&self) -> Facilities {
        self.facilities
    }

    fn window_property(&self, atom: u32, maximum: u32) -> Result<Vec<u32>, Error> {
        let p = self
            .wire
            .get_property(
                false,
                self.root(),
                atom,
                xproto::AtomEnum::WINDOW,
                0,
                maximum,
            )?
            .reply()?;
        if p.type_ == x11rb::NONE {
            return Ok(Vec::new());
        }
        if p.bytes_after != 0 || p.type_ != u32::from(xproto::AtomEnum::WINDOW) {
            return Err(Error::Unreadable);
        }
        let windows = p.value32().ok_or(Error::Unreadable)?.collect();
        Ok(windows)
    }

    pub fn client_stack(&self) -> Result<Vec<u32>, Error> {
        self.window_property(self.atoms.clients, MAX_PROPERTY_WINDOWS)
    }

    pub fn active_window(&self) -> Result<Option<u32>, Error> {
        Ok(self
            .window_property(self.atoms.active, 1)?
            .first()
            .copied()
            .filter(|window| *window != 0))
    }

    pub fn compositor(&self) -> Result<Option<u32>, Error> {
        let owner = self
            .wire
            .get_selection_owner(self.atoms.compositor)?
            .reply()?
            .owner;
        Ok((owner != 0).then_some(owner))
    }

    pub fn owner_pid(&self, window: u32) -> Result<Option<u32>, Error> {
        if !self.facilities.resource || window == 0 || window == self.root() {
            return Err(Error::Unreadable);
        }
        let ids = self
            .wire
            .res_query_client_ids(&[res::ClientIdSpec {
                client: window,
                mask: res::ClientIdMask::LOCAL_CLIENT_PID,
            }])?
            .reply()?
            .ids;
        Ok(match ids.as_slice() {
            [id] if id.spec.mask == res::ClientIdMask::LOCAL_CLIENT_PID => {
                match id.value.as_slice() {
                    [pid] if (1..=i32::MAX as u32).contains(pid) => Some(*pid),
                    _ => None,
                }
            }
            _ => None,
        })
    }

    pub fn facts(&self, window: u32) -> Result<WindowFacts, Error> {
        let attributes = self.wire.get_window_attributes(window)?;
        let geometry = self.wire.get_geometry(window)?;
        let a = attributes.reply()?;
        let g = geometry.reply()?;
        Ok(WindowFacts {
            input_output: a.class == xproto::WindowClass::INPUT_OUTPUT,
            override_redirect: a.override_redirect,
            viewable: a.map_state == xproto::MapState::VIEWABLE,
            visual: a.visual,
            depth: g.depth,
            border: g.border_width,
            rect: Rect {
                x: g.x.into(),
                y: g.y.into(),
                width: g.width,
                height: g.height,
            },
        })
    }

    pub fn tree(&self, window: u32) -> Result<Tree, Error> {
        let t = self.wire.query_tree(window)?.reply()?;
        if t.children.len() > MAX_PROPERTY_WINDOWS as usize {
            return Err(Error::Unreadable);
        }
        Ok(Tree {
            root: t.root,
            parent: t.parent,
            children: t.children,
        })
    }

    pub fn translate(&self, source: u32, destination: u32) -> Result<(i32, i32), Error> {
        let t = self
            .wire
            .translate_coordinates(source, destination, 0, 0)?
            .reply()?;
        if !t.same_screen {
            return Err(Error::Unreadable);
        }
        Ok((t.dst_x.into(), t.dst_y.into()))
    }

    pub fn shape(&self, window: u32, clip: bool) -> Result<Option<Vec<Rect>>, Error> {
        if !self.shape {
            return Ok(None);
        }
        let kind = if clip {
            shape::SK::CLIP
        } else {
            shape::SK::BOUNDING
        };
        let shape = self.wire.shape_get_rectangles(window, kind)?.reply()?;
        if shape.rectangles.len() > MAX_PROPERTY_WINDOWS as usize {
            return Err(Error::Unreadable);
        }
        Ok(Some(shape.rectangles.into_iter().map(Rect::from).collect()))
    }

    pub fn watch(&self, window: u32) -> Result<Watch<'_>, Error> {
        let previous = self
            .wire
            .get_window_attributes(window)?
            .reply()?
            .your_event_mask;
        self.wire
            .change_window_attributes(
                window,
                &xproto::ChangeWindowAttributesAux::new().event_mask(
                    previous
                        | xproto::EventMask::STRUCTURE_NOTIFY
                        | xproto::EventMask::SUBSTRUCTURE_NOTIFY,
                ),
            )?
            .check()?;
        let mut watch = Watch {
            connection: self,
            window,
            previous,
            previous_shape: None,
        };
        if self.shape {
            let previous = self.wire.shape_input_selected(window)?.reply()?.enabled;
            self.wire.shape_select_input(window, true)?.check()?;
            watch.previous_shape = Some(previous);
        }
        Ok(watch)
    }

    pub fn damage(&self, client: u32) -> Result<Damage<'_>, Error> {
        let id = self.wire.generate_id()?;
        self.wire
            .damage_create(id, client, damage::ReportLevel::RAW_RECTANGLES)?
            .check()?;
        Ok(Damage {
            connection: self,
            id,
        })
    }

    pub fn redirect_automatic(&self, top: u32) -> Result<Redirect<'_>, Error> {
        let request = self
            .wire
            .composite_redirect_window(top, composite::Redirect::AUTOMATIC)?;
        request.check()?;
        Ok(Redirect {
            connection: self,
            top,
        })
    }

    pub fn name_pixmap(&self, top: u32) -> Result<Pixmap<'_>, Error> {
        let id = self.wire.generate_id()?;
        self.wire.composite_name_window_pixmap(top, id)?.check()?;
        Ok(Pixmap {
            connection: self,
            id,
        })
    }

    pub fn poll_event(&self) -> Result<Option<Reading>, Error> {
        Ok(self
            .wire
            .poll_for_event_with_sequence()?
            .map(|(event, sequence)| match event {
                Event::DestroyNotify(e) if e.response_type & 0x80 == 0 => {
                    Reading::Destroyed(e.window)
                }
                Event::CreateNotify(_)
                | Event::MapNotify(_)
                | Event::UnmapNotify(_)
                | Event::ReparentNotify(_)
                | Event::ConfigureNotify(_)
                | Event::CirculateNotify(_)
                | Event::GravityNotify(_)
                | Event::ShapeNotify(_) => Reading::StructureChanged,
                Event::DamageNotify(e) if e.response_type & 0x80 == 0 => Reading::Damaged {
                    sequence,
                    damage: e.damage,
                    drawable: e.drawable,
                    rect: e.area.into(),
                },
                _ => Reading::Other,
            }))
    }
}

pub enum Reading {
    Destroyed(u32),
    StructureChanged,
    Damaged {
        sequence: u64,
        damage: u32,
        drawable: u32,
        rect: Rect,
    },
    Other,
}

pub struct Watch<'a> {
    connection: &'a Connection,
    window: u32,
    previous: xproto::EventMask,
    previous_shape: Option<bool>,
}

impl Drop for Watch<'_> {
    fn drop(&mut self) {
        if let Some(previous) = self.previous_shape {
            if let Ok(cookie) = self
                .connection
                .wire
                .shape_select_input(self.window, previous)
            {
                cookie.ignore_error();
            }
        }
        if let Ok(cookie) = self.connection.wire.change_window_attributes(
            self.window,
            &xproto::ChangeWindowAttributesAux::new().event_mask(self.previous),
        ) {
            cookie.ignore_error();
            let _ = self.connection.wire.flush();
        }
    }
}

pub struct Damage<'a> {
    connection: &'a Connection,
    id: u32,
}

impl Damage<'_> {
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Drop for Damage<'_> {
    fn drop(&mut self) {
        if let Ok(cookie) = self.connection.wire.damage_destroy(self.id) {
            cookie.ignore_error();
            let _ = self.connection.wire.flush();
        }
    }
}

pub struct Redirect<'a> {
    connection: &'a Connection,
    top: u32,
}

impl Drop for Redirect<'_> {
    fn drop(&mut self) {
        if let Ok(cookie) = self
            .connection
            .wire
            .composite_unredirect_window(self.top, composite::Redirect::AUTOMATIC)
        {
            cookie.ignore_error();
            let _ = self.connection.wire.flush();
        }
    }
}

pub struct Pixmap<'a> {
    connection: &'a Connection,
    id: u32,
}

impl Drop for Pixmap<'_> {
    fn drop(&mut self) {
        if let Ok(cookie) = self.connection.wire.free_pixmap(self.id) {
            cookie.ignore_error();
            let _ = self.connection.wire.flush();
        }
    }
}

/// A validated GetImage request. Constructing one reads geometry, not pixels.
/// The caller checks its acquisition fence immediately before `read`.
pub struct ImageRead<'a> {
    pixmap: &'a Pixmap<'a>,
    rect: Rect,
    bytes_per_pixel: usize,
    stride: usize,
    masks: [u32; 3],
    little_endian: bool,
}

impl Pixmap<'_> {
    pub fn prepare(&self, rect: Rect, frame: WindowFacts) -> Result<ImageRead<'_>, Error> {
        let setup = self.connection.wire.setup();
        let geom = self.connection.wire.get_geometry(self.id)?.reply()?;
        let valid_size = |size, border| u32::from(size) + 2 * u32::from(border);
        if geom.depth != frame.depth
            || geom.root != self.connection.root()
            || u32::from(geom.width) != valid_size(frame.rect.width, frame.border)
            || u32::from(geom.height) != valid_size(frame.rect.height, frame.border)
            || rect.x < 0
            || rect.y < 0
            || rect.x > i32::from(i16::MAX)
            || rect.y > i32::from(i16::MAX)
            || rect.x + i32::from(rect.width) > i32::from(geom.width)
            || rect.y + i32::from(rect.height) > i32::from(geom.height)
            || !(1..=MAX_CAPTURE_PIXELS).contains(&(u32::from(rect.width) * u32::from(rect.height)))
        {
            return Err(Error::Unreadable);
        }
        let format = setup
            .pixmap_formats
            .iter()
            .find(|f| f.depth == geom.depth)
            .ok_or(Error::Unreadable)?;
        let visual = setup.roots[self.connection.screen]
            .allowed_depths
            .iter()
            .flat_map(|depth| &depth.visuals)
            .find(|v| v.visual_id == frame.visual && v.class == xproto::VisualClass::TRUE_COLOR)
            .ok_or(Error::Unreadable)?;
        if !matches!(format.bits_per_pixel, 16 | 24 | 32)
            || !matches!(format.scanline_pad, 8 | 16 | 32)
        {
            return Err(Error::Unreadable);
        }
        let bits = usize::from(format.bits_per_pixel);
        let pad = usize::from(format.scanline_pad);
        let masks = [visual.blue_mask, visual.green_mask, visual.red_mask];
        if masks.iter().any(|mask| {
            if *mask == 0 {
                return true;
            }
            let normalized = mask >> mask.trailing_zeros();
            !normalized.wrapping_add(1).is_power_of_two() || 32 - mask.leading_zeros() > bits as u32
        }) || (masks[0] & masks[1]) | (masks[1] & masks[2]) | (masks[2] & masks[0]) != 0
        {
            return Err(Error::Unreadable);
        }
        Ok(ImageRead {
            pixmap: self,
            rect,
            bytes_per_pixel: bits / 8,
            stride: (usize::from(rect.width) * bits).div_ceil(pad) * pad / 8,
            masks,
            little_endian: setup.image_byte_order == xproto::ImageOrder::LSB_FIRST,
        })
    }
}

impl ImageRead<'_> {
    pub fn read(self) -> Result<Vec<u8>, Error> {
        #[cfg(feature = "x11-test-support")]
        if let Some(action) = self
            .pixmap
            .connection
            .before_image_read
            .lock()
            .unwrap()
            .take()
        {
            action();
        }
        #[cfg(feature = "x11-test-support")]
        self.pixmap
            .connection
            .read_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let reply = self
            .pixmap
            .connection
            .wire
            .get_image(
                xproto::ImageFormat::Z_PIXMAP,
                self.pixmap.id,
                self.rect.x as i16,
                self.rect.y as i16,
                self.rect.width,
                self.rect.height,
                u32::MAX,
            )?
            .reply()?;
        let used = self.stride * usize::from(self.rect.height);
        if reply.data.len() != used.next_multiple_of(4) {
            return Err(Error::Unreadable);
        }
        let width = usize::from(self.rect.width);
        if self.little_endian
            && self.bytes_per_pixel == 4
            && self.stride == width * 4
            && self.masks == [0xff, 0xff00, 0xff0000]
        {
            return Ok(reply.data);
        }
        let mut bgra = Vec::with_capacity(width * usize::from(self.rect.height) * 4);
        let shifts = self.masks.map(u32::trailing_zeros);
        let maxes = std::array::from_fn::<_, 3, _>(|i| self.masks[i] >> shifts[i]);
        for row in reply.data[..used].chunks_exact(self.stride) {
            for pixel in row[..width * self.bytes_per_pixel].chunks_exact(self.bytes_per_pixel) {
                let mut bytes = [0; 4];
                let value = if self.little_endian {
                    bytes[..pixel.len()].copy_from_slice(pixel);
                    u32::from_le_bytes(bytes)
                } else {
                    bytes[4 - pixel.len()..].copy_from_slice(pixel);
                    u32::from_be_bytes(bytes)
                };
                for i in 0..3 {
                    let channel = (value & self.masks[i]) >> shifts[i];
                    bgra.push(
                        ((u64::from(channel) * 255 + u64::from(maxes[i]) / 2) / u64::from(maxes[i]))
                            as u8,
                    );
                }
                bgra.push(255);
            }
        }
        Ok(bgra)
    }
}

/// Box-resample a tightly packed BGRA frame, then encode it as JPEG. Both the
/// input allocation and the encoder's output dimensions are capped here even
/// when the caller is not an X11 pixmap reader.
pub fn encode_bgra_jpeg(
    bgra: &[u8],
    source: (u32, u32),
    dest: (u32, u32),
) -> Result<Vec<u8>, Error> {
    let (sw, sh) = source;
    let (dw, dh) = dest;
    if source
        .0
        .checked_mul(source.1)
        .is_none_or(|area| area > MAX_CAPTURE_PIXELS || (area as usize) * 4 != bgra.len())
        || sw > u32::from(u16::MAX)
        || sh > u32::from(u16::MAX)
        || dw == 0
        || dh == 0
        || dw > sw
        || dh > sh
        || dw > 2048
        || dh > 2048
    {
        return Err(Error::Unreadable);
    }
    let mut rgb = Vec::with_capacity((dw * dh * 3) as usize);
    for y in 0..dh {
        let y0 = (y * sh / dh) as usize;
        let y1 = ((y + 1) * sh / dh) as usize;
        for x in 0..dw {
            let x0 = (x * sw / dw) as usize;
            let x1 = ((x + 1) * sw / dw) as usize;
            let mut channels = [0u64; 3];
            for row in y0..y1 {
                let offset = row * sw as usize * 4;
                for pixel in bgra[offset + x0 * 4..offset + x1 * 4].as_chunks::<4>().0 {
                    channels[0] += u64::from(pixel[2]);
                    channels[1] += u64::from(pixel[1]);
                    channels[2] += u64::from(pixel[0]);
                }
            }
            let samples = ((x1 - x0) * (y1 - y0)) as u64;
            rgb.extend(channels.map(|sum| ((sum + samples / 2) / samples) as u8));
        }
    }
    let mut jpeg = Vec::new();
    jpeg_encoder::Encoder::new(&mut jpeg, 85)
        .encode(&rgb, dw as u16, dh as u16, jpeg_encoder::ColorType::Rgb)
        .map_err(|_| Error::Unreadable)?;
    Ok(jpeg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(family: u16, address: &[u8], display: &[u8], secret: u8) -> Vec<u8> {
        let mut bytes = family.to_be_bytes().to_vec();
        for field in [address, display, MIT_COOKIE, &[secret; 16]] {
            bytes.extend((field.len() as u16).to_be_bytes());
            bytes.extend(field);
        }
        bytes
    }

    #[test]
    fn local_display_and_authority_do_not_accept_a_different_endpoint() {
        assert_eq!(local_display(":6.2"), Ok((6, 2)));
        assert_eq!(local_display("unix/:6"), Ok((6, 0)));
        for remote in ["host:6", "localhost:6.0", "tcp/:6", "::6", ":-1"] {
            assert_eq!(local_display(remote), Err(Error::Connection));
        }
        let mut auth = entry(256, b"other-host", b"6", 1);
        auth.extend(entry(256, b"host", b"7", 2));
        assert!(find_cookie(&auth, Family::from(256), b"host", 6).is_none());
        auth.extend(entry(65535, b"", b"6", 3));
        auth.extend(entry(256, b"host", b"6", 4));
        assert_eq!(
            find_cookie(&auth, Family::from(256), b"host", 6),
            Some(vec![4; 16])
        );
        let malformed = &auth[auth.len() - 3..];
        assert!(find_cookie(malformed, Family::from(256), b"host", 6).is_none());
    }

    #[test]
    fn resampler_rejects_malformed_or_unbounded_images() {
        for (pixels, src, dst) in [
            (&[0; 15][..], (2, 2), (1, 1)),
            (&[][..], (u32::MAX, 2), (1, 1)),
            (&[0; 16][..], (2, 2), (3, 3)),
            (&[0; 16][..], (2, 2), (0, 2)),
        ] {
            assert_eq!(encode_bgra_jpeg(pixels, src, dst), Err(Error::Unreadable));
        }
        let jpeg = encode_bgra_jpeg(&[0x60; 64], (4, 4), (2, 2)).unwrap();
        assert_eq!(&jpeg[..2], &[0xff, 0xd8]);
        let sof = jpeg.windows(2).position(|m| m == [0xff, 0xc0]).unwrap();
        assert_eq!(&jpeg[sof + 5..sof + 9], &[0, 2, 0, 2]);
    }
}
