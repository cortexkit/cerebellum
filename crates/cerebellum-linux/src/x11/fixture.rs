//! Test-only clients for a private Xvfb display. Nothing here is in the normal binary.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use x11rb::connection::Connection as _;
use x11rb::protocol::composite::{ConnectionExt as _, Redirect};
use x11rb::protocol::xproto::{
    AtomEnum, BackingStore, ChangeGCAux, ChangeWindowAttributesAux, ConfigureWindowAux,
    ConnectionExt as _, CreateGCAux, CreateWindowAux, EventMask, ImageFormat, Rectangle, StackMode,
    WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

use super::{Connection, Rect};

pub fn pixels_requested(connection: &Connection) -> usize {
    connection.read_count.load(Ordering::Relaxed)
}

pub fn before_next_image_read(connection: &Connection, action: impl FnOnce() + Send + 'static) {
    assert!(connection
        .before_image_read
        .lock()
        .unwrap()
        .replace(Box::new(action))
        .is_none());
}

pub const OLD: u32 = 0xcd3020;
pub const NEW: u32 = 0x32b840;
pub const OCCLUDER: u32 = 0x204beb;
pub const LABEL_LINE: u32 = 0x101010;
pub const CLIENT: Rect = Rect {
    x: 62,
    y: 76,
    width: 160,
    height: 100,
};

/// A reparenting fixture WM and a separate app connection. The EWMH
/// properties are published by the WM connection; the app owns the client ID.
pub struct Desktop {
    app: Arc<RustConnection>,
    wm: Arc<RustConnection>,
    root: u32,
    frame: u32,
    client: u32,
    occluder: u32,
    gc: u32,
    frame_gc: u32,
    active: u32,
    compositor: Option<RustConnection>,
    display: String,
    screen: usize,
}

impl Desktop {
    pub fn open(display: &str) -> Self {
        let (wm, screen) = x11rb::connect(Some(display)).unwrap();
        let (app, _) = x11rb::connect(Some(display)).unwrap();
        let root = wm.setup().roots[screen].root;
        wm.change_window_attributes(
            root,
            &ChangeWindowAttributesAux::new().event_mask(EventMask::SUBSTRUCTURE_REDIRECT),
        )
        .unwrap()
        .check()
        .unwrap();
        let frame = wm.generate_id().unwrap();
        wm.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            frame,
            root,
            49,
            61,
            220,
            150,
            2,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new().background_pixel(0xfdc200),
        )
        .unwrap()
        .check()
        .unwrap();
        let client = app.generate_id().unwrap();
        app.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            client,
            root,
            0,
            0,
            CLIENT.width,
            CLIENT.height,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new()
                .backing_store(BackingStore::NOT_USEFUL)
                .background_pixel(OLD),
        )
        .unwrap()
        .check()
        .unwrap();
        wm.reparent_window(client, frame, 11, 13)
            .unwrap()
            .check()
            .unwrap();
        wm.map_window(frame).unwrap().check().unwrap();
        wm.map_window(client).unwrap().check().unwrap();
        let clients = wm
            .intern_atom(false, b"_NET_CLIENT_LIST_STACKING")
            .unwrap()
            .reply()
            .unwrap()
            .atom;
        let active = wm
            .intern_atom(false, b"_NET_ACTIVE_WINDOW")
            .unwrap()
            .reply()
            .unwrap()
            .atom;
        wm.change_property32(
            x11rb::protocol::xproto::PropMode::REPLACE,
            root,
            clients,
            AtomEnum::WINDOW,
            &[client],
        )
        .unwrap()
        .check()
        .unwrap();
        let occluder = wm.generate_id().unwrap();
        wm.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            occluder,
            root,
            58,
            72,
            138,
            113,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new()
                .override_redirect(1)
                .background_pixel(OCCLUDER),
        )
        .unwrap()
        .check()
        .unwrap();
        let gc = app.generate_id().unwrap();
        app.create_gc(gc, client, &CreateGCAux::new())
            .unwrap()
            .check()
            .unwrap();
        let frame_gc = wm.generate_id().unwrap();
        wm.create_gc(frame_gc, frame, &CreateGCAux::new())
            .unwrap()
            .check()
            .unwrap();
        let desktop = Self {
            app: Arc::new(app),
            wm: Arc::new(wm),
            root,
            frame,
            client,
            occluder,
            gc,
            frame_gc,
            display: display.to_owned(),
            screen,
            active,
            compositor: None,
        };
        desktop.set_active_client(true);
        desktop.paint_old();
        desktop
    }

    pub fn window(&self) -> u32 {
        self.client
    }

    pub fn set_active_client(&self, active: bool) {
        use x11rb::protocol::xproto::PropMode;
        self.wm
            .change_property32(
                PropMode::REPLACE,
                self.root,
                self.active,
                AtomEnum::WINDOW,
                &[if active { self.client } else { self.occluder }],
            )
            .unwrap()
            .check()
            .unwrap();
    }

    pub fn set_covered(&self, covered: bool) {
        if covered {
            self.wm.map_window(self.occluder).unwrap().check().unwrap();
            self.wm
                .configure_window(
                    self.occluder,
                    &ConfigureWindowAux::new().stack_mode(StackMode::ABOVE),
                )
                .unwrap()
                .check()
                .unwrap();
        } else {
            self.wm
                .unmap_window(self.occluder)
                .unwrap()
                .check()
                .unwrap();
        }
    }

    pub fn map_client(&self, mapped: bool) {
        if mapped {
            self.wm.map_window(self.client).unwrap().check().unwrap();
        } else {
            self.wm.unmap_window(self.client).unwrap().check().unwrap();
        }
    }

    pub fn map_frame(&self, mapped: bool) {
        if mapped {
            self.wm.map_window(self.frame).unwrap().check().unwrap();
        } else {
            self.wm.unmap_window(self.frame).unwrap().check().unwrap();
        }
    }

    pub fn set_compositing(&mut self, compositing: bool) {
        if !compositing {
            self.compositor = None;
            return;
        }
        let (cm, _) = x11rb::connect(Some(&self.display)).unwrap();
        cm.composite_query_version(0, 4).unwrap().reply().unwrap();
        let owner = cm.generate_id().unwrap();
        cm.create_window(
            0,
            owner,
            self.root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new(),
        )
        .unwrap()
        .check()
        .unwrap();
        let atom = cm
            .intern_atom(false, format!("_NET_WM_CM_S{}", self.screen).as_bytes())
            .unwrap()
            .reply()
            .unwrap()
            .atom;
        cm.set_selection_owner(owner, atom, x11rb::CURRENT_TIME)
            .unwrap()
            .check()
            .unwrap();
        cm.composite_redirect_subwindows(self.root, Redirect::MANUAL)
            .unwrap()
            .check()
            .unwrap();
        self.compositor = Some(cm);
    }

    pub fn paint_old(&self) {
        paint(&self.app, self.client, self.gc, OLD, b"OLD LABEL");
    }

    pub fn paint_new(&self) {
        paint(&self.app, self.client, self.gc, NEW, b"NEW LABEL");
    }

    pub fn repaint_new(&self) -> impl Fn() + Send + 'static {
        let (app, client, gc) = (self.app.clone(), self.client, self.gc);
        move || paint(&app, client, gc, NEW, b"NEW LABEL")
    }

    pub fn damage_frame(&self) -> impl Fn() + Send + 'static {
        let (wm, frame, gc) = (self.wm.clone(), self.frame, self.frame_gc);
        move || {
            wm.change_gc(gc, &ChangeGCAux::new().foreground(0x669900))
                .unwrap()
                .check()
                .unwrap();
            wm.poly_fill_rectangle(
                frame,
                gc,
                &[Rectangle {
                    x: 0,
                    y: 0,
                    width: 220,
                    height: 150,
                }],
            )
            .unwrap()
            .check()
            .unwrap();
        }
    }

    pub fn advertise_pid(&self, claimed: u32) {
        let atom = self
            .app
            .intern_atom(false, b"_NET_WM_PID")
            .unwrap()
            .reply()
            .unwrap()
            .atom;
        self.app
            .change_property32(
                x11rb::protocol::xproto::PropMode::REPLACE,
                self.client,
                atom,
                AtomEnum::CARDINAL,
                &[claimed],
            )
            .unwrap()
            .check()
            .unwrap();
    }

    pub fn transient_clip_change(&self) -> impl FnOnce() + Send + 'static {
        use x11rb::protocol::shape::{ConnectionExt as _, SK, SO};
        use x11rb::protocol::xproto::ClipOrdering;
        let (app, client) = (self.app.clone(), self.client);
        move || {
            for width in [CLIENT.width / 2, CLIENT.width] {
                app.shape_rectangles(
                    SO::SET,
                    SK::CLIP,
                    ClipOrdering::UNSORTED,
                    client,
                    0,
                    0,
                    &[Rectangle {
                        x: 0,
                        y: 0,
                        width,
                        height: CLIENT.height,
                    }],
                )
                .unwrap()
                .check()
                .unwrap();
            }
        }
    }

    /// A visible root pixel used to prove actual, not just logical, occlusion.
    pub fn covered_pixel(&self) -> u32 {
        let reply = self
            .wm
            .get_image(ImageFormat::Z_PIXMAP, self.root, 90, 90, 1, 1, u32::MAX)
            .unwrap()
            .reply()
            .unwrap();
        u32::from_le_bytes(reply.data[..4].try_into().unwrap()) & 0xff_ffff
    }
}

fn paint(app: &RustConnection, client: u32, gc: u32, color: u32, label: &[u8]) {
    app.change_gc(gc, &ChangeGCAux::new().foreground(color))
        .unwrap()
        .check()
        .unwrap();
    app.poly_fill_rectangle(
        client,
        gc,
        &[Rectangle {
            x: 0,
            y: 0,
            width: CLIENT.width,
            height: CLIENT.height,
        }],
    )
    .unwrap()
    .check()
    .unwrap();
    app.change_gc(
        gc,
        &ChangeGCAux::new().foreground(LABEL_LINE).background(color),
    )
    .unwrap()
    .check()
    .unwrap();
    app.image_text8(client, gc, 20, 45, label)
        .unwrap()
        .check()
        .unwrap();
}
