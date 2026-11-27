//! Read-only logind and session-bus queries. No query starts a D-Bus service.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use zbus::proxy::{CacheProperties, MethodFlags};
use zbus::{connection::Builder, Connection, DynamicType, OwnedObjectPath, OwnedVariant, Proxy};

const LOGIN: &str = "org.freedesktop.login1";
const LOGIN_PATH: &str = "/org/freedesktop/login1";
const SYSTEMD: &str = "org.freedesktop.systemd1";
const DBUS: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    X11,
    Wayland,
}

pub type Environment = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessibilityBus {
    pub address: String,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopSession {
    pub id: String,
    pub kind: SessionKind,
    pub locked: bool,
    pub environment: Environment,
    pub accessibility: Option<AccessibilityBus>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoSupportedSession;

/// Re-read the manager's environment even if the logind session has not changed.
/// The process environment is only a fallback for an unreachable user manager.
pub async fn resolve(require_accessibility: bool) -> Result<DesktopSession, NoSupportedSession> {
    // Use the real system bus rather than treating a launcher's environment as
    // authority for logind's session and lock-state readings.
    let system = connect("unix:path=/run/dbus/system_bus_socket")
        .await
        .map_err(|_| NoSupportedSession)?;
    // SAFETY: geteuid has no arguments and returns the caller's effective uid.
    let uid = unsafe { libc::geteuid() };
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let manager_address = format!("unix:path={}/bus", runtime.display());
    let user = connect(&manager_address).await.ok();
    resolve_on(
        &system,
        user.as_ref(),
        uid,
        std::process::id(),
        &runtime,
        || {
            std::env::vars_os()
                .filter_map(|(key, value)| {
                    Some((key.into_string().ok()?, value.into_string().ok()?))
                })
                .collect()
        },
        require_accessibility,
    )
    .await
}

async fn connect(address: &str) -> zbus::Result<Connection> {
    Builder::address(address).build().await
}

async fn call<B, R>(
    connection: &Connection,
    destination: &str,
    path: &str,
    interface: &str,
    method: &str,
    body: &B,
) -> zbus::Result<R>
where
    B: Serialize + DynamicType,
    R: for<'d> zbus::wire::DynamicDeserialize<'d>,
{
    zbus::proxy::Builder::<Proxy<'_>>::new(connection)
        .destination(destination)
        .path(path)
        .interface(interface)
        .cache_properties(CacheProperties::No)
        .build()
        .await?
        .call_with_flags(method, MethodFlags::NO_AUTO_START, body)
        .await?
        .ok_or(zbus::Error::Failure("missing reply".into()))
}

async fn property<T: TryFrom<OwnedVariant>>(
    system: &Connection,
    destination: &str,
    path: &str,
    interface: &str,
    name: &str,
) -> Result<T, NoSupportedSession> {
    let value: OwnedVariant = call(
        system,
        destination,
        path,
        "org.freedesktop.DBus.Properties",
        "Get",
        &(interface, name),
    )
    .await
    .map_err(|_| NoSupportedSession)?;
    T::try_from(value).map_err(|_| NoSupportedSession)
}

async fn logind<B, R>(system: &Connection, method: &str, body: &B) -> zbus::Result<R>
where
    B: Serialize + DynamicType,
    R: for<'d> zbus::wire::DynamicDeserialize<'d>,
{
    call(
        system,
        LOGIN,
        LOGIN_PATH,
        "org.freedesktop.login1.Manager",
        method,
        body,
    )
    .await
}

async fn session_of(system: &Connection, pid: u32) -> zbus::Result<OwnedObjectPath> {
    logind(system, "GetSessionByPID", &(pid,)).await
}

fn method_error(error: &zbus::Error, name: &str) -> bool {
    matches!(error, zbus::Error::MethodError(actual, ..) if actual.as_str() == name)
}

async fn selected_session(
    system: &Connection,
    uid: u32,
    pid: u32,
) -> Result<OwnedObjectPath, NoSupportedSession> {
    match session_of(system, pid).await {
        Ok(path) => Ok(path),
        Err(error) if method_error(&error, "org.freedesktop.login1.NoSessionForPID") => {
            let user: OwnedObjectPath = logind(system, "GetUser", &(uid,))
                .await
                .map_err(|_| NoSupportedSession)?;
            let (_, path): (String, OwnedObjectPath) = property(
                system,
                LOGIN,
                user.as_str(),
                "org.freedesktop.login1.User",
                "Display",
            )
            .await?;
            Ok(path)
        }
        Err(_) => Err(NoSupportedSession),
    }
}

async fn session_property<T: TryFrom<OwnedVariant>>(
    system: &Connection,
    path: &OwnedObjectPath,
    name: &str,
) -> Result<T, NoSupportedSession> {
    property(
        system,
        LOGIN,
        path.as_str(),
        "org.freedesktop.login1.Session",
        name,
    )
    .await
}

async fn resolve_on(
    system: &Connection,
    user: Option<&Connection>,
    uid: u32,
    pid: u32,
    runtime: &Path,
    fallback: impl FnOnce() -> Environment,
    require_accessibility: bool,
) -> Result<DesktopSession, NoSupportedSession> {
    let selected = selected_session(system, uid, pid).await?;
    type ListedSession = (String, u32, String, String, OwnedObjectPath);
    let sessions: Vec<ListedSession> = logind(system, "ListSessions", &())
        .await
        .map_err(|_| NoSupportedSession)?;
    let mut graphical = None;
    for (id, owner, _, _, path) in sessions {
        if owner != uid || !session_property::<bool>(system, &path, "Active").await? {
            continue;
        }
        if session_property::<String>(system, &path, "State").await? == "closing" {
            continue;
        }
        let kind = match session_property::<String>(system, &path, "Type")
            .await?
            .as_str()
        {
            "x11" => SessionKind::X11,
            "wayland" => SessionKind::Wayland,
            _ => continue,
        };
        if graphical.is_some() || path != selected {
            return Err(NoSupportedSession);
        }
        graphical = Some((id, kind));
    }
    let (id, kind) = graphical.ok_or(NoSupportedSession)?;
    let environment = manager_environment(user).await?.unwrap_or_else(fallback);
    let session_type = match kind {
        SessionKind::X11 => "x11",
        SessionKind::Wayland => "wayland",
    };
    if environment
        .get("XDG_SESSION_TYPE")
        .is_some_and(|value| value != session_type)
    {
        return Err(NoSupportedSession);
    }
    match kind {
        SessionKind::X11 => {
            let display: String = session_property(system, &selected, "Display").await?;
            if display.is_empty()
                || environment.get("DISPLAY") != Some(&display)
                || environment.contains_key("WAYLAND_DISPLAY")
            {
                return Err(NoSupportedSession);
            }
        }
        SessionKind::Wayland => {
            let display = environment
                .get("WAYLAND_DISPLAY")
                .filter(|v| !v.is_empty())
                .ok_or(NoSupportedSession)?;
            let display = Path::new(display);
            let socket_path = if display.is_absolute() {
                display.to_path_buf()
            } else if display.components().count() == 1 {
                let runtime = environment
                    .get("XDG_RUNTIME_DIR")
                    .map(Path::new)
                    .unwrap_or(runtime);
                if !runtime.is_absolute() {
                    return Err(NoSupportedSession);
                }
                runtime.join(display)
            } else {
                return Err(NoSupportedSession);
            };
            let peer = tokio::net::UnixStream::connect(socket_path)
                .await
                .map_err(|_| NoSupportedSession)?
                .peer_cred()
                .map_err(|_| NoSupportedSession)?;
            let pid = peer
                .pid()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or(NoSupportedSession)?;
            if peer.uid() != uid || session_of(system, pid).await.ok().as_ref() != Some(&selected) {
                return Err(NoSupportedSession);
            }
        }
    }
    let accessibility = if require_accessibility {
        Some(accessibility_bus(&environment).await?)
    } else {
        None
    };
    let locked = session_property(system, &selected, "LockedHint").await?;
    Ok(DesktopSession {
        id,
        kind,
        locked,
        environment,
        accessibility,
    })
}

async fn manager_environment(
    user: Option<&Connection>,
) -> Result<Option<Environment>, NoSupportedSession> {
    let Some(user) = user else {
        return Ok(None);
    };
    let owner: String = match call(user, DBUS, DBUS_PATH, DBUS, "GetNameOwner", &(SYSTEMD,)).await {
        Ok(owner) => owner,
        Err(error) if method_error(&error, "org.freedesktop.DBus.NameHasNoOwner") => {
            return Ok(None)
        }
        Err(_) => return Err(NoSupportedSession),
    };
    let entries: Vec<String> = property(
        user,
        &owner,
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "Environment",
    )
    .await?;
    let mut environment = Environment::new();
    for entry in entries {
        let (key, value) = entry.split_once('=').ok_or(NoSupportedSession)?;
        if environment
            .insert(key.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(NoSupportedSession);
        }
    }
    Ok(Some(environment))
}

async fn accessibility_bus(
    environment: &Environment,
) -> Result<AccessibilityBus, NoSupportedSession> {
    let address = if let Some(address) = environment.get("AT_SPI_BUS_ADDRESS") {
        address.clone()
    } else {
        let session_address = environment
            .get("DBUS_SESSION_BUS_ADDRESS")
            .ok_or(NoSupportedSession)?;
        let session = connect(session_address)
            .await
            .map_err(|_| NoSupportedSession)?;
        call(
            &session,
            "org.a11y.Bus",
            "/org/a11y/bus",
            "org.a11y.Bus",
            "GetAddress",
            &(),
        )
        .await
        .map_err(|_| NoSupportedSession)?
    };
    let bus = connect(&address).await.map_err(|_| NoSupportedSession)?;
    let id: String = call(&bus, DBUS, DBUS_PATH, DBUS, "GetId", &())
        .await
        .map_err(|_| NoSupportedSession)?;
    if id.is_empty() {
        return Err(NoSupportedSession);
    }
    Ok(AccessibilityBus { address, id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::DirBuilderExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    static NEXT_BUS: AtomicUsize = AtomicUsize::new(0);
    const FIRST: &str = "/org/freedesktop/login1/session/first";
    const SECOND: &str = "/org/freedesktop/login1/session/second";
    const USER: &str = "/org/freedesktop/login1/user/fixture";
    const CALLER: u32 = u32::MAX;
    type Listed = (String, u32, String, String, OwnedObjectPath);

    struct Bus(Child);
    impl Bus {
        fn start(address: &str) -> Self {
            let mut child = Command::new("dbus-daemon")
                .args([
                    "--session",
                    "--nofork",
                    "--print-address=1",
                    &format!("--address={address}"),
                ])
                .stdout(Stdio::piped())
                .spawn()
                .expect("session tests require dbus-daemon");
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(!line.is_empty());
            Self(child)
        }
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[derive(Clone)]
    struct Seat {
        active: bool,
        state: &'static str,
        kind: &'static str,
        display: &'static str,
        locked: Option<bool>,
    }

    struct Fixture {
        selected: Option<&'static str>,
        peer: &'static str,
        first: Seat,
        second: Seat,
        environment: Vec<String>,
    }

    type Shared = Arc<Mutex<Fixture>>;

    struct Logind(Shared, u32);
    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.login1")]
    enum SessionError {
        NoSessionForPID,
    }

    fn path(s: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(s.to_owned()).unwrap()
    }

    #[zbus::interface(name = "org.freedesktop.login1.Manager")]
    impl Logind {
        #[zbus(name = "GetSessionByPID")]
        fn get_session_by_pid(&self, pid: u32) -> Result<OwnedObjectPath, SessionError> {
            let fixture = self.0.lock().unwrap();
            let selected = if pid == CALLER {
                fixture.selected
            } else {
                Some(fixture.peer)
            };
            selected.map(path).ok_or(SessionError::NoSessionForPID)
        }
        fn get_user(&self, uid: u32) -> OwnedObjectPath {
            assert_eq!(uid, self.1);
            path(USER)
        }
        fn list_sessions(&self) -> Vec<Listed> {
            [FIRST, SECOND]
                .into_iter()
                .zip(["first", "second"])
                .map(|(p, id)| (id.into(), self.1, "fixture".into(), "seat0".into(), path(p)))
                .collect()
        }
    }

    struct User;
    #[zbus::interface(name = "org.freedesktop.login1.User")]
    impl User {
        #[zbus(property)]
        fn display(&self) -> (String, OwnedObjectPath) {
            ("first".into(), path(FIRST))
        }
    }

    struct LoginSession(Shared, fn(&Fixture) -> &Seat);
    impl LoginSession {
        fn seat(&self) -> Seat {
            (self.1)(&self.0.lock().unwrap()).clone()
        }
    }
    #[zbus::interface(name = "org.freedesktop.login1.Session")]
    impl LoginSession {
        #[zbus(property)]
        fn active(&self) -> bool {
            self.seat().active
        }
        #[zbus(property)]
        fn state(&self) -> &str {
            self.seat().state
        }
        #[zbus(property, name = "Type")]
        fn kind(&self) -> &str {
            self.seat().kind
        }
        #[zbus(property)]
        fn display(&self) -> &str {
            self.seat().display
        }
        #[zbus(property)]
        fn locked_hint(&self) -> zbus::fdo::Result<bool> {
            self.seat()
                .locked
                .ok_or_else(|| zbus::fdo::Error::Failed("unreadable".into()))
        }
    }

    struct Manager(Shared);
    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl Manager {
        #[zbus(property)]
        fn environment(&self) -> Vec<String> {
            self.0.lock().unwrap().environment.clone()
        }
    }

    struct BusLocator(String);
    #[zbus::interface(name = "org.a11y.Bus")]
    impl BusLocator {
        fn get_address(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> String {
            assert!(header
                .primary()
                .flags()
                .contains(zbus::message::Flags::NO_AUTO_START));
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn selects_and_revalidates_the_session_with_private_bus_doubles() {
        let prefix = format!(
            "ck-desktop-{}-{}",
            std::process::id(),
            NEXT_BUS.fetch_add(1, Ordering::Relaxed)
        );
        let directory = PathBuf::from("/tmp").join(&prefix);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        struct TempDir(PathBuf);
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TempDir(directory);
        let wayland = tokio::net::UnixListener::bind(directory.0.join("wayland-0")).unwrap();
        let accept = tokio::spawn(async move { while wayland.accept().await.is_ok() {} });
        let address = format!("unix:abstract={prefix}-logind");
        let accessibility = format!("unix:abstract={prefix}-a11y");
        let _manager_bus = Bus::start(&address);
        let accessibility_daemon = Bus::start(&accessibility);
        // SAFETY: geteuid has no arguments and returns this process's uid.
        let uid = unsafe { libc::geteuid() };
        let x11_env = vec![
            "DISPLAY=:1".into(),
            "XDG_SESSION_TYPE=x11".into(),
            format!("DBUS_SESSION_BUS_ADDRESS={address}"),
        ];
        let first = Seat {
            active: true,
            state: "active",
            kind: "x11",
            display: ":1",
            locked: Some(false),
        };
        let second = Seat {
            active: false,
            display: ":2",
            ..first.clone()
        };
        let state = Arc::new(Mutex::new(Fixture {
            selected: Some(FIRST),
            peer: SECOND,
            first,
            second,
            environment: x11_env.clone(),
        }));
        let _services = Builder::address(address.as_str())
            .name(LOGIN)
            .name(SYSTEMD)
            .name("org.a11y.Bus")
            .serve_at(LOGIN_PATH, Logind(state.clone(), uid))
            .serve_at("/org/freedesktop/systemd1", Manager(state.clone()))
            .serve_at(FIRST, LoginSession(state.clone(), |f| &f.first))
            .serve_at(SECOND, LoginSession(state.clone(), |f| &f.second))
            .serve_at(USER, User)
            .serve_at("/org/a11y/bus", BusLocator(accessibility.clone()))
            .build()
            .await
            .unwrap();
        let connection = connect(&address).await.unwrap();
        let resolve = |require| {
            resolve_on(
                &connection,
                Some(&connection),
                uid,
                CALLER,
                &directory.0,
                || panic!("the reachable manager's environment must win"),
                require,
            )
        };
        let first_bus = resolve(true).await.unwrap().accessibility.unwrap();
        assert_eq!(first_bus.address, accessibility);
        drop(accessibility_daemon);
        assert_eq!(resolve(true).await, Err(NoSupportedSession));
        assert!(
            resolve(false).await.unwrap().accessibility.is_none(),
            "launch has no a11y dependency"
        );
        let _replacement = Bus::start(&accessibility);
        assert_ne!(
            resolve(true).await.unwrap().accessibility.unwrap().id,
            first_bus.id
        );

        state.lock().unwrap().selected = None;
        assert_eq!(
            resolve(false).await.unwrap().id,
            "first",
            "outside-session service uses User.Display"
        );
        state.lock().unwrap().selected = Some(FIRST);
        state.lock().unwrap().second.active = true;
        assert_eq!(resolve(false).await, Err(NoSupportedSession));
        state.lock().unwrap().second.state = "closing";
        assert_eq!(resolve(false).await.unwrap().id, "first");
        state.lock().unwrap().second.active = false;
        state.lock().unwrap().second.state = "online";
        state.lock().unwrap().environment[0] = "DISPLAY=:2".into();
        assert_eq!(
            resolve(false).await,
            Err(NoSupportedSession),
            "inactive session owns these endpoints"
        );
        state.lock().unwrap().environment = x11_env.clone();
        state.lock().unwrap().environment[1] = "XDG_SESSION_TYPE=wayland".into();
        assert_eq!(resolve(false).await, Err(NoSupportedSession));
        state.lock().unwrap().environment = x11_env.clone();
        state
            .lock()
            .unwrap()
            .environment
            .push("WAYLAND_DISPLAY=wayland-0".into());
        assert_eq!(resolve(false).await, Err(NoSupportedSession));
        state.lock().unwrap().environment = x11_env.clone();
        state.lock().unwrap().first.locked = None;
        assert_eq!(resolve(false).await, Err(NoSupportedSession));
        state.lock().unwrap().first.locked = Some(true);
        assert!(resolve(false).await.unwrap().locked);
        state.lock().unwrap().first.active = false;
        assert_eq!(resolve(false).await, Err(NoSupportedSession));

        {
            let mut f = state.lock().unwrap();
            f.second = Seat {
                active: true,
                state: "active",
                kind: "wayland",
                display: "",
                locked: Some(false),
            };
            f.selected = Some(SECOND);
            f.environment = vec![
                "WAYLAND_DISPLAY=wayland-0".into(),
                "DISPLAY=:3".into(),
                "XDG_SESSION_TYPE=wayland".into(),
                format!("DBUS_SESSION_BUS_ADDRESS={address}"),
            ];
            f.peer = FIRST;
        }
        assert_eq!(resolve(true).await, Err(NoSupportedSession));
        state.lock().unwrap().peer = SECOND;
        let found = resolve(true).await.unwrap();
        assert_eq!(
            (found.id.as_str(), found.kind),
            ("second", SessionKind::Wayland)
        );
        assert_eq!(
            found.environment["DISPLAY"], ":3",
            "Xwayland does not select the X11 route"
        );
        accept.abort();
    }
}
