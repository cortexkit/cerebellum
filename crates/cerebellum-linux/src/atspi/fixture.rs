//! Private test services for the concrete protocol. All app identity comes
//! from the bus daemon, just as it does with toolkit peers.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use zbus::fdo;

use super::*;

pub struct TestAtspiBus {
    daemon: Child,
    pub selected: AccessibilityBus,
    registry: Arc<Mutex<Vec<WireObject>>>,
    _connection: Connection,
}

impl Drop for TestAtspiBus {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

struct Registry(Arc<Mutex<Vec<WireObject>>>);

#[zbus::interface(name = "org.a11y.atspi.Accessible")]
impl Registry {
    fn get_children(&self) -> Vec<WireObject> {
        self.0.lock().unwrap().clone()
    }
}

impl TestAtspiBus {
    pub async fn start() -> Self {
        Self::start_at(None).await
    }

    pub async fn start_at(socket: Option<&str>) -> Self {
        let mut command = Command::new("dbus-daemon");
        command.args(["--session", "--nofork", "--print-address=1"]);
        if let Some(socket) = socket {
            command.arg(format!("--address={socket}"));
        }
        let mut daemon = command
            .stdout(Stdio::piped())
            .spawn()
            .expect("start a private dbus-daemon");
        let mut address = String::new();
        BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let address = socket.unwrap_or_else(|| address.trim());
        let registry = Arc::default();
        let connection = Builder::address(address)
            .name(REGISTRY)
            .serve_at(ROOT, Registry(Arc::clone(&registry)))
            .build()
            .await
            .unwrap();
        let selected = Bus::identify(address).await.unwrap();
        Self {
            daemon,
            selected,
            registry,
            _connection: connection,
        }
    }

    pub async fn app(&self, name: &str) -> TestAtspiApp {
        let effects = Arc::new(Effects::default());
        let mut builder = Builder::address(self.selected.address.as_str());
        for node in [
            Node::new(ROOT, "", name, 75, "application", &[WINDOW]),
            Node::new(
                WINDOW,
                ROOT,
                "Editor window",
                23,
                "frame",
                &[
                    ENTRY,
                    BUTTON,
                    PASSWORD,
                    PAYMENT,
                    UNREADABLE,
                    UNREADABLE_ROLE,
                    LABEL,
                ],
            ),
            Node::new(ENTRY, WINDOW, "Message", 79, "entry", &[]),
            Node::new(BUTTON, WINDOW, "Apply", 43, "push button", &[]),
            Node::new(PASSWORD, WINDOW, "Password", 40, "password text", &[]),
            Node::new(PAYMENT, WINDOW, "Payment", 79, "entry", &[PAYMENT_CHILD]),
            Node::new(PAYMENT_CHILD, PAYMENT, "Card child", 79, "entry", &[]),
            Node::new(UNREADABLE, WINDOW, "Unknown field", 79, "entry", &[]),
            Node::new(UNREADABLE_ROLE, WINDOW, "Unknown role", 79, "entry", &[]),
            Node::new(LABEL, WINDOW, "Awaiting", 29, "label", &[]),
        ] {
            let path = node.path;
            let object = Accessible {
                node,
                effects: effects.clone(),
            };
            builder = builder.serve_at(path, object);
            if matches!(
                path,
                ENTRY | PASSWORD | PAYMENT | PAYMENT_CHILD | UNREADABLE | UNREADABLE_ROLE
            ) {
                builder = builder
                    .serve_at(path, Editable(effects.clone()))
                    .serve_at(path, Text(effects.clone()));
            }
            if matches!(
                path,
                BUTTON | PASSWORD | PAYMENT | PAYMENT_CHILD | UNREADABLE | UNREADABLE_ROLE
            ) {
                builder = builder.serve_at(path, Action(effects.clone()));
            }
        }
        let connection = builder.build().await.unwrap();
        let own = connection.unique_name().unwrap().as_str().to_owned();
        self.registry
            .lock()
            .unwrap()
            .push((own.clone(), path(ROOT)));
        TestAtspiApp {
            connection,
            own,
            registry: Arc::clone(&self.registry),
            effects,
        }
    }
}

const WINDOW: &str = "/fixture/window";
const ENTRY: &str = "/fixture/entry";
const BUTTON: &str = "/fixture/button";
const PASSWORD: &str = "/fixture/password";
const PAYMENT: &str = "/fixture/payment";
const PAYMENT_CHILD: &str = "/fixture/card_child";
const UNREADABLE: &str = "/fixture/unreadable";
const UNREADABLE_ROLE: &str = "/fixture/unreadable_role";
const LABEL: &str = "/fixture/label";

fn path(path: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(path).unwrap()
}

#[derive(Default)]
pub struct Effects {
    pub posts: AtomicUsize,
    pub polls: AtomicUsize,
    pub ready: AtomicBool,
    pub text: Mutex<String>,
    pub entry_payment: AtomicBool,
    pub unreadable_role: AtomicBool,
}

pub struct TestAtspiApp {
    connection: Connection,
    own: String,
    registry: Arc<Mutex<Vec<WireObject>>>,
    pub effects: Arc<Effects>,
}

impl TestAtspiApp {
    pub fn peer(&self) -> &str {
        &self.own
    }

    pub async fn close(self) {
        self.registry
            .lock()
            .unwrap()
            .retain(|(peer, _)| peer != &self.own);
        self.connection.close().await.unwrap();
    }
}

struct Node {
    path: &'static str,
    parent: &'static str,
    name: String,
    role: u32,
    role_name: &'static str,
    children: Vec<&'static str>,
}

impl Node {
    fn new(
        path: &'static str,
        parent: &'static str,
        name: &str,
        role: u32,
        role_name: &'static str,
        children: &[&'static str],
    ) -> Self {
        Self {
            path,
            parent,
            name: name.to_owned(),
            role,
            role_name,
            children: children.to_vec(),
        }
    }
}

struct Accessible {
    node: Node,
    effects: Arc<Effects>,
}

#[zbus::interface(name = "org.a11y.atspi.Accessible")]
impl Accessible {
    #[zbus(property)]
    fn name(&self) -> String {
        if self.node.path == LABEL {
            self.effects.polls.fetch_add(1, Ordering::SeqCst);
            if self.effects.ready.load(Ordering::SeqCst) {
                return "Ready".into();
            }
        }
        self.node.name.clone()
    }

    #[zbus(property)]
    fn parent(&self) -> WireObject {
        let parent = if self.node.parent.is_empty() {
            "/org/a11y/atspi/null"
        } else {
            self.node.parent
        };
        (String::new(), path(parent))
    }

    fn get_children(&self) -> Vec<WireObject> {
        self.node
            .children
            .iter()
            .map(|child| (String::new(), path(child)))
            .collect()
    }

    fn get_role(&self) -> u32 {
        if self.node.path == UNREADABLE_ROLE && self.effects.unreadable_role.load(Ordering::SeqCst)
        {
            0
        } else {
            self.node.role
        }
    }
    fn get_role_name(&self) -> &str {
        self.node.role_name
    }

    fn get_attributes(&self) -> fdo::Result<Attributes> {
        match self.node.path {
            UNREADABLE => Err(fdo::Error::Failed("attribute fixture refusal".into())),
            PAYMENT => Ok(Attributes::from([(
                "autocomplete".into(),
                "shipping CC-number".into(),
            )])),
            ENTRY if self.effects.entry_payment.load(Ordering::SeqCst) => {
                Ok(Attributes::from([("autocomplete".into(), "cc-csc".into())]))
            }
            _ => Ok(Attributes::new()),
        }
    }

    fn get_state(&self) -> Vec<u32> {
        let mut state = (1 << 8) | (1 << 24) | (1 << 25);
        if matches!(
            self.node.path,
            ENTRY | PASSWORD | PAYMENT | PAYMENT_CHILD | UNREADABLE | UNREADABLE_ROLE
        ) {
            state |= 1 << 7;
        }
        if self.node.path == ENTRY {
            state |= 1 << 12;
        }
        vec![state, 0]
    }

    fn get_interfaces(&self) -> Vec<&str> {
        match self.node.path {
            BUTTON => vec![ACTION],
            ENTRY => vec![TEXT, EDITABLE],
            PASSWORD | PAYMENT | PAYMENT_CHILD | UNREADABLE | UNREADABLE_ROLE => {
                vec![ACTION, TEXT, EDITABLE]
            }
            _ => vec![ACCESSIBLE],
        }
    }
}

struct Action(Arc<Effects>);
#[zbus::interface(name = "org.a11y.atspi.Action")]
impl Action {
    fn get_actions(&self) -> Vec<(&str, &str, &str)> {
        vec![("click", "", "")]
    }
    fn do_action(&self, index: i32) -> bool {
        if index != 0 {
            return false;
        }
        self.0.posts.fetch_add(1, Ordering::SeqCst);
        self.0.ready.store(true, Ordering::SeqCst);
        true
    }
}

struct Editable(Arc<Effects>);
#[zbus::interface(name = "org.a11y.atspi.EditableText")]
impl Editable {
    fn set_text_contents(&self, contents: &str) -> bool {
        self.0.posts.fetch_add(1, Ordering::SeqCst);
        *self.0.text.lock().unwrap() = contents.into();
        true
    }
}

struct Text(Arc<Effects>);
#[zbus::interface(name = "org.a11y.atspi.Text")]
impl Text {
    #[zbus(property)]
    fn caret_offset(&self) -> i32 {
        i32::try_from(self.0.text.lock().unwrap().chars().count()).unwrap()
    }
    fn get_n_selections(&self) -> i32 {
        0
    }
    fn get_text(&self, _start: i32, _end: i32) -> String {
        self.0.text.lock().unwrap().clone()
    }
}
