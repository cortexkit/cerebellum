use super::*;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Bus {
    child: Child,
    address: String,
    directory: std::path::PathBuf,
}

impl Bus {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ck-eds-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let services = directory.join("services");
        std::fs::create_dir(&services).unwrap();
        for name in BUS_NAMES {
            std::fs::write(
                services.join(format!("{name}.service")),
                format!(
                    "[D-BUS Service]\nName={name}\nExec=/usr/bin/touch {}\n",
                    directory.join("activated").display()
                ),
            )
            .unwrap();
        }
        let config = directory.join("bus.conf");
        std::fs::write(&config, format!(
            "<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth><servicedir>{}</servicedir><policy context=\"default\"><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>", services.display()
        )).unwrap();
        let mut child = Command::new("dbus-daemon")
            .arg("--nofork")
            .arg("--print-address=1")
            .arg(format!("--config-file={}", config.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("EDS transport tests require dbus-daemon");
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        assert!(!address.trim().is_empty());
        Self {
            child,
            address: address.trim().to_owned(),
            directory,
        }
    }

    async fn connection(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .build()
            .await
            .unwrap()
    }

    async fn session(&self) -> Session {
        Session {
            connection: self.connection().await,
            stopped: Arc::new(|| false),
        }
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn no_activation(header: &zbus::message::Header<'_>) {
    assert!(header
        .primary()
        .flags()
        .contains(zbus::message::Flags::NO_AUTO_START));
    assert!(header.destination().unwrap().as_str().starts_with(':'));
}

#[tokio::test]
async fn eds_activatable_but_unowned_services_are_never_started_even_after_owner_loss() {
    let bus = Bus::new();
    let session = bus.session().await;
    let activatable: Vec<String> = session
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "ListActivatableNames",
            &(),
        )
        .await
        .unwrap();
    for name in BUS_NAMES {
        assert!(activatable.iter().any(|n| n == name));
        assert!(!session
            .owned_names()
            .await
            .unwrap()
            .iter()
            .any(|n| n == name));
        assert_eq!(session.owner(name).await, Err(Error::Missing));
        // Bypass owner lookup to model a service disappearing immediately after
        // a check. The common call path still has to prohibit activation.
        let result: Result<(), _> = session
            .call(name, "/unused", "org.example.Unused", "Ping", &())
            .await;
        assert_eq!(result, Err(Error::Missing));
    }
    assert_eq!(session.sources().await, Err(Error::Missing));
    assert!(!bus.directory.join("activated").exists());
    let mut stopped = session;
    stopped.stopped = Arc::new(|| true);
    assert_eq!(stopped.owned_names().await, Err(Error::Failed));
}

type Objects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedVariant>>>;

struct Registry;
#[zbus::interface(name = "org.freedesktop.DBus.ObjectManager")]
impl Registry {
    fn get_managed_objects(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> Objects {
        no_activation(&header);
        [("cal", "Calendar"), ("tasks", "Task List"), ("book", "Address Book")].into_iter().map(|(uid, extension)| {
            let data = format!("[Data Source]\nDisplayName=CortexKit scratch {uid}\nEnabled=true\n[{extension}]\nBackendName=local\n");
            let properties = HashMap::from([
                ("UID".into(), OwnedVariant::from(zbus::Str::from(uid))),
                ("Data".into(), OwnedVariant::from(zbus::Str::from(data))),
            ]);
            (OwnedObjectPath::try_from(format!("{ROOT}/SourceManager/{uid}")).unwrap(), HashMap::from([(SOURCE.into(), properties)]))
        }).collect()
    }
}

struct Factory {
    owner: String,
    opened: Arc<AtomicUsize>,
}
#[zbus::interface(name = "org.gnome.evolution.dataserver.CalendarFactory")]
impl Factory {
    fn open_calendar(
        &self,
        uid: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (String, String) {
        no_activation(&header);
        assert_eq!(uid, "cal");
        self.opened.fetch_add(1, Ordering::Relaxed);
        ("/calendar".into(), self.owner.clone())
    }
    fn open_task_list(
        &self,
        uid: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (String, String) {
        no_activation(&header);
        assert_eq!(uid, "tasks");
        self.opened.fetch_add(1, Ordering::Relaxed);
        ("/tasks".into(), self.owner.clone())
    }
}

struct BookFactory {
    owner: String,
    opened: Arc<AtomicUsize>,
}
#[zbus::interface(name = "org.gnome.evolution.dataserver.AddressBookFactory")]
impl BookFactory {
    fn open_address_book(
        &self,
        uid: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (String, String) {
        no_activation(&header);
        assert_eq!(uid, "book");
        self.opened.fetch_add(1, Ordering::Relaxed);
        ("/book".into(), self.owner.clone())
    }
}

struct Calendar {
    component: &'static str,
}
#[zbus::interface(name = "org.gnome.evolution.dataserver.Calendar")]
impl Calendar {
    fn open(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> Vec<String> {
        no_activation(&header);
        vec![]
    }
    fn close(&self, #[zbus(header)] header: zbus::message::Header<'_>) {
        no_activation(&header);
    }
    fn get_object_list(
        &self,
        query: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Vec<String> {
        no_activation(&header);
        assert_eq!(query, "#t");
        vec![self.component.into()]
    }
    fn get_object(
        &self,
        uid: &str,
        rid: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> String {
        no_activation(&header);
        assert_eq!(uid, "item");
        assert_eq!(rid, "");
        self.component.into()
    }
    fn get_timezone(&self, id: &str, #[zbus(header)] header: zbus::message::Header<'_>) -> String {
        no_activation(&header);
        assert_eq!(id, "Private/Zone");
        "BEGIN:VTIMEZONE\nTZID:Private/Zone\nEND:VTIMEZONE".into()
    }
}

struct Book;
#[zbus::interface(name = "org.gnome.evolution.dataserver.AddressBook")]
impl Book {
    fn open(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> Vec<String> {
        no_activation(&header);
        vec![]
    }
    fn close(&self, #[zbus(header)] header: zbus::message::Header<'_>) {
        no_activation(&header);
    }
    fn get_contact_list(
        &self,
        query: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Vec<String> {
        no_activation(&header);
        assert_eq!(query, "(contains \"x-evolution-any-field\" \"\")");
        vec!["BEGIN:VCARD\nUID:item\nFN:Scratch\nEND:VCARD".into()]
    }
    fn get_contact(&self, uid: &str, #[zbus(header)] header: zbus::message::Header<'_>) -> String {
        no_activation(&header);
        assert_eq!(uid, "item");
        "BEGIN:VCARD\nUID:item\nFN:Scratch\nEND:VCARD".into()
    }
}

#[tokio::test]
async fn eds_native_wire_reads_one_source_per_client_without_implicit_or_activating_calls() {
    let bus = Bus::new();
    let server = bus.connection().await;
    let opened = Arc::new(AtomicUsize::new(0));
    for name in BUS_NAMES {
        server.request_name(name).await.unwrap();
    }
    let owner = server.unique_name().unwrap().to_string();
    server
        .object_server()
        .at(format!("{ROOT}/SourceManager"), Registry)
        .await
        .unwrap();
    server
        .object_server()
        .at(
            format!("{ROOT}/CalendarFactory"),
            Factory {
                owner: owner.clone(),
                opened: opened.clone(),
            },
        )
        .await
        .unwrap();
    server
        .object_server()
        .at(
            format!("{ROOT}/AddressBookFactory"),
            BookFactory {
                owner,
                opened: opened.clone(),
            },
        )
        .await
        .unwrap();
    server
        .object_server()
        .at(
            "/calendar",
            Calendar {
                component: "BEGIN:VEVENT\nUID:item\nDTSTART:20250101T000000Z\nEND:VEVENT",
            },
        )
        .await
        .unwrap();
    server
        .object_server()
        .at(
            "/tasks",
            Calendar {
                component: "BEGIN:VTODO\nUID:item\nDUE:20250101\nEND:VTODO",
            },
        )
        .await
        .unwrap();
    server.object_server().at("/book", Book).await.unwrap();
    let session = bus.session().await;
    let sources = session.sources().await.unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(
        opened.load(Ordering::Relaxed),
        0,
        "enumeration must open no clients"
    );
    for (index, source) in sources.iter().enumerate() {
        let client = session.open_client(source).await.unwrap();
        assert_eq!(opened.load(Ordering::Relaxed), index + 1);
        assert_eq!(client.source_uid(), source.uid);
        let objects = client.objects().await.unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(
            client.object("item").await.unwrap(),
            Some(objects[0].clone())
        );
        if source.kind != Kind::AddressBook {
            assert!(client
                .time_zone("Private/Zone")
                .await
                .unwrap()
                .unwrap()
                .contains("VTIMEZONE"));
        }
        client.close().await.unwrap();
    }
    assert!(!bus.directory.join("activated").exists());
}

#[test]
fn eds_source_key_files_and_system_zone_names_are_not_guessed() {
    let source = parse_source(
        "uid",
        "[Data Source]\nDisplayName=A\\sB\\nC\nEnabled=true\n[Task List]\nBackendName=local\n",
    )
    .unwrap();
    assert_eq!(source[0].kind, Kind::TaskList);
    assert_eq!(source[0].label, "A B\nC");
    assert!(parse_source(
        "uid",
        "[Data Source]\nEnabled=false\n[Calendar]\nBackendName=local"
    )
    .unwrap()
    .is_empty());
    assert!(parse_source("uid", "[Memo List]\nBackendName=local")
        .unwrap()
        .is_empty());
    assert_eq!(
        zone_name(Some(Path::new("/usr/share/zoneinfo/America/New_York"))),
        Some("America/New_York".into())
    );
    assert_eq!(
        zone_name(Some(Path::new("/usr/share/zoneinfo/right/Europe/Berlin"))),
        Some("Europe/Berlin".into())
    );
    assert_eq!(zone_name(Some(Path::new("/etc/localtime"))), None);
    assert_eq!(zone_name(None), None);
    assert!(!valid_zone_name("../UTC"));
}
