//! Read-only EDS D-Bus transport. No EDS, GLib or libdbus library is loaded.

use std::{collections::HashMap, path::Path, sync::Arc};

use serde::Serialize;
use zbus::{proxy::MethodFlags, Connection, OwnedObjectPath, OwnedVariant};

pub const BUS_NAMES: [&str; 3] = [
    "org.gnome.evolution.dataserver.Sources5",
    "org.gnome.evolution.dataserver.Calendar8",
    "org.gnome.evolution.dataserver.AddressBook10",
];
const ROOT: &str = "/org/gnome/evolution/dataserver";
const SOURCE: &str = "org.gnome.evolution.dataserver.Source";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Calendar,
    TaskList,
    AddressBook,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    pub uid: String,
    pub label: String,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Missing,
    NotFound,
    Failed,
}

fn bus_error(error: zbus::Error) -> Error {
    if let zbus::Error::FDO(error) = &error {
        if matches!(
            error.as_ref(),
            zbus::fdo::Error::NameHasNoOwner(_) | zbus::fdo::Error::ServiceUnknown(_)
        ) {
            return Error::Missing;
        }
    }
    if let zbus::Error::MethodError(name, ..) = &error {
        return match name.as_str() {
            "org.freedesktop.DBus.Error.NameHasNoOwner"
            | "org.freedesktop.DBus.Error.ServiceUnknown" => Error::Missing,
            "org.gnome.evolution.dataserver.Calendar.ObjectNotFound"
            | "org.gnome.evolution.dataserver.AddressBook.ContactNotFound" => Error::NotFound,
            _ => Error::Failed,
        };
    }
    Error::Failed
}

/// A request-local connection. The callback is checked before every new call,
/// including the individual steps of opening a source and fetching its zones.
pub struct Session {
    connection: Connection,
    stopped: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl Session {
    pub async fn connect(stopped: Arc<dyn Fn() -> bool + Send + Sync>) -> Result<Self, Error> {
        if stopped() {
            return Err(Error::Failed);
        }
        // Connecting to a session bus does not ask it to start any EDS service.
        let connection = Connection::session().await.map_err(|_| Error::Missing)?;
        Ok(Self {
            connection,
            stopped,
        })
    }

    async fn call<B, R>(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> Result<R, Error>
    where
        B: Serialize + zbus::DynamicType,
        R: for<'d> zbus::wire::DynamicDeserialize<'d>,
    {
        if (self.stopped)() {
            return Err(Error::Failed);
        }
        // No property cache: creating a proxy must not send implicit GetAll or
        // owner-tracking calls without the no-activation flag.
        let proxy = zbus::proxy::Builder::<zbus::Proxy<'_>>::new(&self.connection)
            .destination(destination)
            .path(path)
            .interface(interface)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(bus_error)?;
        proxy
            .call_with_flags(method, MethodFlags::NO_AUTO_START, body)
            .await
            .map_err(bus_error)?
            .ok_or(Error::Failed)
    }

    async fn owner(&self, name: &str) -> Result<String, Error> {
        self.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
            &(name,),
        )
        .await
    }

    pub async fn owned_names(&self) -> Result<Vec<String>, Error> {
        self.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "ListNames",
            &(),
        )
        .await
    }

    pub async fn sources(&self) -> Result<Vec<Source>, Error> {
        let owner = self.owner(BUS_NAMES[0]).await?;
        // Source properties: evolution-data-server 3.62.1,
        // src/private/org.gnome.evolution.dataserver.Source.xml. Enumeration
        // uses the standard ObjectManager at the source-manager singleton.
        type Objects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedVariant>>>;
        let objects: Objects = self
            .call(
                &owner,
                &format!("{ROOT}/SourceManager"),
                "org.freedesktop.DBus.ObjectManager",
                "GetManagedObjects",
                &(),
            )
            .await?;
        let mut sources = Vec::new();
        for interfaces in objects.into_values() {
            let Some(properties) = interfaces.get(SOURCE) else {
                continue;
            };
            let uid = properties
                .get("UID")
                .and_then(|v| <&str>::try_from(v).ok())
                .ok_or(Error::Failed)?;
            let data = properties
                .get("Data")
                .and_then(|v| <&str>::try_from(v).ok())
                .ok_or(Error::Failed)?;
            sources.extend(parse_source(uid, data)?);
        }
        sources.sort_by(|a, b| a.uid.cmp(&b.uid));
        Ok(sources)
    }

    pub async fn open_client(&self, source: &Source) -> Result<Client, Error> {
        let (factory, factory_interface, method) = match source.kind {
            Kind::Calendar => (1, "CalendarFactory", "OpenCalendar"),
            Kind::TaskList => (1, "CalendarFactory", "OpenTaskList"),
            Kind::AddressBook => (2, "AddressBookFactory", "OpenAddressBook"),
        };
        let owner = self.owner(BUS_NAMES[factory]).await?;
        // evolution-data-server 3.62.1, src/private/
        // org.gnome.evolution.dataserver.{CalendarFactory,AddressBookFactory}.xml:
        // one source UID in; backend object path and bus name (both strings) out.
        let (path, name): (String, String) = self
            .call(
                &owner,
                &format!("{ROOT}/{factory_interface}"),
                &format!("org.gnome.evolution.dataserver.{factory_interface}"),
                method,
                &(&source.uid,),
            )
            .await?;
        // Pin the returned backend's unique owner as well. A factory dying or
        // losing its name between checks must never cause service activation.
        let owner = self.owner(&name).await?;
        let client = Client {
            session: Self {
                connection: self.connection.clone(),
                stopped: self.stopped.clone(),
            },
            source: source.clone(),
            owner,
            path,
        };
        let _: Vec<String> = client.call("Open", &()).await?;
        Ok(client)
    }
}

pub struct Client {
    session: Session,
    source: Source,
    owner: String,
    path: String,
}

impl Client {
    pub fn source_uid(&self) -> &str {
        &self.source.uid
    }

    async fn call<B, R>(&self, method: &str, body: &B) -> Result<R, Error>
    where
        B: Serialize + zbus::DynamicType,
        R: for<'d> zbus::wire::DynamicDeserialize<'d>,
    {
        // evolution-data-server 3.62.1, src/private/
        // org.gnome.evolution.dataserver.{Calendar,AddressBook}.xml.
        let interface = if self.source.kind == Kind::AddressBook {
            "AddressBook"
        } else {
            "Calendar"
        };
        self.session
            .call(
                &self.owner,
                &self.path,
                &format!("org.gnome.evolution.dataserver.{interface}"),
                method,
                body,
            )
            .await
    }

    pub async fn objects(&self) -> Result<Vec<String>, Error> {
        let (method, query) = if self.source.kind == Kind::AddressBook {
            (
                "GetContactList",
                "(contains \"x-evolution-any-field\" \"\")",
            )
        } else {
            ("GetObjectList", "#t")
        };
        self.call(method, &(query,)).await
    }

    pub async fn object(&self, uid: &str) -> Result<Option<String>, Error> {
        let result = if self.source.kind == Kind::AddressBook {
            self.call("GetContact", &(uid,)).await
        } else {
            // Empty recurrence id requests the complete UID, not only its master.
            self.call("GetObject", &(uid, "")).await
        };
        match result {
            Ok(value) => Ok(Some(value)),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn time_zone(&self, id: &str) -> Result<Option<String>, Error> {
        match self.call("GetTimezone", &(id,)).await {
            Ok(value) => Ok(Some(value)),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn close(&self) -> Result<(), Error> {
        self.call("Close", &()).await
    }
}

fn parse_source(uid: &str, data: &str) -> Result<Vec<Source>, Error> {
    let mut section = "";
    let mut label = None;
    let mut enabled = true;
    let mut kinds = Vec::new();
    for line in data.lines().map(str::trim) {
        if line.starts_with(['#', ';']) || line.is_empty() {
            continue;
        }
        if let Some(group) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = group;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::Failed);
        };
        match (section, key.trim()) {
            ("Data Source", "DisplayName") => label = Some(key_string(value)?),
            ("Data Source", "Enabled") => enabled = value.trim() == "true",
            ("Calendar", "BackendName") if !value.trim().is_empty() => kinds.push(Kind::Calendar),
            ("Task List", "BackendName") if !value.trim().is_empty() => kinds.push(Kind::TaskList),
            ("Address Book", "BackendName") if !value.trim().is_empty() => {
                kinds.push(Kind::AddressBook)
            }
            _ => {}
        }
    }
    if !enabled {
        return Ok(vec![]);
    }
    let label = label.unwrap_or_else(|| uid.to_owned());
    Ok(kinds
        .into_iter()
        .map(|kind| Source {
            uid: uid.to_owned(),
            label: label.clone(),
            kind,
        })
        .collect())
}

fn key_string(value: &str) -> Result<String, Error> {
    let mut result = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        result.push(if c != '\\' {
            c
        } else {
            match chars.next() {
                Some('s') => ' ',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some('\\') => '\\',
                _ => return Err(Error::Failed),
            }
        });
    }
    Ok(result)
}

/// Read the configured IANA name, not the current numeric offset or TZ override.
/// No UTC default is supplied. The calendar/reminder projector in
/// cerebellum-ability validates the name and refuses reads without a known zone.
pub fn system_iana_zone() -> Option<String> {
    let localtime = std::fs::canonicalize("/etc/localtime").ok();
    zone_name(localtime.as_deref()).or_else(|| {
        let name = std::fs::read_to_string("/etc/timezone").ok()?;
        let name = name.trim();
        valid_zone_name(name).then(|| name.to_owned())
    })
}

fn zone_name(path: Option<&Path>) -> Option<String> {
    let value = path?.to_str()?.split_once("/zoneinfo/")?.1;
    let value = value
        .strip_prefix("posix/")
        .or_else(|| value.strip_prefix("right/"))
        .unwrap_or(value);
    valid_zone_name(value).then(|| value.to_owned())
}

fn valid_zone_name(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|s| {
            !matches!(s, "" | "." | "..")
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_+-".contains(&b))
        })
}

#[cfg(test)]
mod tests;
