//! AT-SPI messages on the discovered accessibility bus. Never activates a
//! service, enables accessibility, or uses a well-known name for an app.

use std::collections::HashMap;
use std::future::Future;
use std::time::Instant;

use serde::Serialize;
use zbus::proxy::{CacheProperties, MethodFlags};
use zbus::{connection::Builder, Connection, DynamicType, OwnedObjectPath, OwnedVariant, Proxy};

use crate::session::AccessibilityBus;

const DBUS: &str = "org.freedesktop.DBus";
const REGISTRY: &str = "org.a11y.atspi.Registry";
const ACCESSIBLE: &str = "org.a11y.atspi.Accessible";
const TEXT: &str = "org.a11y.atspi.Text";
const EDITABLE: &str = "org.a11y.atspi.EditableText";
const ACTION: &str = "org.a11y.atspi.Action";
pub const ROOT: &str = "/org/a11y/atspi/accessible/root";

pub type Attributes = HashMap<String, String>;
type WireObject = (String, OwnedObjectPath);

#[cfg(feature = "atspi-test-support")]
pub mod fixture;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Object {
    pub peer: String,
    pub path: String,
}

impl Object {
    fn from_wire((peer, path): WireObject, relative_to: &str) -> Option<Self> {
        if path.as_str() == "/org/a11y/atspi/null" {
            return None;
        }
        Some(Self {
            peer: if peer.is_empty() {
                relative_to.into()
            } else {
                peer
            },
            path: path.to_string(),
        })
    }

    pub fn is_unique(&self) -> bool {
        zbus::names::UniqueName::try_from(self.peer.as_str()).is_ok() && self.peer.starts_with(':')
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Stale,
    Unreadable,
    Timeout,
}

/// Run a synchronous driver's query from a blocking worker so it cannot stall
/// the asynchronous request reader. The deadline covers the entire operation.
pub fn bounded<T>(
    deadline: Instant,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| Error::Unreadable)?;
    runtime.block_on(async move {
        tokio::time::timeout_at(deadline.into(), work)
            .await
            .map_err(|_| Error::Timeout)?
    })
}

#[derive(Clone, Debug)]
pub struct Bus(Connection);

impl Bus {
    pub async fn identify(address: &str) -> Result<AccessibilityBus, Error> {
        let bus = Self(
            Builder::address(address)
                .build()
                .await
                .map_err(|_| Error::Unreadable)?,
        );
        let id: String = bus.daemon("GetId", &()).await?;
        if id.is_empty() {
            return Err(Error::Unreadable);
        }
        Ok(AccessibilityBus {
            address: address.to_owned(),
            id,
        })
    }

    pub async fn connect(selected: &AccessibilityBus) -> Result<Self, Error> {
        let connection = Builder::address(selected.address.as_str())
            .build()
            .await
            .map_err(|_| Error::Unreadable)?;
        let result = Self(connection);
        result.check_id(&selected.id).await?;
        Ok(result)
    }

    pub async fn check_id(&self, expected: &str) -> Result<(), Error> {
        let id: String = self.daemon("GetId", &()).await?;
        if id == expected {
            Ok(())
        } else {
            Err(Error::Stale)
        }
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
        B: Serialize + DynamicType,
        R: for<'d> zbus::wire::DynamicDeserialize<'d>,
    {
        let proxy = zbus::proxy::Builder::<Proxy<'_>>::new(&self.0)
            .destination(destination)
            .path(path)
            .interface(interface)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(|_| Error::Unreadable)?;
        proxy
            .call_with_flags(method, MethodFlags::NO_AUTO_START, body)
            .await
            .map_err(|error| match error {
                zbus::Error::MethodError(ref name, _, _)
                    if matches!(
                        name.as_str(),
                        "org.freedesktop.DBus.Error.NameHasNoOwner"
                            | "org.freedesktop.DBus.Error.ServiceUnknown"
                            | "org.freedesktop.DBus.Error.UnknownObject"
                    ) =>
                {
                    Error::Stale
                }
                _ => Error::Unreadable,
            })?
            .ok_or(Error::Unreadable)
    }

    async fn daemon<B, R>(&self, method: &str, body: &B) -> Result<R, Error>
    where
        B: Serialize + DynamicType,
        R: for<'d> zbus::wire::DynamicDeserialize<'d>,
    {
        self.call(DBUS, "/org/freedesktop/DBus", DBUS, method, body)
            .await
    }

    async fn object<B, R>(
        &self,
        object: &Object,
        interface: &str,
        method: &str,
        body: &B,
    ) -> Result<R, Error>
    where
        B: Serialize + DynamicType,
        R: for<'d> zbus::wire::DynamicDeserialize<'d>,
    {
        if !object.is_unique() {
            return Err(Error::Unreadable);
        }
        self.call(&object.peer, &object.path, interface, method, body)
            .await
    }

    async fn property<T: TryFrom<OwnedVariant>>(
        &self,
        object: &Object,
        interface: &str,
        name: &str,
    ) -> Result<T, Error> {
        let value: OwnedVariant = self
            .object(
                object,
                "org.freedesktop.DBus.Properties",
                "Get",
                &(interface, name),
            )
            .await?;
        T::try_from(value).map_err(|_| Error::Unreadable)
    }

    pub async fn applications(&self) -> Result<Vec<Object>, Error> {
        let roots: Vec<WireObject> = self
            .call(REGISTRY, ROOT, ACCESSIBLE, "GetChildren", &())
            .await?;
        Ok(roots
            .into_iter()
            .filter_map(|root| Object::from_wire(root, ""))
            .filter(|root| root.is_unique() && root.path == ROOT)
            .collect())
    }

    pub async fn pid(&self, object: &Object) -> Result<u32, Error> {
        if !object.is_unique() {
            return Err(Error::Unreadable);
        }
        let mut credentials: HashMap<String, OwnedVariant> = match self
            .daemon("GetConnectionCredentials", &(&object.peer,))
            .await
        {
            Ok(credentials) => credentials,
            Err(error) => {
                // Daemons can use different error names for missing
                // credentials. Only absence of the unique name proves
                // that the bound peer is gone.
                let owned: bool = self.daemon("NameHasOwner", &(&object.peer,)).await?;
                return Err(if owned { error } else { Error::Stale });
            }
        };
        credentials
            .remove("ProcessID")
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid != 0)
            .ok_or(Error::Unreadable)
    }

    pub async fn children(&self, object: &Object) -> Result<Vec<Option<Object>>, Error> {
        let children: Vec<WireObject> = self.object(object, ACCESSIBLE, "GetChildren", &()).await?;
        Ok(children
            .into_iter()
            .map(|child| Object::from_wire(child, &object.peer))
            .collect())
    }

    pub async fn parent(&self, object: &Object) -> Result<Option<Object>, Error> {
        let value: OwnedVariant = self.property(object, ACCESSIBLE, "Parent").await?;
        let value = WireObject::try_from(value).map_err(|_| Error::Unreadable)?;
        Ok(Object::from_wire(value, &object.peer))
    }

    pub async fn name(&self, object: &Object) -> Result<String, Error> {
        self.property(object, ACCESSIBLE, "Name").await
    }

    pub async fn role(&self, object: &Object) -> Result<(u32, String), Error> {
        let raw = self.object(object, ACCESSIBLE, "GetRole", &()).await?;
        let name: String = self.object(object, ACCESSIBLE, "GetRoleName", &()).await?;
        if raw == 0 || name.is_empty() {
            return Err(Error::Unreadable);
        }
        Ok((raw, name))
    }

    pub async fn attributes(&self, object: &Object) -> Result<Attributes, Error> {
        self.object(object, ACCESSIBLE, "GetAttributes", &()).await
    }

    pub async fn state(&self, object: &Object) -> Result<Vec<u32>, Error> {
        self.object(object, ACCESSIBLE, "GetState", &()).await
    }

    pub async fn interfaces(&self, object: &Object) -> Result<Vec<String>, Error> {
        self.object(object, ACCESSIBLE, "GetInterfaces", &()).await
    }

    pub async fn action_names(&self, object: &Object) -> Result<Vec<String>, Error> {
        let count: i32 = self.property(object, ACTION, "NActions").await?;
        if !(0..=64).contains(&count) {
            return Err(Error::Unreadable);
        }
        // GTK localizes the bulk GetActions labels and may omit actions from
        // that list. GetName reads the name at the index used by DoAction.
        let mut names = Vec::new();
        for index in 0..count {
            names.push(self.object(object, ACTION, "GetName", &(index,)).await?);
        }
        Ok(names)
    }

    pub async fn action(&self, object: &Object, index: i32) -> Result<bool, Error> {
        self.object(object, ACTION, "DoAction", &(index,)).await
    }

    pub async fn text(&self, object: &Object) -> Result<String, Error> {
        // GTK's editable-text reader clamps a negative end offset to zero.
        // Ask for the actual character range on the same accessible object.
        let end: i32 = self.property(object, TEXT, "CharacterCount").await?;
        let length = usize::try_from(end).map_err(|_| Error::Unreadable)?;
        let text: String = self.object(object, TEXT, "GetText", &(0_i32, end)).await?;
        let current_end: i32 = self.property(object, TEXT, "CharacterCount").await?;
        if current_end != end || text.chars().count() != length {
            // A field that grew during the read might have returned only the
            // old prefix. Do not use a partial string to confirm a write.
            return Err(Error::Unreadable);
        }
        Ok(text)
    }

    pub async fn selection(&self, object: &Object) -> Result<(i32, i32), Error> {
        let count: i32 = self.object(object, TEXT, "GetNSelections", &()).await?;
        match count {
            0 => {
                let caret: i32 = self.property(object, TEXT, "CaretOffset").await?;
                Ok((caret, caret))
            }
            1 => self.object(object, TEXT, "GetSelection", &(0_i32,)).await,
            _ => Err(Error::Unreadable),
        }
    }

    pub async fn set_text(&self, object: &Object, text: &str) -> Result<bool, Error> {
        self.object(object, EDITABLE, "SetTextContents", &(text,))
            .await
    }
}
