//! The Linux transport owns D-Bus; this adapter owns the ability vocabulary.

use std::{future::Future, sync::Arc};

use cerebellum_ability::ical;
use cerebellum_linux::eds as dbus;
use tokio::runtime::Handle;

use super::{Bus, BusFactory, Client, Kind, Refusal, Source, TerminalArbiter};

pub(super) struct Factory;

fn bridge<T>(runtime: &Handle, future: impl Future<Output = T>) -> T {
    runtime.block_on(future)
}

fn refusal(error: dbus::Error) -> Refusal {
    match error {
        dbus::Error::Missing => Refusal::Unavailable("data_service_missing"),
        dbus::Error::NotFound | dbus::Error::Failed => Refusal::SourceFailed,
    }
}

impl BusFactory for Factory {
    fn connect(&self) -> Result<Box<dyn Bus>, Refusal> {
        self.connect_for_call(None)
    }

    fn connect_for_call(
        &self,
        gate: Option<Arc<TerminalArbiter>>,
    ) -> Result<Box<dyn Bus>, Refusal> {
        let runtime = Handle::try_current().map_err(|_| Refusal::SourceFailed)?;
        // The ability runner invokes this factory only from spawn_blocking.
        // Handle::block_on drives zbus on the existing Tokio runtime; it neither
        // creates a second runtime nor blocks a runtime worker thread.
        let session = bridge(
            &runtime,
            dbus::Session::connect(Arc::new(move || {
                gate.as_ref().is_some_and(|g| g.gate.stopped())
            })),
        )
        .map_err(refusal)?;
        Ok(Box::new(NativeBus { session, runtime }))
    }
}

struct NativeBus {
    session: dbus::Session,
    runtime: Handle,
}

fn kind(kind: Kind) -> dbus::Kind {
    match kind {
        Kind::Calendar => dbus::Kind::Calendar,
        Kind::TaskList => dbus::Kind::TaskList,
        Kind::AddressBook => dbus::Kind::AddressBook,
    }
}

impl Bus for NativeBus {
    fn owned_names(&self) -> Result<Vec<String>, Refusal> {
        self.runtime
            .block_on(self.session.owned_names())
            .map_err(refusal)
    }
    fn system_iana_zone(&self) -> Option<String> {
        dbus::system_iana_zone()
    }
    fn sources(&mut self) -> Result<Vec<Source>, Refusal> {
        self.runtime
            .block_on(self.session.sources())
            .map_err(refusal)
            .map(|sources| {
                sources
                    .into_iter()
                    .map(|s| Source {
                        uid: s.uid,
                        label: s.label,
                        kind: match s.kind {
                            dbus::Kind::Calendar => Kind::Calendar,
                            dbus::Kind::TaskList => Kind::TaskList,
                            dbus::Kind::AddressBook => Kind::AddressBook,
                        },
                    })
                    .collect()
            })
    }
    fn open_client(&mut self, source: &Source) -> Result<Box<dyn Client>, Refusal> {
        let client = self
            .runtime
            .block_on(self.session.open_client(&dbus::Source {
                uid: source.uid.clone(),
                label: source.label.clone(),
                kind: kind(source.kind),
            }))
            .map_err(refusal)?;
        Ok(Box::new(NativeClient {
            client,
            runtime: self.runtime.clone(),
            calendar: source.kind != Kind::AddressBook,
        }))
    }
}

struct NativeClient {
    client: dbus::Client,
    runtime: Handle,
    calendar: bool,
}

impl NativeClient {
    fn wait<T>(&self, future: impl Future<Output = Result<T, dbus::Error>>) -> Result<T, Refusal> {
        self.runtime.block_on(future).map_err(refusal)
    }
    fn complete(&self, mut objects: Vec<String>) -> Result<Vec<String>, Refusal> {
        if !self.calendar || objects.is_empty() {
            return Ok(objects);
        }
        for zone in ical::eds_missing_time_zones(&objects).map_err(|_| Refusal::SourceFailed)? {
            if let Some(text) = self.wait(self.client.time_zone(&zone))? {
                objects.push(text);
            }
        }
        Ok(vec![
            ical::join_eds_objects(&objects).map_err(|_| Refusal::SourceFailed)?
        ])
    }
}

impl Client for NativeClient {
    fn source_uid(&self) -> &str {
        self.client.source_uid()
    }
    fn objects(&mut self) -> Result<Vec<String>, Refusal> {
        self.complete(self.wait(self.client.objects())?)
    }
    fn object(&mut self, uid: &str) -> Result<Option<String>, Refusal> {
        let Some(text) = self.wait(self.client.object(uid))? else {
            return Ok(None);
        };
        Ok(self.complete(vec![text])?.pop())
    }
}

impl Drop for NativeClient {
    fn drop(&mut self) {
        let _ = self.runtime.block_on(self.client.close());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_and_shared_interface_versions_are_identical() {
        assert_eq!(dbus::BUS_NAMES, super::super::ACCEPTED_BUS_NAMES);
    }

    #[tokio::test]
    async fn native_factory_bridge_runs_on_the_ability_blocking_pool() {
        let runtime_thread = std::thread::current().id();
        tokio::task::spawn_blocking(move || {
            assert_ne!(std::thread::current().id(), runtime_thread);
            // Exercise the same runtime bridge without opening a real user's
            // bus. A nested runtime would panic instead of completing here.
            let runtime = Handle::try_current().unwrap();
            let bridge_thread = bridge(&runtime, async { std::thread::current().id() });
            assert_eq!(bridge_thread, std::thread::current().id());
        })
        .await
        .unwrap();
    }
}
