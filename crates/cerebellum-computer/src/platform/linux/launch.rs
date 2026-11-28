//! The desktop launch stays on one native thread until ptrace detaches.

use std::time::Duration;

use cerebellum_linux::desktop_entry::Snapshot;
use cerebellum_linux::identity::IdentityReader;
use cerebellum_linux::session::Environment;
use cerebellum_linux::{spawn_desktop_barred, DesktopChild, DesktopExit, ProcessGeneration};

pub struct Released {
    child: DesktopChild,
    pid: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Settle {
    Running(u32),
    Exited(DesktopExit),
    Unknown,
}

pub fn release(
    snapshot: &Snapshot,
    identity: &IdentityReader,
    environment: &Environment,
    check_session: impl Fn() -> Result<(), &'static str>,
    check_cancelled: impl Fn() -> Result<(), &'static str>,
    place_scope: impl FnOnce(ProcessGeneration) -> Result<(), &'static str>,
) -> Result<Released, &'static str> {
    snapshot
        .recheck(identity)
        .map_err(|reason| reason.reason())?;
    check_session()?;
    check_cancelled()?;
    let child = match spawn_desktop_barred(snapshot.executable(), snapshot.arguments(), environment)
    {
        Ok(child) => child,
        Err(_) => {
            snapshot
                .recheck(identity)
                .map_err(|reason| reason.reason())?;
            return Err("launch_entry_unsupported");
        }
    };
    let generation = child.generation();
    snapshot
        .check_stopped(identity, generation)
        .map_err(|reason| reason.reason())?;
    place_scope(generation)?;
    let reaper = child.prepare_reaper().map_err(|_| "backend_unavailable")?;
    snapshot
        .check_stopped(identity, generation)
        .map_err(|reason| reason.reason())?;
    check_session()?;
    snapshot
        .check_paths_unchanged()
        .map_err(|reason| reason.reason())?;
    check_cancelled()?;
    let child = child
        .release(reaper)
        .map_err(|_| "image_replaced_since_launch")?;
    Ok(Released {
        child,
        pid: generation.pid,
    })
}

impl Released {
    pub async fn settle(self) -> Settle {
        match self.child.exit_within(Duration::from_secs(2)).await {
            Ok(Some(exit)) => Settle::Exited(exit),
            Err(_) => Settle::Unknown,
            Ok(None) => Settle::Running(self.pid),
        }
    }
}
