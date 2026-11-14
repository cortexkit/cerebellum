//! Run in an isolated Linux login with three pre-populated scratch EDS sources.
//! No source creation, writes, authentication or service activation is attempted.

#[cfg(any(target_os = "linux", test))]
fn scratch_ids(args: &[String]) -> Result<[String; 3], &'static str> {
    if args.len() != 7
        || args[0] != "--scratch"
        || args[1] != "--calendar"
        || args[3] != "--tasks"
        || args[5] != "--contacts"
    {
        return Err("requires --scratch --calendar UID --tasks UID --contacts UID");
    }
    let ids = [args[2].clone(), args[4].clone(), args[6].clone()];
    if ids
        .iter()
        .any(|id| !id.starts_with("ck-scratch-") || id.len() <= 11)
        || ids[0] == ids[1]
        || ids[0] == ids[2]
        || ids[1] == ids[2]
    {
        return Err("three distinct ck-scratch- source UIDs are required");
    }
    Ok(ids)
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use cerebellum_linux::eds::{self, Kind};
    use std::sync::Arc;

    let ids = scratch_ids(&std::env::args().skip(1).collect::<Vec<_>>()).unwrap_or_else(|reason| {
        eprintln!("{reason}");
        std::process::exit(2)
    });
    let session = eds::Session::connect(Arc::new(|| false))
        .await
        .expect("session bus");
    let sources = session
        .sources()
        .await
        .expect("running EDS source registry");
    let kinds = [Kind::Calendar, Kind::TaskList, Kind::AddressBook];
    // Validate all three before opening even the first client.
    let selected: Vec<_> = ids
        .iter()
        .zip(kinds)
        .map(|(id, kind)| {
            sources
                .iter()
                .find(|s| {
                    &s.uid == id && s.kind == kind && s.label.starts_with("CortexKit scratch")
                })
                .expect("UID must name a source of the requested kind labelled CortexKit scratch")
        })
        .collect();
    for source in selected {
        let client = session
            .open_client(source)
            .await
            .expect("scratch source client");
        let objects = client.objects().await.expect("scratch source read");
        assert!(
            !objects.is_empty(),
            "populate each scratch source before probing"
        );
        println!("{:?}: {} scratch objects", source.kind, objects.len());
        client.close().await.expect("close scratch client");
    }
    println!("configured IANA zone: {:?}", eds::system_iana_zone());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("EDS desk probe requires Linux");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_refuses_missing_flag_and_non_scratch_sources() {
        let args = [
            "--scratch",
            "--calendar",
            "ck-scratch-c",
            "--tasks",
            "ck-scratch-t",
            "--contacts",
            "ck-scratch-a",
        ]
        .map(str::to_owned);
        assert!(scratch_ids(&args).is_ok());
        assert!(scratch_ids(&args[1..]).is_err());
        let mut unsafe_args = args;
        unsafe_args[2] = "operator-calendar".into();
        assert!(scratch_ids(&unsafe_args).is_err());
    }
}
