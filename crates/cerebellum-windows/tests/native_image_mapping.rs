#![cfg(windows)]

use cerebellum_windows::{lock_image_file, retain_image_process, ImageMappingReading};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    child: Option<Child>,
    dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
#[ignore = "helper invoked by the image-mapping test"]
fn image_mapping_child() {
    use std::io::Write;

    println!("IMAGE_MAPPING_CHILD_READY");
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin().read(&mut [0]);
}

#[test]
fn image_mapping_refuses_a_replacement_at_the_same_path() {
    let dir = PathBuf::from(r"\tmp").join(format!(
        "cerebellum-image-mapping-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let mut fixture = Fixture { child: None, dir };
    let original = fixture.dir.join("fixture.exe");
    let renamed = fixture.dir.join("original.exe");
    let this_test = std::env::current_exe().unwrap();
    fs::copy(&this_test, &original).unwrap();
    #[allow(
        clippy::disallowed_methods,
        reason = "migrated by the spawn-wrapper slice"
    )]
    let child = Command::new(&original)
        .args(["--exact", "image_mapping_child", "--ignored", "--nocapture"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    fixture.child = Some(child);
    let child = fixture.child.as_mut().unwrap();
    let (ready, wait) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("IMAGE_MAPPING_CHILD_READY") {
                let _ = ready.send(());
                break;
            }
        }
    });
    wait.recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    reader.join().unwrap();

    let process = retain_image_process(child.id()).unwrap();
    let recorded_path = process.image_path().unwrap();
    assert_eq!(recorded_path.file_name(), original.file_name());
    let loaded_id = match process
        .image_mapping(&lock_image_file(&recorded_path).unwrap())
        .unwrap()
    {
        ImageMappingReading::SameFile(id) => id,
        reading => panic!("correct loaded file did not match: {reading:?}"),
    };

    fs::rename(&recorded_path, &renamed).unwrap();
    // Copy the same bytes to the exact same old path. Only the file object is
    // different; a pathname or SHA-256 comparison cannot detect replacement.
    fs::copy(&this_test, &recorded_path).unwrap();
    let replacement = lock_image_file(&recorded_path).unwrap();
    assert_ne!(
        loaded_id,
        cerebellum_windows::file_identity(replacement.read_only_handle()).unwrap()
    );
    assert!(
        matches!(
            process.image_mapping(&replacement).unwrap(),
            ImageMappingReading::NtStatus(_)
        ),
        "different file at the original image path matched"
    );
    assert_eq!(
        process
            .image_mapping(&lock_image_file(&renamed).unwrap())
            .unwrap(),
        ImageMappingReading::SameFile(loaded_id),
        "the moved file still backs the loaded image"
    );
}
