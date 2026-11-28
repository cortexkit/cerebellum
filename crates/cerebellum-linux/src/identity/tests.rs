use super::*;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new("/tmp").join(format!(
            "ck-k1-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn flatpak_markers_refuse_before_the_executable_is_opened() {
    let scratch = Scratch::new();
    let root = scratch.0.join("root");
    fs::create_dir(&root).unwrap();
    fs::write(scratch.0.join("cgroup"), b"0::/user.slice/ordinary.scope\n").unwrap();
    assert_eq!(check_flatpak(&scratch.0, &root), Ok(()));
    fs::write(
        root.join(".flatpak-info"),
        b"not trusted, only a refusal marker",
    )
    .unwrap();
    assert_eq!(check_flatpak(&scratch.0, &root), Err(AppIdentityUnproven));
    fs::remove_file(root.join(".flatpak-info")).unwrap();
    fs::write(
        scratch.0.join("cgroup"),
        b"0::/user.slice/app-flatpak-org.example.Fixture.scope\n",
    )
    .unwrap();
    assert_eq!(check_flatpak(&scratch.0, &root), Err(AppIdentityUnproven));
}

#[test]
fn descriptor_hashes_the_original_file_and_never_rehashes_an_unchanged_key() {
    let scratch = Scratch::new();
    let path = scratch.0.join("fixture");
    fs::write(&path, b"abc").unwrap();
    let reader = IdentityReader::default();
    let mut first = File::open(&path).unwrap();
    let first_key = image_key(&first.metadata().unwrap());
    let first_sum = reader
        .digest(&mut first, first_key, Algorithm::Sha256)
        .unwrap();
    assert_eq!(
        first_sum,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let mut unchanged = File::open(&path).unwrap();
    assert_eq!(
        reader
            .digest(&mut unchanged, first_key, Algorithm::Sha256)
            .unwrap(),
        first_sum
    );
    assert_eq!(unchanged.stream_position().unwrap(), 0);
    assert_eq!(reader.digests.lock().unwrap().hashes, 1);
    fs::write(scratch.0.join("replacement"), b"def").unwrap();
    fs::rename(scratch.0.join("replacement"), &path).unwrap();
    assert_eq!(
        check_exe(&path, &first.metadata().unwrap()),
        Err(ImageReplacedSinceLaunch)
    );
    let mut replacement = File::open(path).unwrap();
    let replacement_key = image_key(&replacement.metadata().unwrap());
    assert_ne!(
        reader
            .digest(&mut replacement, replacement_key, Algorithm::Sha256)
            .unwrap(),
        first_sum
    );
    assert_eq!(reader.digests.lock().unwrap().hashes, 2);
}

#[test]
fn mapping_parser_distinguishes_unlinked_injected_and_anonymous_mappings() {
    let cases: &[(&[u8], Refusal)] = &[
        (
            b"100-200 r-xp 0000 08:03 9 /lib/libfoo.so (deleted)",
            ImageReplacedSinceLaunch,
        ),
        (
            b"100-200 r-xp 0000 00:01 9 /memfd:loader (deleted)",
            ExecutableMappingUnverifiable,
        ),
        (
            b"100-200 r-xp 0000 08:03 9 /lib/foo\\012bar",
            ExecutableMappingUnverifiable,
        ),
        (b"100-200 r-xp 0000 08:03 9", ExecutableMappingUnverifiable),
    ];
    for (line, reason) in cases {
        assert_eq!(Mapping::parse(line).unwrap_err(), *reason);
    }
    assert!(Mapping::parse(b"100-200 r-xp 0000 00:00 0 [vdso]")
        .unwrap()
        .is_none());
    assert!(Mapping::parse(b"100-200 r--p 0000 08:03 9 /lib/foo")
        .unwrap()
        .is_none());
    let mapping = Mapping::parse(b"100-200 r-xp 0000 08:0f 9            /usr/lib/a library.so")
        .unwrap()
        .unwrap();
    assert_eq!(
        (mapping.dev, mapping.ino, mapping.path),
        ((8, 15), 9, b"/usr/lib/a library.so".as_slice())
    );
}

#[test]
fn path_walk_resolves_absolute_and_relative_symlinks_inside_the_process_root() {
    let scratch = Scratch::new();
    let root = open_path(&scratch.0).unwrap();
    fs::create_dir(scratch.0.join("lib")).unwrap();
    fs::write(scratch.0.join("lib/file"), b"fixture").unwrap();
    symlink("/lib", scratch.0.join("absolute")).unwrap();
    symlink("../../../../lib/file", scratch.0.join("lib/relative")).unwrap();
    symlink("/proc/self/exe", scratch.0.join("escape")).unwrap();
    let expected = fs::metadata(scratch.0.join("lib/file")).unwrap();
    for path in ["/absolute/file", "/lib/relative"] {
        let opened = walk(&root, Path::new(path), false).unwrap();
        assert!(same_file(&expected, &opened.metadata().unwrap()));
    }
    assert!(walk(&root, Path::new("/escape"), false).is_err());
}

#[test]
fn mountinfo_records_use_ids_and_deny_non_block_filesystems_even_with_dev_sources() {
    let overlay = Mount::parse(b"50 1 0:40 / / rw - overlay /dev/sda1 rw").unwrap();
    let fuse = Mount::parse(b"51 50 0:42 / /mnt/lib\\040test rw - fuseblk /dev/sda1 rw").unwrap();
    let snap =
        Mount::parse(b"52 50 7:2 / /snap/fixture/123 ro,nodev - squashfs /dev/loop2 ro").unwrap();
    assert!(!overlay.trusted());
    assert!(!fuse.trusted());
    assert_eq!(fuse.target, Path::new("/mnt/lib test"));
    assert!(snap.trusted());
    let mut mounts = Mounts {
        namespace: File::open("/proc/self/ns/mnt").unwrap(),
        host: HashMap::from([(50, overlay)]),
        private: HashMap::new(),
    };
    assert!(owned_mount_namespace(&mounts.namespace).unwrap());
    assert!(mounts.record(52).is_none());
    mounts.private.insert(52, snap);
    assert_eq!(mounts.record(52).unwrap().dev, (7, 2));
    assert_eq!(mounts.record(50).unwrap().fs_type, "overlay");
}

#[test]
fn verified_basename_blocks_proxy_interpreter_and_operator_images() {
    for name in ["xdg-dbus-proxy", "bwrap"] {
        assert_eq!(
            check_basename(&Path::new("/usr/bin").join(name)),
            Err(AppIdentityUnproven)
        );
    }
    for path in [
        "/usr/bin/python3.12",
        "/lib64/ld-linux-x86-64.so.2",
        "/usr/lib/electron1/helper",
    ] {
        assert_eq!(check_basename(Path::new(path)), Err(InterpreterHostedImage));
    }
    for path in [
        "/usr/libexec/polkit-1/helper",
        "/usr/bin/xdg-desktop-portal-gtk",
        "/usr/bin/pinentry-gtk",
        "/usr/bin/gnome-shell",
        "/usr/bin/kwin_wayland",
        "/usr/bin/alfonso",
    ] {
        assert_eq!(check_basename(Path::new(path)), Err(OperatorAppBlocked));
    }
    assert_eq!(check_basename(Path::new("/usr/bin/sleep")), Ok(()));
}

pub(super) fn require_hosted_runner() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    assert_eq!(crate::bridge::read_effective_uid(), 0);
    // Fail before touching mounts unless unshare already put the test binary
    // in a namespace separate from the VM's init process.
    assert!(!same_file(
        &fs::metadata("/proc/self/ns/mnt").unwrap(),
        &fs::metadata("/proc/1/ns/mnt").unwrap()
    ));
}

pub(super) fn checked(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct FixtureChild(Child);

impl Drop for FixtureChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child_at(path: &Path, preload: Option<&Path>) -> FixtureChild {
    let mut command = Command::new("unshare");
    command.args([
        "--mount",
        "--propagation",
        "private",
        "--",
        "setpriv",
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "env",
        "-i",
    ]);
    if let Some(lib) = preload {
        command.arg(format!("LD_PRELOAD={}", lib.display()));
    }
    let child = FixtureChild(command.arg(path).arg("60").spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    let proc = PathBuf::from(format!("/proc/{}", child.0.id()));
    // Waiting for maps also makes the negative preload case check a library
    // which the dynamic loader has actually mapped executable.
    while Instant::now() < deadline {
        if fs::read_link(proc.join("exe"))
            .as_deref()
            .is_ok_and(|exe| exe == path)
            && preload.is_none_or(|lib| {
                fs::read(proc.join("maps")).is_ok_and(|text| {
                    text.windows(lib.as_os_str().len())
                        .any(|field| field == lib.as_os_str().as_bytes())
                })
            })
        {
            return child;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("fixture did not reach exec: {path:?}");
}

pub(super) struct TestMount(pub(super) &'static str);

impl Drop for TestMount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(self.0).status();
    }
}

#[test]
#[ignore = "requires sudo, btrfs-progs, loop devices and a private mount namespace on GitHub-hosted Ubuntu"]
fn native_btrfs_private_namespace_and_package_upgrade() {
    require_hosted_runner();
    let scratch = Scratch::new();
    let image = scratch.0.join("btrfs.img");
    File::create(&image)
        .unwrap()
        .set_len(256 * 1024 * 1024)
        .unwrap();
    checked(Command::new("mkfs.btrfs").args(["-q", "-f"]).arg(&image));
    checked(
        Command::new("mount")
            .args(["-o", "loop"])
            .arg(&image)
            .arg("/mnt"),
    );
    let _mount = TestMount("/mnt");
    checked(Command::new("btrfs").args(["subvolume", "create", "/mnt/trusted"]));
    checked(Command::new("btrfs").args(["subvolume", "create", "/mnt/untrusted"]));

    let packaged = Path::new("/mnt/trusted/ck-fixture");
    let injected = Path::new("/mnt/untrusted/libfixture.so");
    fs::copy("/usr/bin/sleep", packaged).unwrap();
    let source = scratch.0.join("fixture.c");
    fs::write(&source, b"int ck_fixture(void) { return 0; }\n").unwrap();
    let lib = scratch.0.join("fixture.so");
    checked(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&lib)
            .arg(&source),
    );
    fs::copy(&lib, injected).unwrap();
    std::os::unix::fs::chown(injected, Some(65534), Some(65534)).unwrap();
    let exe_meta = fs::metadata(packaged).unwrap();
    let lib_meta = fs::metadata(injected).unwrap();
    assert_eq!(
        exe_meta.ino(),
        lib_meta.ino(),
        "fixture must use coincident inode numbers"
    );
    assert_ne!(
        exe_meta.dev(),
        lib_meta.dev(),
        "subvolumes must have different st_dev"
    );

    fs::create_dir_all("/mnt/dpkg/info").unwrap();
    fs::write("/mnt/dpkg/status", b"").unwrap();
    fs::write(
        "/mnt/dpkg/info/ck-fixture:amd64.list",
        b"/mnt/trusted/ck-fixture\n",
    )
    .unwrap();
    let checksum_file = "/mnt/dpkg/info/ck-fixture:amd64.md5sums";
    let record = || {
        let sum = hash::<Md5>(&mut File::open(packaged).unwrap()).unwrap();
        fs::write(checksum_file, format!("{sum}  mnt/trusted/ck-fixture\n")).unwrap();
    };
    record();
    fs::write("/mnt/dpkg/info/coreutils-fixture.list", b"/bin/sleep\n").unwrap();
    let host_sum = hash::<Md5>(&mut File::open("/usr/bin/sleep").unwrap()).unwrap();
    fs::write(
        "/mnt/dpkg/info/coreutils-fixture.md5sums",
        format!("{host_sum}  bin/sleep\n"),
    )
    .unwrap();
    checked(Command::new("mount").args(["--bind", "/mnt/dpkg", "/var/lib/dpkg"]));
    let _database = TestMount("/var/lib/dpkg");

    let reader = IdentityReader::default();
    let original = child_at(packaged, None);
    let proc = PathBuf::from(format!("/proc/{}", original.0.id()));
    let exe_mount = mount_id(&File::open(proc.join("exe")).unwrap()).unwrap();
    assert!(
        !Mount::read(Path::new("/proc/self/mountinfo"))
            .unwrap()
            .contains_key(&exe_mount),
        "the target has a private mount id"
    );
    assert_eq!(
        reader.prove(original.0.id()).unwrap().subject,
        "dpkg:ck-fixture"
    );
    assert_eq!(
        reader.prove(original.0.id()).unwrap().subject,
        "dpkg:ck-fixture"
    );
    assert_eq!(reader.digests.lock().unwrap().hashes, 1);
    let aliased = child_at(Path::new("/usr/bin/sleep"), None);
    assert_eq!(
        reader.prove(aliased.0.id()).unwrap().subject,
        "dpkg:coreutils-fixture"
    );

    let tainted = child_at(packaged, Some(injected));
    let mappings = fs::read(format!("/proc/{}/maps", tainted.0.id())).unwrap();
    let mappings: Vec<_> = mappings
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| Mapping::parse(line).unwrap())
        .collect();
    let mapped = |path: &Path| {
        mappings
            .iter()
            .find(|mapping| mapping.path == path.as_os_str().as_bytes())
            .unwrap()
    };
    assert_eq!(
        mapped(packaged).dev,
        mapped(injected).dev,
        "the maps device must coincide too"
    );
    assert_eq!(
        reader.prove(tainted.0.id()),
        Err(ExecutableMappingUnverifiable)
    );

    std::os::unix::fs::chown("/mnt/untrusted", Some(65534), Some(65534)).unwrap();
    let unowned = Path::new("/mnt/untrusted/ck-fixture");
    fs::copy(packaged, unowned).unwrap();
    std::os::unix::fs::chown(unowned, Some(65534), Some(65534)).unwrap();
    let local = child_at(unowned, None);
    let app = reader.prove(local.0.id()).unwrap();
    assert!(app.subject.starts_with("sha256:"));
    assert!(app
        .display_name(None)
        .contains("/mnt/untrusted/ck-fixture; no supported package manager has a verified record"));

    fs::copy(packaged, "/mnt/trusted/next").unwrap();
    OpenOptions::new()
        .append(true)
        .open("/mnt/trusted/next")
        .unwrap()
        .write_all(b"next build")
        .unwrap();
    fs::rename("/mnt/trusted/next", packaged).unwrap();
    record();
    assert_eq!(reader.prove(original.0.id()), Err(ImageReplacedSinceLaunch));
    let upgraded = child_at(packaged, None);
    assert_eq!(
        reader.prove(upgraded.0.id()).unwrap().subject,
        "dpkg:ck-fixture"
    );
    fs::remove_file(checksum_file).unwrap();
    assert_eq!(
        reader.prove(upgraded.0.id()),
        Err(PackageChecksumUnavailable)
    );
}
