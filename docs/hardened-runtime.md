# Hardened runtime

On macOS, `ck-cerebellum` is signed with hardened runtime (`codesign --options runtime`)
and no entitlements. Without it, or with `com.apple.security.get-task-allow`,
any other program running as the same user can attach a debugger to the
module and read its memory, including the launch secret it holds. `lldb -p`
attached without a prompt to an unhardened module and was refused on a
hardened copy.

- `scripts/stage.sh` signs with `--options runtime`, then refuses to stage
  unless the signed file passes `scripts/check-placed-hardening.sh`.
- Placement is a plain copy made by the daemon owner. The placement gate runs
  `scripts/check-placed-hardening.sh <placed path>` on the placed file and
  refuses the placement if it exits non-zero. The script only reads the
  signature. It checks every architecture slice for the `runtime` flag and
  for the absence of `get-task-allow`, and names each problem it finds.
- `scripts/check-placed-hardening.test.sh` proves both outcomes on ad hoc
  signed scratch binaries, and `scripts/rust-test-gate.sh` runs it on macOS.

## Why no entitlement is needed

Hardened runtime restricts what the process itself may do: load libraries
not signed by Apple or its own team, use JIT or unsigned executable memory,
honour `DYLD_*` variables, or be debugged. Nothing the module does needs an
exemption from those restrictions:

- The computer-control side (reading app state, clicking, typing) passed
  every live check in the `crates/cerebellum/examples/v13_desk_arms.rs`
  probe on a hardened copy. That run included the private SkyLight symbols,
  which are loaded with `dlopen`/`dlsym` from a platform-signed framework
  and so satisfy library validation (`crates/cerebellum-macos/src/skylight.rs`).
- The browser launch path uses no task port and no debugger right on the
  child. `prepare_spawn` starts Chrome with `POSIX_SPAWN_START_SUSPENDED`
  (`crates/cerebellum-macos/src/launch.rs`, the `posix_spawnattr_setflags`
  call). The running child is identified and checked with
  `SecCodeCopyGuestWithAttributes` and `SecCodeCheckValidity`, and its
  process generation with `proc_pidinfo`. The guardian then releases it with
  `kill(pid, SIGCONT)` (`guardian_main`). None of these needs an entitlement.
  The macOS crates call no `task_for_pid`, `ptrace`, `mach_vm_*`,
  `task_resume` or `thread_get_state`, and pass no `DYLD_*` variable to the
  child. `ptrace` appears only in the Linux launcher.

## Probe: launching Chrome from a hardened binary

The source audit above cannot prove the launch works under hardened runtime;
only running it can. This probe opens visible Chrome windows, so run it only
with the operator's permission. It builds the `live_launch` example, signs a
copy with hardened runtime, and runs it against a throwaway home under `/tmp`,
so no journal, profile or custody record reaches the operator's data home.
The copy lives under `/tmp`, not `$TMPDIR`: `codesign` on a file under the
per-user `$TMPDIR` hangs on macOS 27. The identifier differs from
`ck-cerebellum` so the probe cannot inherit or disturb the production
binary's permission grants.

```sh
# On macOS, from the repository root.
cargo build -p cerebellum --example live_launch

PROBE=/tmp/ck-hardened-launch-probe
rm -rf "$PROBE" && mkdir -p "$PROBE/home" "$PROBE/tmp"
cp target/debug/examples/live_launch "$PROBE/live_launch"
: "${SIGNING_IDENTITY:?Set SIGNING_IDENTITY to your Apple Development certificate name}"
codesign --force --sign "$SIGNING_IDENTITY" \
  --identifier ck-cerebellum-live-launch-probe --options runtime \
  "$PROBE/live_launch"
scripts/check-placed-hardening.sh "$PROBE/live_launch"   # must print "hardened:"

HOME="$PROBE/home" XDG_DATA_HOME="$PROBE/home/.local/share" TMPDIR="$PROBE/tmp/" \
  "$PROBE/live_launch"; echo "exit=$?"
```

Pass: exit 0, a `[first] launch:` and a `[second] launch:` line, and a
`VERDICT: the second launch ...` line. A `skipped:` line also exits 0 but
proves nothing, because no browser was launched. A hardened-runtime failure
shows as `launch refused: ...` or `VERDICT: a wire probe failed` with a spawn
or identity error. To tell that apart from a failure unrelated to hardening,
repeat the run with a control copy signed the same way without
`--options runtime`. Only a failure that appears on the hardened copy and not
on the control counts against hardened runtime.

Clean up afterwards with `rm -rf /tmp/ck-hardened-launch-probe`.
