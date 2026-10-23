#!/usr/bin/env python3
"""Tell whether the process table here can be read the way launch recovery
reads it, without compiling anything.

The launch_recovery_clear tests run the real reading in
`launch_recovery::user_process_arguments`: the owner of every process, through
`PROC_PIDT_SHORTBSDINFO` (which the kernel normally answers for any process,
whoever runs it), then the arguments of this user's own processes, through
`KERN_PROCARGS2`. Most of them also scope that reading to their own test
binary's descendants, which they find with `/bin/ps -A -o pid=,ppid=`
(`ScopedTable` in browser_launch_service.rs). A worker sandbox refuses
`/bin/ps` even where the reading itself works, and those tests then fail with
`process_table_unreadable`. This probe makes the same two reads for every
process, in the same order, with the same retry (it checks only that an
argument answer arrived, where launch recovery also parses it), and runs the
same `ps` command. When either fails, the gate skips the
launch_recovery_clear tests and says so.

Exit 0 when the table is readable, 1 when it is not.
"""
import ctypes
import os
import subprocess
import sys
import time

ESRCH = 3
STATUS_ZOMBIE = 5
PROC_PIDT_SHORTBSDINFO = 13
CTL_KERN, KERN_ARGMAX, KERN_PROCARGS2 = 1, 8, 49
GONE = "gone"


class ProcBsdShortInfo(ctypes.Structure):
    # struct proc_bsdshortinfo, as cerebellum_macos::process_owner reads it.
    _fields_ = [
        ("pbsi_pid", ctypes.c_uint32),
        ("pbsi_ppid", ctypes.c_uint32),
        ("pbsi_pgid", ctypes.c_uint32),
        ("pbsi_status", ctypes.c_uint32),
        ("pbsi_comm", ctypes.c_char * 16),
        ("pbsi_flags", ctypes.c_uint32),
        ("pbsi_uid", ctypes.c_uint32),
        ("pbsi_gid", ctypes.c_uint32),
        ("pbsi_ruid", ctypes.c_uint32),
        ("pbsi_rgid", ctypes.c_uint32),
        ("pbsi_svuid", ctypes.c_uint32),
        ("pbsi_svgid", ctypes.c_uint32),
        ("pbsi_rfu", ctypes.c_uint32),
    ]


def readable(pids, owner, arguments, this_user, retry_window=1.0, pause=0.02):
    """Whether every process of `this_user` reads as launch recovery needs.

    `owner(pid)` answers GONE, `(uid, zombie)`, or None when the kernel
    refuses. `arguments(pid)` answers GONE, True when read, or False when
    refused. Another user's process is skipped on its owner alone, as launch
    recovery skips it, so a process only root may inspect in full never makes
    the table unreadable. Refused arguments are retried until one deadline
    shared by the whole scan, as in launch recovery (`UNREADABLE_RETRY_WINDOW`
    and `UNREADABLE_RETRY_PAUSE`).
    """
    deadline = None
    for pid in pids:
        found = owner(pid)
        if found == GONE:
            continue
        if found is None:
            return False
        uid, zombie = found
        if zombie or uid != this_user:
            continue
        while True:
            answer = arguments(pid)
            if answer is True or answer == GONE:
                break
            # A process exiting or exec'ing can refuse for a moment.
            again = owner(pid)
            if again == GONE or (again is not None and again[1]):
                break
            now = time.monotonic()
            if deadline is None:
                deadline = now + retry_window
            if now >= deadline:
                return False
            time.sleep(min(pause, deadline - now))
    return True


def ps_lists_parents(run=subprocess.run):
    """Whether `/bin/ps -A -o pid=,ppid=` lists processes with their parents,
    the way the tests' `ScopedTable` reads it."""
    try:
        result = run(["/bin/ps", "-A", "-o", "pid=,ppid="],
                     capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
    return bool(rows) and all(
        len(row) == 2 and row[0].isdigit() and row[1].isdigit() for row in rows
    )


def system_reads():
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libc = ctypes.CDLL(None, use_errno=True)
    list_all = libproc.proc_listallpids
    list_all.argtypes = [ctypes.c_void_p, ctypes.c_int]
    list_all.restype = ctypes.c_int
    pid_info = libproc.proc_pidinfo
    pid_info.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                         ctypes.c_void_p, ctypes.c_int]
    pid_info.restype = ctypes.c_int
    sysctl = libc.sysctl
    sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                       ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    sysctl.restype = ctypes.c_int

    def pids():
        estimate = list_all(None, 0)
        if estimate < 0:
            raise OSError(ctypes.get_errno(), "proc_listallpids")
        capacity = estimate + 256
        for _ in range(4):
            buffer = (ctypes.c_int * capacity)()
            count = list_all(buffer, ctypes.sizeof(buffer))
            if count < 0:
                raise OSError(ctypes.get_errno(), "proc_listallpids")
            if count < capacity:
                return [pid for pid in buffer[:count] if pid > 0]
            capacity *= 2
        raise OSError(0, "the process table kept outgrowing the buffer")

    def owner(pid):
        info = ProcBsdShortInfo()
        ctypes.set_errno(0)
        size = ctypes.sizeof(info)
        if pid_info(pid, PROC_PIDT_SHORTBSDINFO, 0, ctypes.byref(info), size) != size:
            return GONE if ctypes.get_errno() == ESRCH else None
        return info.pbsi_uid, info.pbsi_status == STATUS_ZOMBIE

    maximum = ctypes.c_int(0)
    length = ctypes.c_size_t(ctypes.sizeof(maximum))
    name = (ctypes.c_int * 2)(CTL_KERN, KERN_ARGMAX)
    if sysctl(name, 2, ctypes.byref(maximum), ctypes.byref(length), None, 0) != 0 \
            or maximum.value <= 0:
        raise OSError(ctypes.get_errno(), "KERN_ARGMAX")

    def arguments(pid):
        buffer = ctypes.create_string_buffer(maximum.value)
        size = ctypes.c_size_t(maximum.value)
        name = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
        ctypes.set_errno(0)
        if sysctl(name, 3, buffer, ctypes.byref(size), None, 0) != 0:
            return GONE if ctypes.get_errno() == ESRCH else False
        # The answer starts with the argument count.
        return size.value >= 4

    return pids, owner, arguments


def self_test():
    me, root = 501, 0

    def run(owners, refused_arguments):
        return readable(
            list(owners),
            lambda pid: owners[pid],
            lambda pid: pid not in refused_arguments,
            me,
            retry_window=0,
        )

    # Root's launchd refuses the full information form to an unprivileged
    # user, but its owner alone answers, so it is skipped and never refuses.
    assert run({1: (root, False), 2: (me, False)}, {1})
    # An owner the kernel refuses makes the table unreadable.
    assert not run({1: None, 2: (me, False)}, set())
    # So do arguments of this user's process that stay refused.
    assert not run({2: (me, False)}, {2})
    # Gone and zombie processes are skipped.
    assert run({2: GONE, 3: (me, True)}, {3})

    class Ran:
        def __init__(self, returncode, stdout):
            self.returncode, self.stdout = returncode, stdout

    def ps(returncode=0, stdout="    1     0\n  412     1\n", error=None):
        def run(*_args, **_kwargs):
            if error:
                raise error
            return Ran(returncode, stdout)
        return ps_lists_parents(run)

    assert ps()
    # A sandbox that refuses ps, or a ps that fails or prints something else,
    # leaves the tests' scoping unreadable.
    assert not ps(error=PermissionError(1, "Operation not permitted"))
    assert not ps(returncode=1)
    assert not ps(stdout="")
    assert not ps(stdout="  PID  PPID\n    1     0\n")
    print("process table probe: self-test passed")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if sys.platform != "darwin":
        # The tests it decides about run only on macOS.
        return 0
    try:
        pids, owner, arguments = system_reads()
        me = owner(os.getpid())
        if me == GONE or me is None:
            return 1
        return 0 if readable(pids(), owner, arguments, me[0]) and ps_lists_parents() else 1
    except (OSError, AttributeError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
