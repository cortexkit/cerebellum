#!/usr/bin/env python3
"""Tell whether the process table here can be read the way launch recovery
reads it, without compiling anything.

The launch_recovery_clear tests run the real reading in
`launch_recovery::user_process_arguments`: the owner of every process, through
`PROC_PIDT_SHORTBSDINFO`, which the kernel answers for any process whoever runs
it, then the arguments of this user's own processes, through `KERN_PROCARGS2`.
A worker sandbox hides older processes, and those tests then fail with
`process_table_unreadable`. This probe makes the same reads in the same order,
so the gate skips those tests only where they cannot pass.

Exit 0 when the table is readable, 1 when it is not.
"""
import ctypes
import os
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


def readable(pids, owner, arguments, this_user, attempts=3, pause=0.05):
    """Whether every process of `this_user` reads as launch recovery needs.

    `owner(pid)` answers GONE, `(uid, zombie)`, or None when the kernel
    refuses. `arguments(pid)` answers GONE, True when read, or False when
    refused. Another user's process is skipped on its owner alone, as launch
    recovery skips it, so a process only root may inspect in full never makes
    the table unreadable.
    """
    for pid in pids:
        found = owner(pid)
        if found == GONE:
            continue
        if found is None:
            return False
        uid, zombie = found
        if zombie or uid != this_user:
            continue
        for attempt in range(attempts):
            answer = arguments(pid)
            if answer is True or answer == GONE:
                break
            # A process exiting or exec'ing can refuse for a moment; launch
            # recovery retries the same way before refusing a clear.
            again = owner(pid)
            if again == GONE or (again is not None and again[1]):
                break
            if attempt + 1 < attempts:
                time.sleep(pause)
        else:
            return False
    return True


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
            pause=0,
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
        return 0 if readable(pids(), owner, arguments, me[0]) else 1
    except (OSError, AttributeError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
