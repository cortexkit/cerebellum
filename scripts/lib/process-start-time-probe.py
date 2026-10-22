#!/usr/bin/env python3
"""Probe the macOS process reader used by launch recovery, without compiling."""
import ctypes
import sys


class ProcBsdInfo(ctypes.Structure):
    # Match cerebellum_macos::process_start_time's PROC_PIDTBSDINFO layout.
    _fields_ = [
        (name, ctypes.c_uint32)
        for name in (
            "pbi_flags", "pbi_status", "pbi_xstatus", "pbi_pid", "pbi_ppid",
            "pbi_uid", "pbi_gid", "pbi_ruid", "pbi_rgid", "pbi_svuid",
            "pbi_svgid", "rfu_1",
        )
    ] + [("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32)
        for name in ("pbi_nfiles", "pbi_pgid", "pbi_pjobc", "e_tdev", "e_tpgid")
    ] + [
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def readable():
    # The launch_recovery_clear tests are macOS-only. PID 1 is always alive and
    # outside this gate's process family. A sandbox may expose our own children
    # and parent while hiding the older processes orphan recovery must inspect.
    if sys.platform != "darwin":
        return True
    info = ProcBsdInfo()
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    query = libproc.proc_pidinfo
    query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                     ctypes.c_void_p, ctypes.c_int]
    query.restype = ctypes.c_int
    size = ctypes.sizeof(info)
    written = query(1, 3, 0, ctypes.byref(info), size)
    return written == size and info.pbi_start_tvsec > 0 and info.pbi_start_tvusec < 1_000_000


if __name__ == "__main__":
    try:
        sys.exit(0 if readable() else 1)
    except (OSError, AttributeError):
        sys.exit(1)
