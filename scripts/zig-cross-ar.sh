#!/bin/sh
# The archiver half of the zig-backed Linux cross toolchain. See zig-cross-cc.sh.
exec zig ar "$@"
