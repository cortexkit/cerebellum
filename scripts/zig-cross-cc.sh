#!/bin/sh
# A C cross-compiler for the Linux target, backed by zig.
#
# The gate lints the Linux target from a macOS host. Two dependencies in our
# tree compile C -- ring and libsqlite3-sys, both arriving through subc-core --
# so that lint needs a C compiler that can produce Linux objects. Without one
# the phase fails on a build script and reports nothing about our code.
#
# zig ships a full cross-compiling clang, so no separate toolchain has to be
# installed or kept in step with anything.
#
# THE ARGUMENT FILTER IS NOT INCIDENTAL: cc-rs passes --target=<rust triple>,
# and zig parses that flag itself and rejects the spelling
# (UnknownOperatingSystem on x86_64-unknown-linux-gnu). Dropping it and
# supplying zig's own spelling is what makes this work at all.
args=""
for a in "$@"; do
  case "$a" in
    --target=*) ;;
    *) args="$args \"$a\"" ;;
  esac
done
eval exec zig cc -target x86_64-linux-gnu $args
