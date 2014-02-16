#! /usr/bin/env bash
set -o errexit -o nounset
${@+declare "$@"}

shopt -s extglob
. "$FUNCTIONS"

buildcommand() {
    printf ' %s\0' "$@"
    printf '\n'
} >> "$ROOT/buildcommands"

add_binary() { buildcommand "$FUNCNAME" "$@"; }
add_symlink() { buildcommand "$FUNCNAME" "$1" "$2"; }
add_file() { buildcommand "$FUNCNAME" "$@"; }
add_runscript() { buildcommand "$FUNCNAME" "${BASH_SOURCE[1]}"; }
add_full_dir() { buildcommand "$FUNCNAME" "$1"; }
add_module() { buildcommand "$FUNCNAME" "$1"; }

auto_modules() { :; }

. "$HOOK"

set +o nounset  # Some hooks try to access empty arrays
build
