# Scripts for Pacman and Arch Linux packages #

* roopwn: Pacman wrapper with ELF dependency checking
* makeaur: Builds source package with AURINFO and signature

## pkgbundle ##

Posix shell script to install Arch Linux packages. Does not use _chroot_ or
require any Arch programs to be installed on the host, so the host may be a
different operating system or architecture.

Run “pkgbundle help” for a list of options.

## mkinitcpio-cross ##

Python script to build an Arch Linux _initcpio_ without using _chroot_ or
target programs.

Currently very hacky, brittle, incomplete, minimal, etc.
Probably best to avoid use with real host root privileges;
try “fakeroot” instead.

# To install Arch Linux #

To install basic system into a directory $DESTDIR:

    DBPATH="$DESTDIR/var/lib/pacman" CACHEDIR="$DESTDIR/var/cache/pacman" \
    pkgbundle fs "$DESTDIR" fs-sudo \
        repo 'http://mirrors.kernel.org/archlinux/core/os/$arch/core.db' \
        repo 'http://mirrors.kernel.org/archlinux/extra/os/$arch/extra.db' \
        install base

See <https://www.archlinux.org/mirrorlist/> for repository URLs.
Both the “core” and “extra” repositories may be needed
to install all the dependencies of the “base” group.
The $repo variable from the mirror list has to be manually substituted,
and $repo.db appended, for each repository, however $arch may be retained.

    mkinitcpio-cross --preset linux "$DESTDIR"
