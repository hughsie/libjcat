#!/bin/sh
set -e

#evaluate using Debian's build flags
eval "$(dpkg-buildflags --export=sh)"
#filter out -Bsymbolic-functions
export LDFLAGS=$(dpkg-buildflags --get LDFLAGS | sed "s/-Wl,-Bsymbolic-functions\s//")

export LC_ALL=C.UTF-8
mkdir -p build && cd build
rm * -rf
meson .. \
    --cross-file=../contrib/s390x.cross \
    -Dintrospection=false \
    -Dman=false \
    -Dgpg=false \
    -Dgtkdoc=false \
    -Dtests=true $@
ninja -v || bash
ninja test -v
DESTDIR=/tmp/install-ninja ninja install
cd ..
