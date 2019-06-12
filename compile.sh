#!/bin/sh

LINUX64=0
LDPATH=$(pwd)/libs/x32
if [ "`uname -m`" == "x86_64" ]; then
 LINUX64=1
 LDPATH=$(pwd)/libs/x64
fi

echo LD_LIBRARY_PATH=${LDPATH}
export LD_LIBRARY_PATH=${LDPATH}

make -C src clean
make -C src LINUX64=${LINUX64}
