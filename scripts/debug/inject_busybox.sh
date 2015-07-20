#!/bin/bash

set -e

# eg.  /var/lib/rkt/pods/run/921d4ecb-4986-4065-8607-8597469c30f0/stage1/rootfs/bin
BIN_DIR="/var/lib/rkt/pods/run/`ls -1t /var/lib/rkt/pods/run | head -1`/stage1/rootfs/usr/bin/"
BUSYBOX=${BUSYBOX_BINARY:-$(which busybox 2> /dev/null)}

cp $BUSYBOX $BIN_DIR/busybox

for link in $($BUSYBOX --list); do
    [ ! -e $BIN_DIR/$link ] && (cd $BIN_DIR; ln -sv busybox $link)
done
