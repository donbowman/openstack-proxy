#!/bin/bash
cd "$(dirname "$0")"
shift
set -- $*
[ "$1" = "null" ] && shift
logger "ssh-jump: $*"
exec ./python2.7 ./ssh-jump $*
