#!/bin/bash
cd "$(dirname "$0")"
shift
set -- $*
[ "$1" = "null" ] && shift
logger "ssh-jump: $SSH_CONNECTION $*"
exec ./python2.7 ./ssh-jump $*
