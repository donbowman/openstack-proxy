#!/bin/bash
cd "$(dirname "$0")"
shift
logger "ssh-jump: $*"
exec ./python2.7 ./ssh-jump $*
