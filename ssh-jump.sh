#!/bin/bash
shift
echo $* > /tmp/nsnc
exec ~jump/python2.7 ~jump/nsnc $*
