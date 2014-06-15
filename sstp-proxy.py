#!/usr/bin/python

"""

 sstp-proxy: SSTP routing proxy

A simple eventlet-based proxy server to take in SSL of SSTP
format and route to a specific virtual machine inside our
private cloud

We expect a path of: /user/project[/instance]
if instance is specified, then we find instance-vpn.
if its not specified, we find the first instance-vpn for that user/project

"""

from novaclient import client
from novaclient.v3 import servers
import eventlet
import ssl
import re
import os
import pwd
import grp

#"SSTP_DUPLEX_POST /myvpn/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1"

# expects /path/sra_
# we might have:
# /user/project/instance (in which case we find the specific nova instance)
# or /user/project (in which case we find the first nova instance)
def find_host(s):
    h = "localhost"
    p = 443
    path = s.split('/')
    if len(path) < 4:
        return (h,p)

    user = path[1]
    project = path[2]

    cl = client.Client(3,"admin","@dmin-p@ssword",project,"http://vk-3.phenomi.ca:5000/v2.0")
    servers = cl.servers.list()

    # the case where we have user but not path, use first server
    if len(path) == 4:
        ss = ".*"
    else:
        ss = path[3]
    for s in servers:
        if re.search("%s-vpn" % ss, s.name):
            for i in s.networks:
                if i == "public":
                    h = str(s.networks[i][0])

    return str(h),p

def rforward(source, dest):
    while True:
        try:
            d = source.recv(32384)
            if d == '':
                break
            dest.sendall(d)
        except:
            source.close()
            dest.close()

def forward(source):
    dest = ""
    ibuf = ""

    while True:
        try:
            d = source.recv(32384)
        except:
            source.close()
            break
        if d == '':
            break
        if dest == "":
            h = ""
            ibuf = ibuf + d
            result = re.match("^SSTP_DUPLEX_POST (.*sra_)", ibuf)
            if result != None:
                h, p = find_host(result.groups()[0])
                ibuf = re.sub("^SSTP_DUPLEX_POST.*/sra_","SSTP_DUPLEX_POST /sra_", ibuf)
            else:
                if ibuf.startswith('S') != True:
                    h = "localhost"
                    p = 443
            if (h != ""):
                print("Connect SSTP proxy to %s:%d" % (h,p))
                try:
                    dest = eventlet.wrap_ssl(eventlet.connect((h,p)),
                                           cert_reqs=ssl.CERT_NONE
                                          )
                    eventlet.spawn_n(rforward, dest, source)
                except:
                    source.close()
                    break
                d = ibuf
        if dest:
            try:
                dest.sendall(d)
            except:
                dest.close()
                source.close()

listener = eventlet.wrap_ssl(eventlet.listen(('', 9999)),
                             server_side = True,
                             certfile = "/etc/ssl/certs/vk-3.crt",
                             keyfile = "/etc/ssl/private/vk-3.key")
while True:
    xcl, addr = listener.accept()
    eventlet.spawn_n(forward, xcl)

