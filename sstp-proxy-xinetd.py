#!/usr/bin/python

"""

 sstp-proxy: SSTP routing proxy

A simple eventlet-based proxy server to take in SSL of SSTP
format and route to a specific virtual machine inside our
private cloud

We expect a path of: /tenant/instance

"""

# Steal stderr away and watch it in a file
# should never write anything, but if it does
# then a) our ssl connection dies, and b)
# we never see it
import sys
sys.stderr.close()
sys.stderr = open("/tmp/sstp.log","a")

# What's this you ask?
# Well, xinetd or stunel is reaping SIGCHLD, and if 
# we use popen, we are screwed.
# and, keystone calls keyring which calls uname
import platform
def __syscmd_uname(option,default=''):
    return 'x86_64'

platform._syscmd_uname = __syscmd_uname

import novaclient.client
from neutronclient.v2_0 import client as neutronclient
from keystoneclient.v2_0 import client as keystoneclient

import traceback

from novaclient.v3 import servers
from eventlet.green import socket
import socket
import ssl, re, os, argparse, sys
import StringIO
import ConfigParser
import syslog
import ctypes
import prctl
import os
import find_ns
from time import sleep
import requests
import memcache

import eventlet
eventlet.monkey_patch()

syslog.openlog(ident="sstp-proxy",logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)
#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
#sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

def log(severity,txt):
    if (os.isatty(1)):
        print(txt)
    else:
        syslog.syslog(severity,txt)


def forward(source, dest):
    while True:
        try:
            d = source.recv(32768)
            if d == '':
                break
            dest.sendall(d)
        except:
            break
    try:
        source.close()
        dest.close()
    except:
        pass
    sys.exit(0)

def result_instance_tenant(s):
    tenant = ""
    instance = ""
    path = s.split('/')
    if len(path) < 4:
        path = s.split('.')
        if len(path) == 6:
            tenant = path[0]
            instance= path[2]
        elif len(path) == 5:
            tenant = path[0]
            instance = path[1]
    else:
        if len(path) == 4:
            tenant = path[1]
            instance = path[2]
        else:
            tenant = path[1]
            instance = path[3]

    return tenant,instance

def route(source,gp,args):
    dest = ""
    ibuf = ""
    p = 443

    while True:
        d = source.recv(32384)
        if d == '':
            break
        if dest == "":
            h = ""
            ibuf = ibuf + d
            #log(syslog.LOG_INFO,"result: %s" % ibuf)
            #CONNECT https://don.don-vpn.vpn.sandvine.rocks:9999:443 HTTP/1.1
            result_connect = re.match("^CONNECT (.*):",ibuf)
            result_sra = re.match("^SSTP_DUPLEX_POST (.*sra_)", ibuf)
            result_host = re.search("^Host: ([^\r\n]+)", ibuf, re.MULTILINE)
            if result_host != None:
                host = result_host.groups()[0]
            if result_sra != None or result_host != None or result_connect != None:
                if result_connect != None:
                    ibuf = ""
                    tenant,instance = result_instance_tenant(result_connect.groups()[0])
                    h, ns,floating = find_ns.find_host(  args.admin_user,
                                                tenant,
                                                args.admin_pass,
                                                instance,
                                                args.keystone_url)

                if (h == "" and result_host != None and len(host.split('.')) > 3):
                    tenant,instance = result_instance_tenant(result_host.groups()[0])
                    h, ns,floating = find_ns.find_host(  args.admin_user,
                                                tenant,
                                                args.admin_pass,
                                                instance,
                                                args.keystone_url)

                if (h == "" and result_sra != None):
                    tenant,instance = result_instance_tenant(result_sra.groups()[0])
                    h, ns,floating = find_ns.find_host(  args.admin_user,
                                                tenant,
                                                args.admin_pass,
                                                instance,
                                                args.keystone_url)

                ibuf = re.sub("^SSTP_DUPLEX_POST.*/sra_","SSTP_DUPLEX_POST /sra_", ibuf)
                ibuf = re.sub(":[0-9]+", "", ibuf)
                if (h != "" and ns != ""):
                    d = ibuf
                    log(syslog.LOG_INFO,"Connect proxy to %s:%d (ns=%s)" % (h,p,ns))
                    _ns = find_ns.NS(ns)
                    if result_connect != None:
                        log(syslog.LOG_INFO,"to send 200OK")
                        dest = eventlet.connect((h,p))
                        dest.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        source.sendall("HTTP/1.0 200 Connection established\r\n\r\n")
                    else:
                        try:
                            dest = eventlet.wrap_ssl(eventlet.connect((h,p)),
                                                   cert_reqs=ssl.CERT_NONE
                                                  )
                        except:
                            find_ns.uncache_host(tenant,instance)
                            log(syslog.LOG_ERR,"Error on connect (%s,%s) get %s" % (h,p,traceback.format_exc()))
                        dest.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        dest.sendall(d)
                    # now proxy dest<>source
                    gp.spawn(forward, dest, source)
                    return forward(source,dest)
                else:
                    log(syslog.LOG_ERR,"Give up on connection-2 h:%s,ns:%s (ibuf=%s)" % (h,ns,ibuf))
                    source.close()
                    break
            else:
                # dunno what we got, but lets not keep looking
                if len(ibuf) > 10:
                    log(syslog.LOG_ERR,"Give up on connection-3 (ibuf=%s)" % ibuf)
                    source.close()
                    break

config = ConfigParser.RawConfigParser({'sstp_port':9999,
                                       'http_port':'9998',
                                       'cert':'',
                                       'key':'',
                                       'admin_user':'admin',
                                       'admin_pass':'',
                                       'keystone_url':''})

with open('/etc/default/sstp-proxy') as r:
    ini_str= '[sstp_proxy]\n' + r.read()
    ini_fp = StringIO.StringIO(ini_str)
    config.readfp(ini_fp)

parser = argparse.ArgumentParser(description='SSTP proxy')
parser.add_argument('-sstp_port',type=int,default=config.get('sstp_proxy','sstp_port'),help='SSTP Port #')
parser.add_argument('-http_port',type=int,default=config.get('sstp_proxy','http_port'),help='HTTP Port #')
parser.add_argument('-cert',type=str,default=config.get('sstp_proxy','cert'),help='Cert')
parser.add_argument('-key',type=str,default=config.get('sstp_proxy','key'),help='Key')
parser.add_argument('-admin_user',type=str,default=config.get('sstp_proxy','admin_user'),help='Keystone admin user')
parser.add_argument('-admin_pass',type=str,default=config.get('sstp_proxy','admin_pass'),help='Keystone admin password')
parser.add_argument('-keystone_url',type=str,default=config.get('sstp_proxy','keystone_url'),help='Keystone url')

args = parser.parse_args()

if os.access(args.key, os.R_OK) == False:
    print("Error: private key %s not readable" % args.key)
    sys.exit(1)

if os.access(args.cert, os.R_OK) == False:
    print("Error: certificate %s not readable" % args.cert)
    sys.exit(1)


# This allows our app to get into a network namespace other than the default.
# to do so, open /var/run/netns/<file>, and then have @ it with the fd using
# the setns(2) call. E.g. f=open('/var/run/netns/x'); setns(f)
prctl.cap_permitted.sys_admin = True
prctl.cap_effective.sys_admin = True

fd = int(1)
source = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
source.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

gp = eventlet.greenpool.GreenPool()
gp.spawn(route,source,gp,args)
gp.waitall()


