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

# tenant might have dot, complicates parsing.
# disallow dots in instance(host) name
# don.n1.vpn.sandvine.rocks
# /don/db-vpn/sra_
# vhost--tenant.instance.vpn.sandvine.rocks
# vhost.instance.outreach.sandvine.rocks
def result_instance_tenant(s):
    tenant = ""
    instance = ""
    m = re.search("(.*)\.(.*)\.outreach.sandvine.rocks",s)
    if (m != None and len(m.groups()) == 2):
        # hardcode the tenant to outreach, accept vhost.instance.outreach.sandvine.rocks
        # as syntax, returning outreach,instance
        return "outreach",m.groups()[1]
    s1 = re.sub("/sra_$","", s)
    s1 = re.sub("\.vpn.sandvine.rock.*$","", s1)
    s1 = re.sub("\.sandvine.rock.*$","", s1)
    path = s1.split('/')
    if (len(path) == 3):
        tenant = path[1]
        instance = path[2]
    else:
        m = re.search("(.*)\.([^.]*$)",s1)
        if (len(m.groups()) == 2):
            tenant = m.groups()[0]
            instance = m.groups()[1]
    s = re.split("--",tenant)
    if (len(s) == 2):
        tenant = s[1]
    log(syslog.LOG_INFO,"result_instance_tenant(%s) -> %s,%s" % (s,tenant,instance))
    return tenant,instance

def route(source,gp,args):
    dest = ""
    ibuf = ""
    p = args.output_port
    ns = None

    while True:
        d = source.recv(32384)
        if d == '':
            break
        if dest == "":
            h = ""
            ibuf = ibuf + d
            #print >> sys.stderr, "result: %s" % ibuf
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
                            if (args.output_tls):
                                dest = eventlet.wrap_ssl(eventlet.connect((h,p)),
                                                       cert_reqs=ssl.CERT_NONE
                                                      )
                            else:
                                dest = eventlet.connect((h,p))
                            dest.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            dest.sendall(d)
                        except:
                            find_ns.uncache_host(tenant,instance)
                            log(syslog.LOG_ERR,"Error on connect (%s,%s) get %s" % (h,p,traceback.format_exc()))
                    if dest != None:
                        # now proxy dest<>source
                        gp.spawn(forward, dest, source)
                        return forward(source,dest)
                    else:
                        log(syslog.LOG_ERR,"Give up on connection-2 h:%s,ns:%s (ibuf=%s)" % (h,ns,ibuf))
                        source.close()
                        break
                else:
                    log(syslog.LOG_ERR,"Give up on connection-3 h:%s,ns:%s (ibuf=%s)" % (h,ns,ibuf))
                    source.close()
                    break
            else:
                # dunno what we got, but lets not keep looking
                if len(ibuf) > 10:
                    log(syslog.LOG_ERR,"Give up on connection-3 (ibuf=%s)" % ibuf)
                    source.close()
                    break

config = ConfigParser.RawConfigParser({'output_port':'443',
                                       'output_tls':'true',
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
parser.add_argument('-output_port',type=int,default=443)
parser.add_argument('-output_tls',type=str,default='true')
parser.add_argument('-cert',type=str,default=config.get('sstp_proxy','cert'),help='Cert')
parser.add_argument('-key',type=str,default=config.get('sstp_proxy','key'),help='Key')
parser.add_argument('-admin_user',type=str,default=config.get('sstp_proxy','admin_user'),help='Keystone admin user')
parser.add_argument('-admin_pass',type=str,default=config.get('sstp_proxy','admin_pass'),help='Keystone admin password')
parser.add_argument('-keystone_url',type=str,default=config.get('sstp_proxy','keystone_url'),help='Keystone url')

args = parser.parse_args()

if (args.output_tls == 'true' or args.output_tls == 'True' or args.output_tls == '1'):
    args.output_tls = True
else:
    args.output_tls = False

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


