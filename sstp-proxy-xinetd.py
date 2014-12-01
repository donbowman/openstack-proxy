#!/usr/bin/python

"""

 sstp-proxy: SSTP routing proxy

A simple eventlet-based proxy server to take in SSL of SSTP
format and route to a specific virtual machine inside our
private cloud

We expect a path of: /tenant/user/instance

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
from time import sleep
import requests
import memcache

import eventlet
eventlet.monkey_patch()

syslog.openlog(ident="sstp-proxy",logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)
#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
#sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

_libc = ctypes.CDLL('libc.so.6')
current_ns = ""
current_ns_fd = ""

def setns(ns):
    global _libc
    global current_ns
    global current_ns_fd
    if current_ns_fd != "":
        current_ns_fd.close()
        current_ns_fd = ""
    current_ns = ns
    if len(ns):
        current_ns_fd = open('/var/run/netns/qrouter-%s' % ns, 'r')
        fd = current_ns_fd.fileno()
        _libc.setns(fd,0)

def log(severity,txt):
    if (os.isatty(1)):
        print(txt)
    else:
        syslog.syslog(severity,txt)


# expects /path/sra_/tenant/user/instance 
# or Host: tenant.user.instance.vpn.sandvine.rocks
# or Host: tenant.instance.vpn.sandvine.rocks
def find_host(s,admin_user,admin_password,keystone_url):
    tenant = ""
    h = ""
    ns_id = ""
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

    if (tenant == ""):
        return (h,ns_id)

    try:
        mc = memcache.Client([('127.0.0.1',11211)])
        v = mc.get("%s-%s" % (tenant,instance))
        if v != None and len(v):
            if os.path.exists('/var/run/netns/qrouter-%s' % v[1]):
                ns_id = v[1]
                h = v[0]
                log(syslog.LOG_INFO,"find_host tenant:%s, instance=%s ->cached %s (%s)" % (tenant,instance,h,ns_id))
                return h,ns_id
    except:
        log(syslog.LOG_ERR,"Error on memcache get %s" % traceback.format_exc())

    log(syslog.LOG_INFO,"find_host tenant:%s, instance=%s" % (tenant,instance))

    keystone_cl = keystoneclient.Client(username=admin_user,
                       password=admin_password,
                       auth_url=keystone_url)

    tl = keystone_cl.tenants.list()
    for t in tl:
        if t.name == tenant:
            tenant_id = t.id
            break

    neutron_cl = neutronclient.Client(username=admin_user,
                       password=admin_password,
                       tenant_id=tenant_id,
                       auth_url=keystone_url)

    nova_cl = novaclient.client.Client(3,
                       admin_user,
                       admin_password,
                       tenant,
                       keystone_url)

    servers = nova_cl.servers.list()

    for s in servers:
        if s.name.lower() == instance.lower():
            for i in s.networks:
                if (len(ns_id) == 0 and len(s.networks[i])):
                    h = str(s.networks[i][0])
                    # how to find ns_id for router on net?
                    net = neutron_cl.list_networks(name=i,tenant_id=tenant_id)
                    snet = net['networks'][0]['subnets'][0]
                    ports = neutron_cl.list_ports(device_owner='network:router_interface')
                    for p in ports['ports']:
                        tsn = p['fixed_ips'][0]['subnet_id']    
                        if tsn == snet and len(p['device_id']):
                            ns_id = p['device_id']
                            if (len(ns_id)):
                                break
            break


    if (h==""):
        log(syslog.LOG_ERR,"Error: host %s not found" % instance)
    if (ns_id == ""):
        log(syslog.LOG_ERR,"Error: namespace not found for instance %s" % instance)

    try:
        if (len(h)):
            v = mc.set("%s-%s" % (tenant,instance), [h,ns_id], 900)
    except:
        log(syslog.LOG_ERR,"Error on memcache set")
        pass

    return str(h),ns_id


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
            if result_sra != None or result_host != None or result_connect != None:
                if result_connect != None:
                    ibuf = ""
                    h, ns = find_host(result_connect.groups()[0],
                                     args.admin_user,
                                     args.admin_pass,
                                     args.keystone_url)
                if (h == "" and result_sra != None):
                    h, ns = find_host(result_sra.groups()[0],
                                     args.admin_user,
                                     args.admin_pass,
                                     args.keystone_url)

                if (h == "" and result_host != None):
                    h, ns = find_host(result_host.groups()[0],
                                     args.admin_user,
                                     args.admin_pass,
                                     args.keystone_url)

                ibuf = re.sub("^SSTP_DUPLEX_POST.*/sra_","SSTP_DUPLEX_POST /sra_", ibuf)
                ibuf = re.sub(":[0-9]+", "", ibuf)
                if (h != "" and ns != ""):
                    d = ibuf
                    log(syslog.LOG_INFO,"Connect proxy to %s:%d (ns=%s)" % (h,p,ns))
                    setns(ns)
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


