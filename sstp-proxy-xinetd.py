#!/usr/bin/python

"""

 sstp-proxy: SSTP routing proxy

A simple eventlet-based proxy server to take in SSL of SSTP
format and route to a specific virtual machine inside our
private cloud

We expect a path of: /tenant/user/instance

"""

import novaclient.client
from neutronclient.v2_0 import client as neutronclient
import traceback, sys

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

import eventlet
eventlet.monkey_patch()

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
def find_host(s,admin_user,admin_password,keystone_url):
    user = ""
    h = ""
    ns_id = ""
    path = s.split('/')
    if len(path) < 4:
        path = s.split('.')
        if len(path) == 6:
            user = path[0]
            tenant = path[1]
            instance = path[2]
    else:
        user = path[1]
        tenant = path[2]
        instance = path[3]

    if (user == ""):
        return (h,ns_id)

    log(syslog.LOG_INFO,"find_host user:%s, tenant:%s, instance=%s" % (user,tenant,instance))

    nova_cl = ""
    neutron_cl = ""

    # Sometimes we are getting a 'no connection' to
    # nova api, added retry logic with exponential backoff
    for retry in range(0,4):
        try:
            if neutron_cl != "":
                del neutron_cl
            neutron_cl = neutronclient.Client(username=admin_user,
                               password=admin_password,
                               tenant_name=tenant,
                               auth_url=keystone_url)


            if nova_cl != "":
                del nova_cl
            nova_cl = novaclient.client.Client(3,
                               admin_user,
                               admin_password,
                               tenant,
                               keystone_url,
                               timeout=3)

            servers = nova_cl.servers.list()
            routers = neutron_cl.list_routers()

            for s in servers:
                if s.name.lower() == instance.lower():
                    for i in s.networks:
                        if (len(s.networks[i])):
                            h = str(s.networks[i][0])
                            # how to find ns_id for router on net?
                            net = neutron_cl.list_networks(name=i)
                            snet = net['networks'][0]['subnets'][0]
                            ports = neutron_cl.list_ports(device_owner='network:router_interface')
                            for p in ports['ports']:
                                tsn = p['fixed_ips'][0]['subnet_id']    
                                if (tsn == snet):
                                    ns_id = p['device_id']
                                    break
                    break
            log(syslog.LOG_INFO,"host: %s, ns_id: %s" % (h, ns_id))
            return (h,ns_id)
        except requests.exceptions.ConnectionError as e:
            log(syslog.LOG_ERR,"Error: Exception contacting neutron/nova (retry=%d)" % retry)
            # If neutron/nova get restarted, we can end up with bad cached credential token,
            # and i don't know how to flush it. Respawn is enabled in upstart
            if (retry > 2):
                sys.exit(0)
            sleep(1 * retry*retry)
        except Exception as e:
            log(syslog.LOG_ERR,"Error: Misc Exception contacting neutron/nova")
            sys.exit(0)
            break

    log(syslog.LOG_ERR,"Error: host %s not found (exhausted retries)" % instance)
    return (h,ns_id)


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
            #CONNECT https://don.don.don-vpn.vpn.sandvine.rocks:9999:443 HTTP/1.1
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
                    log(syslog.LOG_INFO,"Connect proxy to %s:%d (ns=%s), init buf=<%s>" % (h,p,ns,ibuf))
                    setns(ns)
                    if result_connect != None:
                        log(syslog.LOG_INFO,"to send 200OK")
                        dest = eventlet.connect((h,p))
                        source.sendall("HTTP/1.0 200 Connection established\r\n\r\n")
                    else:
                        dest = eventlet.wrap_ssl(eventlet.connect((h,p)),
                                               cert_reqs=ssl.CERT_NONE
                                              )
                        dest.sendall(d)
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

gp = eventlet.greenpool.GreenPool()
gp.spawn(route,source,gp,args)
gp.waitall()


