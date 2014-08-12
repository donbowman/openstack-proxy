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

import novaclient.client
from neutronclient.v2_0 import client as neutronclient
import traceback, sys

from novaclient.v3 import servers
import eventlet
import ssl, re, os, argparse, sys
import StringIO
import ConfigParser
import syslog
import ctypes
import prctl

def setns(fd):
    _libc = ctypes.CDLL('libc.so.6')
    # auto detect files vs fds, fudge anything else
    try:
        fd = fd.fileno()
    except AttributeError:
        fd = int(fd)
    _libc.setns(fd,0)



# expects /path/sra_
# we might have:
# /user/project/instance (in which case we find the specific nova instance)
# or /user/project (in which case we find the first nova instance)
# We assume that either:
#  a) there is no router in this instance (L2 only), in which case no setns
#  b) there is exactly 1 interesting router (L3), in which case we 
#     assume it can reach our host
def find_host(s,admin_user,admin_password,keystone_url):
    h = "unknown"
    p = 443
    ns_id = ""
    path = s.split('/')
    if len(path) < 4:
        return (h,p)

    user = path[1]
    project = path[2]

    # the case where we have user but not path, use first server
    if len(path) == 4:
        ss = ".*"
    else:
        ss = path[3]

    try:
        neutron_cl = neutronclient.Client(username=admin_user,
                           password=admin_password,
                           tenant_name=project,
                           auth_url=keystone_url)
        rtrs = neutron_cl.list_routers();
        if (len(rtrs) == 1):
            ns_id = rtrs['routers'][0]['id']
        else:
            for r in rtrs:
                if re.search("%s-rtr" % ss, r['name']):
                    ns_id = r['id']

    except:
        syslog.syslog(syslog.LOG_ERR,"Error getting neutron router-list... Will try without namespace")
        syslog.syslog(syslog.LOG_ERR,"Exc: %s" % traceback.format_exc())

    nova_cl = novaclient.client.Client(3,
                       admin_user,
                       admin_password,
                       project,
                       keystone_url)


    try:
        servers = nova_cl.servers.list()
    except:
        syslog.syslog(syslog.LOG_ERR,"Error getting info from nova for sstp-proxy")
        return "",0

    for s in servers:
        if re.search("%s-vpn" % ss, s.name):
            for i in s.networks:
                if (len(s.networks[i])):
                    h = str(s.networks[i][0])

    return str(h),p,ns_id

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

def forward(source,admin_user,admin_password,keystone_url):
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
                h, p, ns = find_host(result.groups()[0],
                                 admin_user,
                                 admin_password,
                                 keystone_url)
                ibuf = re.sub("^SSTP_DUPLEX_POST.*/sra_","SSTP_DUPLEX_POST /sra_", ibuf)
            else:
                if ibuf.startswith('S') != True:
                    h = "localhost"
                    p = 443
            if (h != ""):
                syslog.syslog(syslog.LOG_INFO,"Connect SSTP proxy to %s:%d (ns=%s)" % (h,p,ns))
                try:
                    if (ns != ""):
                        f = open('/var/run/netns/qrouter-%s' % ns, 'r')
                        setns(f)
                    dest = eventlet.wrap_ssl(eventlet.connect((h,p)),
                                           cert_reqs=ssl.CERT_NONE
                                          )
                    eventlet.spawn_n(rforward, dest, source)
                    if (ns != ""):
                        f.close()
                except:
                    if (ns != ""):
                        f.close()
                    source.close()
                    break
                d = ibuf
        if dest:
            try:
                dest.sendall(d)
            except:
                dest.close()
                source.close()

config = ConfigParser.RawConfigParser({'port':9999,
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
parser.add_argument('-port',type=int,default=config.get('sstp_proxy','port'),help='Port #')
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
    print("Error: certificate %s not readable" % args.key)
    sys.exit(1)

listener = eventlet.wrap_ssl(eventlet.listen(('', args.port)),
                             server_side = True,
                             certfile = args.cert,
                             keyfile = args.key)

# This allows our app to get into a network namespace other than the default.
# to do so, open /var/run/netns/<file>, and then have @ it with the fd using
# the setns(2) call. E.g. f=open('/var/run/netns/x'); setns(f)
prctl.cap_permitted.sys_admin = True
prctl.cap_effective.sys_admin = True
#f = open('/var/run/netns/qrouter-821b625c-8b12-46cd-b2f1-92455ce82ebf', 'r')
#setns(f)

while True:
    xcl, addr = listener.accept()
    syslog.syslog(syslog.LOG_INFO, "accepted connection %s %s" % (xcl, addr))
    eventlet.spawn_n(forward, xcl,args.admin_user,args.admin_pass,args.keystone_url)

