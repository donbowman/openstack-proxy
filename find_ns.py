#!/usr/bin/python

"""

 find_ns.py: find the host-ip/namespace for a given
 tenant/instance

"""

import novaclient.client
from neutronclient.v2_0 import client as neutronclient
from keystoneclient.v2_0 import client as keystoneclient

from novaclient.v3 import servers
import memcache
import os, argparse, ctypes
import StringIO
import ConfigParser
import prctl

class NS:
    ns_fd = ""
    def setns(self, fd):
        _libc = ctypes.CDLL('libc.so.6')
        # auto detect files vs fds, fudge anything else
        try:
            fd = fd.fileno()
        except AttributeError:
            fd = int(fd)
        _libc.setns(fd,0)
    def __init__(self, ns):
        self.ns_fd = open('/var/run/netns/qrouter-%s' % ns, 'r')
        self.setns(self.ns_fd)
    def __del__(self):
        self.ns_fd.close()

def find_host(user,tenant,password,instance,keystone_url):
    h = ""
    ns_id = ""

    # Try the cache. if the router isn't there, assume the
    # user has recreated a similar instance
    try:
        mc = memcache.Client([('127.0.0.1',11211)])
        v = mc.get("%s-%s" % (tenant,instance))
        if v != None and len(v):
            if os.path.exists('/var/run/netns/qrouter-%s' % v[1]):
                ns_id = v[1]
                h = v[0]
                return h,ns_id
    except:
        print("Error on memcache get %s" % traceback.format_exc())

    keystone_cl = keystoneclient.Client(username=user,
                       password=password,
                       auth_url=keystone_url)

    tl = keystone_cl.tenants.list()
    for t in tl:
        if t.name == tenant:
            tenant_id = t.id
            break
    neutron_cl = neutronclient.Client(username=user,
                       password=password,
                       tenant_id=tenant_id,
                       auth_url=keystone_url)

    nova_cl = novaclient.client.Client(3,
                       user,
                       password,
                       tenant,
                       keystone_url)

    servers = nova_cl.servers.list()

    for s in servers:
        if s.name.lower() == instance.lower():
            ports = neutron_cl.list_ports(device_owner='network:router_interface')
            mports = neutron_cl.list_ports(device_id=s.id)
            for myport in mports['ports']:
                for psn in ports['ports']:
                    if psn['network_id'] == myport['network_id']:
                        h = str(myport['fixed_ips'][0]['ip_address'])
                        ns_id = str(psn['device_id'])
                        break

    if (h==""):
        print("Error: host %s not found" % instance)
    if (ns_id == ""):
        print("Error: namespace not found for instance %s" % instance)

    try:
        if (len(h)):
            v = mc.set("%s-%s" % (tenant,instance), [h,ns_id], 900)
    except:
        pass

    return str(h),ns_id

def do_args():
    def_url = ''
    def_user = ''
    def_password = ''
    def_tenant = ''

    try:
        config = ConfigParser.RawConfigParser({'admin_user':'admin',
                                               'admin_pass':'',
                                               'keystone_url':''})
        with open('/etc/default/sstp-proxy') as r:
            ini_str= '[sstp_proxy]\n' + r.read()
            ini_fp = StringIO.StringIO(ini_str)
            config.readfp(ini_fp)
        def_url = config.get('sstp_proxy','keystone_url')
        def_user = config.get('sstp_proxy','admin_user')
        def_password = config.get('sstp_proxy','admin_pass')
    except:
        pass

    config = ConfigParser.RawConfigParser({'user':'',
                                           'password':'',
                                           'tenant':'',
                                           'host':'' })

    parser = argparse.ArgumentParser(description='NSNC')
    parser.add_argument('-user',type=str,default=def_user,help='Username')
    parser.add_argument('-password',type=str,default=def_password,help='Password')
    parser.add_argument('-tenant',type=str,default='',help='Tenant')
    parser.add_argument('-host',type=str,default='',help='Host')
    parser.add_argument('-auth_url',type=str,default=def_url,help='Auth-Url')

    args = parser.parse_args()
    return args

