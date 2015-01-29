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
import StringIO, sys
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

def uncache_host(tenant,instance):
    mc = memcache.Client([('127.0.0.1',11211)])
    if mc != None:
        mc.delete("%s-%s" % (tenant,instance))

def mkey(x):
    if len(x['fixed_ips']):
        v = x['fixed_ips'][0]['ip_address']
    else:
        v= ''
    return v

# Get a connection to keystone/neutron/nova, locked to our
# tenant
def get_conns(user,tenant,password,keystone_url):
    keystone_cl = keystoneclient.Client(username=user,
                       password=password,
                       auth_url=keystone_url)

    tl = keystone_cl.tenants.list()
    for t in tl:
        if t.name == tenant:
            tenant_id = t.id
            break
    if tenant_id == None:
        print >> sys.stderr, "Error finding tenant for %s,%s" % (user,tenant)
    neutron_cl = neutronclient.Client(username=user,
                       password=password,
                       tenant_id=tenant_id,
                       auth_url=keystone_url)

    nova_cl = novaclient.client.Client(3,
                       user,
                       password,
                       tenant,
                       keystone_url)

    return keystone_cl,neutron_cl,nova_cl,tenant_id

def find_ns(user,tenant,password,rtr,keystone_url):
    ns_id = None
    # Try the cache. 
    try:
        mc = memcache.Client([('127.0.0.1',11211)])
        v = mc.get("%s-%s" % (tenant,rtr))
        if v != None and len(v) and os.path.exists('/var/run/netns/qrouter-%s' % v[0]):
            ns_id = v[0]
            return ns_id
    except:
        print("Error on memcache get %s" % traceback.format_exc())
    #import pdb; pdb.set_trace()

    keystone_cl,neutron_cl,nova_cl,tenant_id = get_conns(user,tenant,password,keystone_url)
    rtrs = neutron_cl.list_routers(tenant_id=tenant_id,name=rtr)

    if len(rtrs) and len(rtrs['routers']) == 1:
        ns_id = rtrs['routers'][0]['id']

    try:
        if (len(ns_id)):
            v = mc.set("%s-%s" % (tenant,rtr), ns_id, 900)
    except:
        pass
    return ns_id

def find_host(user,tenant,password,instance,keystone_url):
    h = None
    ns_id = ""
    v = None
    tenant_id = None

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

    keystone_cl,neutron_cl,nova_cl,tenant_id = get_conns(user,tenant,password,keystone_url)

    servers = nova_cl.servers.list()

    for s in servers:
        if s.name.lower() == instance.lower():
            ports = neutron_cl.list_ports(tenant_id=tenant_id,device_owner='network:router_interface')
            mports = neutron_cl.list_ports(device_id=s.id)
            #import pdb; pdb.set_trace()

            sports = sorted(mports['ports'],key=mkey)
            for i in range(len(sports)-1,-1,-1):
                if len(sports[i]['fixed_ips']) == 0:
                    del sports[i]

            rports = sorted(ports['ports'],key=mkey)
            for i in range(len(rports)-1,-1,-1):
                if len(rports[i]['fixed_ips']) == 0:
                    del rports[i]
            for myport in rports:
                for psn in sports:
                    if h == None and psn['network_id'] == myport['network_id']:
                        h = str(psn['fixed_ips'][0]['ip_address'])
                        ns_id = str(myport['device_id'])
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

#find_ns('don','don','random-password','x-pptp-rtr','https://nubo-7.sandvine.rocks:5000/v2.0')

