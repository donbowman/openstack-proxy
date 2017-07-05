#!/usr/bin/python

"""

 find_ns.py: find the host-ip/namespace for a given
 tenant/instance

"""

import novaclient.client
from neutronclient.v2_0 import client as neutronclient
from keystoneclient.v2_0 import client as keystoneclient

try:
    from novaclient.v2 import servers
except:
    from novaclient.v3 import servers

import traceback
import memcache
import os, argparse, ctypes
import StringIO, sys
import ConfigParser
import prctl
import syslog
import re
import pprint

syslog.openlog(ident="openstack-proxy",logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

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
        try:
            self.ns_fd = open('/var/run/netns/qrouter-%s' % ns, 'r')
            self.setns(self.ns_fd)
        except:
            print >> sys.stderr, ("Error: router '%s' does not exist. It might be still in progress" % ns)
            raise Exception("NoRouter")
    def __del__(self):
        try:
            self.ns_fd.close()
        except:
            pass

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


# Allow an arbitrary number of vhost before the name
# e.g. tenant.instance.vpn.sandvine.rocks
# e.g. vhost.tenant.instance.vpn.sandvine.rocks
# e.g. vhost1.vhost2.tenant.instance.vpn.sandvine.rocks
# this also works if the tenant has a dot in the name (and it will hit the memcache
# eventually and then stick

# Get a connection to keystone/neutron/nova, locked to our
# tenant
def get_conns(user,tenant,password,keystone_url):
    tenant_id = None
    keystone_cl = keystoneclient.Client(username=user,
                       password=password,
                       auth_url=keystone_url)

    tl = keystone_cl.tenants.list()
    for t in tl:
        if t.name == tenant:
            tenant_id = t.id
            break
    if tenant_id == None:
        ntenant = re.sub("[^.]+.(.*)",r'\1', tenant)
        if (ntenant != tenant):
            return get_conns(user,ntenant,password,keystone_url)
        else:
            return None,None,None

    neutron_cl = neutronclient.Client(username=user,
                       password=password,
                       tenant_id=tenant_id,
                       auth_url=keystone_url)

    nova_cl = novaclient.client.Client("2",
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

    syslog.syslog(syslog.LOG_INFO,"Tenant:%s, User:%s, Router: %s --1" % (tenant,user,rtr))
    keystone_cl,neutron_cl,nova_cl,tenant_id = get_conns(user,tenant,password,keystone_url)
    if (tenant_id == None):
        return None
    rtrs = neutron_cl.list_routers(tenant_id=tenant_id,name=rtr)

    if len(rtrs) and len(rtrs['routers']) == 1:
        ns_id = rtrs['routers'][0]['id']

    try:
        if (len(ns_id)):
            v = mc.set("%s-%s" % (tenant,rtr), ns_id, 300)
    except:
        pass
    return ns_id

def find_host(user,tenant,password,instance,keystone_url,shared_subnet_id = None, shared_router_id = None):
    h = None
    ns_id = ""
    v = None
    tenant_id = None
    floating = None

    dbg = {}

    # Try the cache. if the router isn't there, assume the
    # user has recreated a similar instance
    try:
        mc = memcache.Client([('127.0.0.1',11211)])
        v = mc.get("%s-%s" % (tenant,instance))
        if v != None and len(v):
            if os.path.exists('/var/run/netns/qrouter-%s' % v[1]):
                if (len(v) > 1):
                    floating = v[2]
                ns_id = v[1]
                h = v[0]
                return h,ns_id,floating
    except:
        print >> sys.stderr, ("Error on memcache get %s" % traceback.format_exc())

    syslog.syslog(syslog.LOG_INFO,"Tenant:%s, User:%s, Host: %s --2" % (tenant,user,instance))
    #import pdb; pdb.set_trace()
    try:
        keystone_cl,neutron_cl,nova_cl,tenant_id = get_conns(user,tenant,password,keystone_url)
    except:
        print >> sys.stderr, ("Error on kkeystone get %s,%s,%s,%s" % (user,tenant,password,keystone_url))
        return None,None,None
    if (tenant_id == None):
        return None,None,None

    servers = nova_cl.servers.list()

    dbg['all_servers'] = servers

    for s in servers:
        if h == None and s.name.lower() == instance.lower():
            ports = neutron_cl.list_ports(tenant_id=tenant_id,device_owner='network:router_interface')
            mports = neutron_cl.list_ports(device_id=s.id)

            dbg['instance_name'] = s
            dbg['ports'] = ports
            dbg['mports'] = mports

            sports = sorted(mports['ports'],key=mkey)
            dbg['sports'] = sports
#            import pdb; pdb.set_trace()
            for i in range(len(sports)-1,-1,-1):
                if len(sports[i]['fixed_ips']) == 0:
                    del sports[i]
                else:
                    if sports[i]['fixed_ips'][0]['subnet_id'] == shared_subnet_id:
                        h = str(sports[i]['fixed_ips'][0]['ip_address'])
                        ns_id = shared_router_id
                        break

            if h != None:
                break

            rports = sorted(ports['ports'],key=mkey)
            dbg['rports'] = rports
            for i in range(len(rports)-1,-1,-1):
                if len(rports[i]['fixed_ips']) == 0:
                    del rports[i]
            for myport in rports:
                for psn in sports:
                    if h == None and psn['network_id'] == myport['network_id']:
                        h = str(psn['fixed_ips'][0]['ip_address'])
                        ns_id = str(myport['device_id'])
                        for addr in s.addresses:
                            for j in range(len(s.addresses[addr])-1,-1,-1):
                                type = s.addresses[addr][j]['type']  if 'type' in s.addresses[addr][j] else s.addresses[addr][j]['OS-EXT-IPS:type']
                                if type == 'floating':
                                    floating = s.addresses[addr][j]['addr']
                        break

#    import pdb; pdb.set_trace()
    if (h==None):
        print >> sys.stderr, ("Error: host %s not found" % instance)
    if (ns_id == None):
        print >> sys.stderr, ("\nError: namespace not found for instance %s\nYou need to have a routed interface connected\n" % instance)
        pprint.pprint(dbg, stream=sys.stderr)
#        import pdb; pdb.set_trace()
#        print >> sys.stderr, ("\nDebug: %s\n" % dbg)

    try:
        if (len(h)):
            v = mc.set("%s-%s" % (tenant,instance), [h,ns_id,floating], 300)
    except:
        pass

    return str(h),ns_id,floating

def find_tenant_name(user,tenant,password,keystone_url):
    tenant_name = None

    # Try the cache.
    try:
        mc = memcache.Client([('127.0.0.1',11211)])
        v = mc.get("%s" % (tenant))
        if v != None and len(v):
            return v
    except:
        print >> sys.stderr, ("Error on memcache get %s" % traceback.format_exc())

    syslog.syslog(syslog.LOG_INFO,"TenantID:%s" % tenant)

    keystone_cl = keystoneclient.Client(username=user,
                       password=password,
                       auth_url=keystone_url)

    tl = keystone_cl.tenants.list()
    for t in tl:
        if t.id == tenant:
            tenant_name = t.name
    if (tenant_name == None):
        return None
    try:
        mc = memcache.Client([('127.0.0.1',11211)])
        mc.set("%s" % tenant, tenant_name, 300)
    except:
        pass
    return tenant_name

def do_args():
    def_url = ''
    def_user = ''
    def_password = ''
    def_tenant = ''
    def_fqdn = ''
    def_shared_subnet_id = ''
    def_shared_router_id = ''
    def_test = False

    try:
        config = ConfigParser.RawConfigParser({'admin_user':'admin',
                                               'admin_pass':'',
                                               'keystone_url':'',
                                               'shared_subnet_id':'',
                                               'shared_router_id':'',
                                               'test':False,
                                               })
        with open('/etc/default/sstp-proxy') as r:
            ini_str= '[sstp_proxy]\n' + r.read()
            ini_fp = StringIO.StringIO(ini_str)
            config.readfp(ini_fp)
        def_url = config.get('sstp_proxy','keystone_url')
        def_user = config.get('sstp_proxy','admin_user')
        def_password = config.get('sstp_proxy','admin_pass')
        def_shared_subnet_id = config.get('sstp_proxy','shared_subnet_id')
        def_shared_router_id = config.get('sstp_proxy','shared_router_id')
    except:
        pass

    config = ConfigParser.RawConfigParser({'user':'',
                                           'password':'',
                                           'tenant':'',
                                           'host':'',
                                           'fqdn':'',
                                           'shared_subnet_id':'',
                                           'shared_router_id':'',
                                           'test':False
                                           })

    parser = argparse.ArgumentParser(description='NSNC')
    parser.add_argument('-user',type=str,default=def_user,help='Username')
    parser.add_argument('-password',type=str,default=def_password,help='Password')
    parser.add_argument('-tenant',type=str,default='',help='Tenant')
    parser.add_argument('-host',type=str,default='',help='Host')
    parser.add_argument('-fqdn',type=str,default='',help='Fqdn')
    parser.add_argument('-auth_url',type=str,default=def_url,help='Auth-Url')
    parser.add_argument('-shared_subnet_id',type=str,default=def_shared_subnet_id,help='Shared Subnet-id')
    parser.add_argument('-shared_router_id',type=str,default=def_shared_router_id,help='Shared Router-id')
    parser.add_argument('-test',default=False,help='Test-mode', action='store_true')

    args = parser.parse_args()
    if (len(args.fqdn)):
        s = args.fqdn.split(".")
        args.tenant = s[0]
        args.host = s[1]
    return args

