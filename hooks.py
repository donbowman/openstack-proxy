#!/usr/bin/env python
# coding: utf-8
#
# pppd hooks.
# Make sure pppd_pyhook.so is in the pppd plugins directory and deploy
# this file in /etc/ppp/ to enable it.

import syslog, sys, random,subprocess, re, os
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

# What's this you ask?
# Well, our parent is reaping SIGCHLD, and if
# we use popen, we are screwed.
# And, keystone calls keyring, which calls uname.
import platform
def __syscmd_uname(option,default=""):
    return "x86_64"

platform._syscmd_uname = __syscmd_uname

sys.argv[0] = "pptpd"
sys.path.insert(1, "/home/jump/openstack-proxy")
import find_ns

syslog.openlog(ident="pptp-hooks", logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

def sendAcct(ns, user,ip,action):
    srv=Client(server="172.16.3.1",
               secret="",
               dict=Dictionary("/etc/ppp/aaa-dictionary"))

    import types
    def setRetryTimeout(self, r,t):
        self.retries = r
        self.timeout = t

    srv.setRetryTimeout = types.MethodType( setRetryTimeout, srv)

    srv.setRetryTimeout(1,0)

    req=srv.CreateAcctPacket(User_Name=user)

#    req["NAS-IP-Address"]="192.168.1.10"
#    req["NAS-Port"]=0
#    req["NAS-Identifier"]="trillian"
#    req["Called-Station-Id"]="00-04-5F-00-0F-D1"
#    req["Calling-Station-Id"]="00-01-24-80-B3-9C"
    req["Framed-IP-Address"]=ip

    req["Acct-Status-Type"]=action
    x = find_ns.NS(ns)
    try:
        srv.SendPacket(req)
    except:
        pass
    x.__del__()


# parse_user parses the username string and returns user, tenant and instance.
# It supports two formats: user@tenant/instance and user@tenant|instance, the
# latter is to support Windows clients since "/" isn't a valid character
# for PPTP user names on that OS.
def parse_user(info):
    parts = info.split("@")
    assert len(parts) == 2, "malformed user name"

    user = parts[0]
    info = parts[1]
    parts = info.split("/")
    if len(parts) != 2:
        parts = info.split("|") # Support for Windows clients.
    if len(parts) != 2:
        parts = info.split("+") # Support for Windows clients.
    assert len(parts) == 2, "malformed tenant/instance info"

    tenant = parts[0]
    instance = parts[1]

    return user, tenant, instance

def get_secret_for_user(user, ipparam):
    global ppp_user, namespace_id, vpn_ip
    tenant = ""
    instance = ""
    syslog.syslog(syslog.LOG_INFO, "get_secret_for_user(%s,%s)" % (user,ipparam))
    try:
        # ppp_user is required for ip-up and ip-down.
        ppp_user, tenant, instance = parse_user(user)
    except AssertionError, e:
        syslog.syslog(syslog.LOG_INFO, "wrong format for user '%s': %s" % user, e)
        return str(random.random())

    syslog.syslog(syslog.LOG_INFO, "connecting user %s with ipparam %s" % (user, ipparam))

    try:
        args = find_ns.do_args()
        vpn_ip, ns, h = find_ns.find_host(args.user, tenant, args.password, instance, args.auth_url)
        #syslog.syslog(syslog.LOG_INFO, "namespace for %s %s is %s" % (tenant, instance, ns))
        assert ns != "", "empty namespace"
        namespace_id = ns
    except:
        syslog.syslog(syslog.LOG_INFO, "could not find namespace for %s %s" % (tenant, instance))
        return str(random.random())

    return "cl0ud"

def allowed_address_hook(ip):
    syslog.syslog(syslog.LOG_INFO, "allowed_address_hook %s" % ip)
    return True

def chap_check_hook():
    syslog.syslog(syslog.LOG_INFO, "chap_check_hook")
    return True

def ip_up_notifier(ifname, localip, remoteip):
    global rad_session
    global ppp_table
    global ppp_user
    global ppp_addr
    global ppp_ifname
    global namespace_id
    global vpn_ip

    ppp = 0
    try:
        ppp = int(ifname[3:])
    except Exception, e:
        syslog.syslog(syslog.LOG_INFO, "failed to parse pppN from: %s" % ifname)
        return

    # used by ip-down
    ppp_table = 1000 + ppp
    ppp_addr = remoteip
    ppp_ifname = ifname

    ns = "qrouter-%s" % namespace_id
    v0 = "veth-%s-ext" % ifname
    v0_ip = "10.1.%u.1" % ppp
    v1 = "veth-%s-int" % ifname
    v1_ip = "10.1.%u.2" % ppp

    p = subprocess.Popen(["/sbin/ifconfig", ifname], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ifc = p.communicate()[0]
    peer = ""
    try:
        peer = re.match(r".*P-t-P:([^\s]*)", ifc, re.MULTILINE|re.DOTALL).groups()[0]
    except Exception, e:
        syslog.syslog(syslog.LOG_ERR, "failed to get %s address: %s" % (ifname, e))
        return

    # the initial del handle the case where we crashed out somehow w/o cleanup
    f = "/tmp/%s-up.sh" % ifname
    with open(f, "w") as fd:
        fd.write("#!/bin/bash\n")
        fd.write("set -x\n")
        fd.write("/sbin/ip link del %s\n" % v0)
        fd.write("/sbin/ip netns exec %s /sbin/ip link del %s\n" % (v0,v1))
        fd.write("/sbin/ip link add %s type veth peer name %s\n" % (v0, v1))
        fd.write("/sbin/ip link set %s netns %s\n" % (v1, ns))
        fd.write("/sbin/ifconfig %s inet %s/30\n" % (v0, v0_ip))
        fd.write("/sbin/ip rule add dev %s table %s\n" % (ifname, ppp_table))
        fd.write("/sbin/ip route add default via %s table %d\n" % (v1_ip, ppp_table))
        fd.write("/sbin/ip netns exec %s route add 172.16.3.1/32 gw %s\n" % (ns, vpn_ip))
        fd.write("/sbin/ip netns exec %s ifconfig %s inet %s/30\n" % (ns, v1, v1_ip))
        fd.write("/sbin/ip netns exec %s ip route add %s via %s\n" % (ns, peer, v0_ip))
        fd.write("/sbin/ip netns exec %s ip rule add dev %s table %d\n" % (ns, v1, ppp_table))
        fd.write("/sbin/ip netns exec %s ip route add default via %s table %d\n" % (ns, vpn_ip, ppp_table))
    os.system("bash %s > %s.log 2>&1" % (f,f))
#    os.unlink(f)
    sendAcct(namespace_id, ppp_user,remoteip,"Start")

def ip_down_notifier(arg):
    global ppp_table
    global ppp_user
    global ppp_addr
    global ppp_ifname
    global namespace_id
    global vpn_ip

    ppp = int(ppp_ifname[3:])

    ns = "qrouter-%s" % namespace_id
    v0_ip = "10.1.%u.1" % ppp
    v1 = "veth-%s-int" % ppp_ifname
    sendAcct(namespace_id, ppp_user,ppp_addr,"Start")
    f = "/tmp/%s-down.sh" % ppp_ifname
    with open(f, "w") as fd:
        fd.write("#!/bin/bash\n")
        fd.write("set -x\n")
        fd.write("/sbin/ip link del veth-%s-ext\n" % ppp_ifname)
        fd.write("/sbin/ip rule del dev %s\n" % ppp_ifname)
        fd.write("/sbin/ip netns exec %s ip rule del dev %s\n" % (ns, v1))
        fd.write("/sbin/ip netns exec %s ip route flush table %d\n" % (ns, ppp_table))
    os.system("bash %s > %s.log 2>&1" % (f,f))
#    os.unlink(f)

def auth_up_notifier(arg):
    syslog.syslog(syslog.LOG_INFO, "auth_up_notifier %s" % arg)
    pass

def link_down_notifier(arg):
    syslog.syslog(syslog.LOG_INFO, "auth_down_notifier %s" % arg)
    pass

