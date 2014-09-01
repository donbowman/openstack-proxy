sstp-proxy -- proxy incoming SSTP (Microsoft VPN) to an appropriate
instance of a virtual machine under OpenStack.

This allows you to run an OpenStack cloud w/o public IP, and
still VPN into your instances. I use it to VPn to a specific Heat
stack.

The user must connect as /tenant/user/instance.

E.g. if we instantiated the below Heat template as 'x', this might be x-vpn.

The SSTP proxy will then connect there.

The user will specific a user name of cloud@vpn (and password cloud).
You will now be bridged to that VM.

As a fallback, any other SSL coming in that is not SSTP (or not of the
format /tenant/user/instance) will be routed to localhost:443

The invocation requires supplying the certificate/private key for SSL,
and a keystone user/password who has privilege to run 'nova list'
on all tenants. Note that there will not be an error thrown for
a non-readable private key file until the first connection... These
are normally in /etc/ssl/private, and not readable except by root.

    optional arguments:
      -h, --help                 show this help message and exit
      -port PORT                 Port #
      -cert CERT                 Cert
      -key KEY                   Key
      -admin-user ADMIN_USER     Keystone admin user
      -admin-pass ADMIN_PASS     Keystone admin password
      -keystone-url KEYSTONE_URL Keystone url

As a pre-req, you neet python-prctl installed.

I use this with a VPN installed on Ubuntu 14.04 (softether), using
the following Heat Template subset. Login as cloud@VPN (password cloud).

So the full url would now be: https://proxy:port/tenant/user/host
and the SSTP vpn would pass through.

    vpn:
      type: OS::Nova::Server
      properties:
        name: { str_replace: { params: { $stack_name: { get_param: 'OS::stack_name' } }, template: '$stack_name-vpn' } }
        key_name: { get_resource: key }
        image: "trusty"
        flavor: "m1.tiny"
        config_drive: "true"
        networks:
          - network: { get_resource: ctrl_net }
          - network: { get_resource: data_sub_net1 }
        user_data_format: RAW
        user_data: |
          #!/bin/bash
          iptables -F
          sed -i -e '/eth1/d' /etc/network/interfaces
          cat <<EOF >>/etc/network/interfaces
          auto eth1
          iface eth1 inet manual
            up ip link set eth1 up promisc on
            down ip link set eth1 down promisc off
          EOF
          ifup eth1

          cd /var/lib/softether
          stop softether
          rm -f vpn_server_config
          start softether
          cat <<EOF1 > vpn.cmd
          HubCreate vpn /PASSWORD:""
          hub vpn
          SecureNatDisable
          ServerCertRegenerate vk
          SstpEnable yes
          BridgeCreate vpn /DEVICE:eth1 /TAP:no
          UserCreate cloud /GROUP:none /REALNAME:none /NOTE:none
          UserPasswordSet cloud /PASSWORD:cloud
          EOF1
          vpncmd localhost /server /IN:vpn.cmd

