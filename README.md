sstp-proxy -- proxy incoming SSTP (Microsoft VPN) to an appropriate
instance of a virtual machine.

The user must connect as /user/project[/instance]. If instance
is specified, we'll find a machine called instance-vpn. If instance
is not specified we'll take the first -vpn name we find.

The SSTP proxy will then connect there.

The user will specific a user name of cloud@vpn (and password cloud).
You will now be bridged to that VM.

As a fallback, any other SSL coming in that is not SSTP (or not of the
format /user/project[/instance]) will be routed to localhost:443

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

As a pre-req, you neet python-prctl installed
