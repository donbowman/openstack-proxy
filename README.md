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


