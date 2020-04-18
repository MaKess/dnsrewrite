"dnsrewrite" is a small python tool to rewrite DNS-suffixes on-the-fly.
the goal is to be able to resolve host names in a home network where the default DHCP server distributes names under fixed
domain that cannot be changed. (e.g. mypc.fritz.box)

```
dnsrewrite --forward-host 192.168.178.1 --listen-port 5300 --listen-host 192.168.23.3 --replace-suffix home.example.net:fritz.box
```

this will launch `dnsrewrite` as a local DNS server.
now instead of querying the DNS server that comes with the DHCP server:
```
dig mypc.fritz.box @192.168.178.1
```
we can look up the host under a "real" domain
```
dig -p 5300 mypc.home.example.net @192.168.23.3
```

how to deploy:
* copy "dnsrewrite.py" to "/usr/local/bin/dnsrewrite"

how to enable:
* copy "dnsrewrite.service" file to "/etc/systemd/system/" (the location for user-provided unit files)
* systemctl enable dnsrewrite
* systemctl start dnsrewrite
