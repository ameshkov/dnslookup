# dnslookup

Simple command line utility to make DNS lookups to the specified server.

### Examples:

Plain DNS:
```
./dnslookup example.org 176.103.130.130
```

DNS-over-TLS:
```
./dnslookup example.org tls://dns.adguard.com
```

DNS-over-HTTPS:
```
./dnslookup example.org https://dns.adguard.com/dns-query
```

DNSCrypt (stamp):
```
./dnslookup example.org sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```

DNSCrypt (parameters):
```
./dnslookup example.org 176.103.130.130:5443 2.dnscrypt.default.ns1.adguard.com D12B:47F2:52DC:F2C2:BBF8:9910:86EA:F79C:E449:5D8B:16C8:A0C4:322E:52CA:3F39:0873
```