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

DNSCrypt:
```
./dnslookup example.org sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```