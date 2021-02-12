[![Build Status](https://travis-ci.com/ameshkov/dnslookup.svg?branch=master)](https://travis-ci.com/ameshkov/dnslookup)
[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/dnslookup)](https://goreportcard.com/report/ameshkov/dnslookup)
[![Latest release](https://img.shields.io/github/release/ameshkov/dnslookup/all.svg)](https://github.com/ameshkov/dnslookup/releases)
[![Snap Store](https://snapcraft.io/dnslookup/badge.svg)](https://snapcraft.io/dnslookup)

# dnslookup

Simple command line utility to make DNS lookups. Supports all known DNS protocols: plain DNS, DoH, DoT, DoQ, DNSCrypt.

### How to install

* Using homebrew:
    ```
    brew install ameshkov/tap/dnslookup
    ```
* From source:
    ```
    go get github.com/ameshkov/dnslookup
    ```
* You can get a binary from the [releases page](https://github.com/ameshkov/dnslookup/releases).
* You can install it from the [Snap Store](https://snapcraft.io/dnslookup)

### Examples:

Plain DNS:
```
./dnslookup example.org 94.140.14.14
```

DNS-over-TLS:
```
./dnslookup example.org tls://dns.adguard.com
```

DNS-over-TLS with IP:
```
./dnslookup example.org tls://dns.adguard.com 94.140.14.14
```

DNS-over-HTTPS:
```
./dnslookup example.org https://dns.adguard.com/dns-query
```

DNS-over-HTTPS with IP:
```
./dnslookup example.org https://dns.adguard.com/dns-query 94.140.14.14
```

DNSCrypt (stamp):
```
./dnslookup example.org sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```

DNSCrypt (parameters):
```
./dnslookup example.org 176.103.130.130:5443 2.dnscrypt.default.ns1.adguard.com D12B:47F2:52DC:F2C2:BBF8:9910:86EA:F79C:E449:5D8B:16C8:A0C4:322E:52CA:3F39:0873
```

DNS-over-QUIC (experimental, uses port 784):
```
./dnslookup example.org quic://dns.adguard.com
```

Machine-readable format:
```
JSON=1 ./dnslookup example.org 94.140.14.14
```

Disable certificates verification:
```
VERIFY=0 ./dnslookup example.org tls://127.0.0.1
```

Specify the type of resource record (default A):
```
RRTYPE=AAAA ./dnslookup example.org tls://127.0.0.1
RRTYPE=HTTPS ./dnslookup example.org tls://127.0.0.1
```
