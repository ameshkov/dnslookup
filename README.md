[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/dnslookup)](https://goreportcard.com/report/ameshkov/dnslookup)
[![Latest release](https://img.shields.io/github/release/ameshkov/dnslookup/all.svg)](https://github.com/ameshkov/dnslookup/releases)
[![Snap Store](https://snapcraft.io/dnslookup/badge.svg)](https://snapcraft.io/dnslookup)

# dnslookup

Simple command line utility to make DNS lookups. Supports all known DNS
protocols: plain DNS, DoH, DoT, DoQ, DNSCrypt.

### How to install

* Using homebrew:
    ```
    brew install ameshkov/tap/dnslookup
    ```
* From source:
    ```
    go install github.com/ameshkov/dnslookup@latest
    ```
* You can get a binary from
  the [releases page](https://github.com/ameshkov/dnslookup/releases).
* You can install it from the [Snap Store](https://snapcraft.io/dnslookup)

### Examples:

Plain DNS:

```shell
dnslookup example.org 94.140.14.14
```

DNS-over-TLS:

```shell
dnslookup example.org tls://dns.adguard.com
```

DNS-over-TLS with IP:

```shell
dnslookup example.org tls://dns.adguard.com 94.140.14.14
```

DNS-over-HTTPS with HTTP/2:

```shell
dnslookup example.org https://dns.adguard.com/dns-query
```

DNS-over-HTTPS with HTTP/3 support (the version is chosen automatically):

```shell
HTTP3=1 dnslookup example.org https://dns.google/dns-query
```

DNS-over-HTTPS forcing HTTP/3 only:

```shell
dnslookup example.org h3://dns.google/dns-query
```

DNS-over-HTTPS with IP:

```shell
dnslookup example.org https://dns.adguard.com/dns-query 94.140.14.14
```

DNSCrypt (stamp):

```shell
dnslookup example.org sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
```

DNSCrypt (parameters):

```shell
dnslookup example.org 176.103.130.130:5443 2.dnscrypt.default.ns1.adguard.com D12B:47F2:52DC:F2C2:BBF8:9910:86EA:F79C:E449:5D8B:16C8:A0C4:322E:52CA:3F39:0873
```

DNS-over-QUIC:

```shell
dnslookup example.org quic://dns.adguard.com
```

Machine-readable format:

```shell
JSON=1 dnslookup example.org 94.140.14.14
```

Disable certificates verification:

```shell
VERIFY=0 dnslookup example.org tls://127.0.0.1
```

Specify the type of resource record (default A):

```shell
RRTYPE=AAAA dnslookup example.org tls://127.0.0.1
RRTYPE=HTTPS dnslookup example.org tls://127.0.0.1
```

Specify the class of query (default IN):

```shell
CLASS=CH dnslookup example.org tls://127.0.0.1
```

Set DNSSEC DO bit in the request's OPT record:

```shell
DNSSEC=1 dnslookup example.org tls://8.8.8.8
```

Specify EDNS subnet:

```shell
SUBNET=1.2.3.4/24 dnslookup example.org tls://8.8.8.8
```

Add EDNS0 Padding:

```shell
PAD=1 dnslookup example.org tls://127.0.0.1
```

Specify EDNS option with code point `code` and optionally payload of `value` as
a hexadecimal string: `EDNSOPT=code:value`. Example (equivalent of dnsmasq's
`--add-cpe-id=12345678`):

```shell
EDNSOPT=65074:3132333435363738 RRTYPE=TXT dnslookup o-o.myaddr.l.google.com tls://8.8.8.8
```

Combine multiple options:
```shell
RRTYPE=TXT SUBNET=1.1.1.1/24 PAD=1 dnslookup o-o.myaddr.l.google.com tls://8.8.8.8
```

Verbose-level logging:

```shell
VERBOSE=1 dnslookup example.org tls://dns.adguard.com
```
