[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/dnslookup)](https://goreportcard.com/report/ameshkov/dnslookup)
[![Latest release](https://img.shields.io/github/release/ameshkov/dnslookup/all.svg)](https://github.com/ameshkov/dnslookup/releases)
[![Snap Store](https://snapcraft.io/dnslookup/badge.svg)](https://snapcraft.io/dnslookup)

# dnslookup

Simple command line utility to make DNS lookups. Supports all known DNS
protocols: plain DNS, plain DNS-over-TCP, DoH, DoT, DoQ, DNSCrypt.

## How to install

* Using homebrew:

    ```sh
    brew install ameshkov/tap/dnslookup
    ```

* From source:

    ```sh
    go install github.com/ameshkov/dnslookup@latest
    ```

* You can get a binary from
  the [releases page](https://github.com/ameshkov/dnslookup/releases).
* You can install it from the [Snap Store](https://snapcraft.io/dnslookup)

## Options

Every option can be passed either as a command-line flag or as an environment
variable.  Command-line flags take precedence over environment variables, and
can be placed before, after, or between the positional arguments.

| Flag | Environment variable | Description |
|------|----------------------|-------------|
| `--rrtype <type>` | `RRTYPE` | Type of resource record to query, default `A` |
| `--class <class>` | `CLASS` | Class of the query, default `IN` |
| `--subnet <subnet>` | `SUBNET` | EDNS Client Subnet, e.g. `1.2.3.4/24` |
| `--ednsopt <code[:value]>` | `EDNSOPT` | EDNS option with code point `code` and optionally payload `value` as a hexadecimal string |
| `--dnssec` | `DNSSEC=1` | Set the DNSSEC DO bit in the request's OPT record |
| `--pad` | `PAD=1` | Add EDNS0 Padding |
| `--timeout <seconds>` | `TIMEOUT` | Query timeout in seconds, default 10 |
| `--json` | `JSON=1` | Machine-readable JSON output |
| `--verify=<bool>` | `VERIFY` | Verify the TLS certificate, default true; `--verify=false` disables it (same as `VERIFY=0`) |
| `--http3` | `HTTP3=1` | Enable HTTP/3 support for DoH |
| `--verbose` | `VERBOSE=1` | Verbose logging |
| `-v`, `--version` | | Print the version and exit |
| `-h`, `--help` | | Print usage and exit |

Examples:

```shell
# Same as RRTYPE=AAAA dnslookup example.org tls://dns.adguard-dns.com
dnslookup example.org tls://dns.adguard-dns.com --rrtype AAAA

dnslookup example.org tls://dns.adguard-dns.com --rrtype HTTPS --dnssec

dnslookup o-o.myaddr.l.google.com tls://8.8.8.8 --rrtype TXT --subnet 1.1.1.1/24 --pad

dnslookup example.org tls://127.0.0.1 --verify=false

# The flag wins, so this queries AAAA:
RRTYPE=A dnslookup example.org 94.140.14.14 --rrtype AAAA
```

## Examples

Plain DNS, use default system resolver:

```shell
dnslookup example.org
```

Plain DNS:

```shell
dnslookup example.org 94.140.14.14
```

Plain DNS-over-TCP:

```shell
dnslookup example.org tcp://94.140.14.14
```

DNS-over-TLS:

```shell
dnslookup example.org tls://dns.adguard-dns.com
```

DNS-over-TLS with IP:

```shell
dnslookup example.org tls://dns.adguard-dns.com 94.140.14.14
```

DNS-over-HTTPS with HTTP/2:

```shell
dnslookup example.org https://dns.adguard-dns.com/dns-query
```

DNS-over-HTTPS with HTTP/3 support (the version is chosen automatically):

```shell
HTTP3=1 dnslookup example.org https://dns.google/dns-query
```

DNS-over-HTTPS forcing HTTP/3 only:

```shell
# Google DNS
dnslookup example.org h3://dns.google/dns-query
```

DNS-over-HTTPS with IP:

```shell
dnslookup example.org https://dns.adguard-dns.com/dns-query 94.140.14.14
```

DNS-over-HTTPS with basic auth (supported
by [AdGuard DNS](https://adguard-dns.io/)):

```shell
dnslookup example.org https://username:password@d.adguard-dns.com/dns-query
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
# AdGuard DNS
dnslookup example.org quic://dns.adguard-dns.com

# Quad9
dnslookup example.org quic://9.9.9.9
```

Sending a PTR query for an IPv4 address (IP address is recognized automatically
when RRTYPE is not specified):

```shell
dnslookup 8.8.8.8
```

Sending a PTR query for an IPv6 address (IP address is recognized automatically
when RRTYPE is not specified):

```shell
dnslookup 2606:4700:4700::1111
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
VERBOSE=1 dnslookup example.org tls://dns.adguard-dns.com
```
