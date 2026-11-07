// Package main is the command-line tool that does DNS lookups using
// dnsproxy/upstream.  See README.md for more information.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil/sysresolv"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

type jsonMsg struct {
	dns.Msg
	Elapsed time.Duration `json:"elapsed"`
}

// VersionString -- see the makefile
var VersionString = "master"

func main() {
	// parse env variables
	machineReadable := os.Getenv("JSON") == "1"
	insecureSkipVerify := os.Getenv("VERIFY") == "0"
	http3Enabled := os.Getenv("HTTP3") == "1"
	verbose := os.Getenv("VERBOSE") == "1"
	padding := os.Getenv("PAD") == "1"
	do := os.Getenv("DNSSEC") == "1"
	subnetOpt := getSubnet()
	ednsOpt := getEDNSOpt()

	if verbose {
		log.SetLevel(log.DEBUG)
	}

	printVersion(machineReadable)
	checkArgs(insecureSkipVerify)

	question := getQuestion()

	opts := &upstream.Options{
		Timeout:            time.Duration(getTimeout()) * time.Second,
		InsecureSkipVerify: insecureSkipVerify,
		HTTPVersions:       getHTTPVersions(http3Enabled),
	}

	applyBootstrap(opts)

	server := setupDNSCrypt(getServer())

	u, err := upstream.AddressToUpstream(server, opts)
	if err != nil {
		log.Fatalf("Cannot create an upstream: %s", err)
	}

	req, err := buildRequest(question, requestOptions{
		DNSSEC:  do,
		Subnet:  subnetOpt,
		EDNSOpt: ednsOpt,
		Padding: padding,
	})
	if err != nil {
		log.Fatalf("Cannot build the DNS request: %s", err)
	}

	startTime := time.Now()
	reply, err := u.Exchange(req)
	if err != nil {
		log.Fatalf("Cannot make the DNS request: %s", err)
	}

	printReply(machineReadable, server, startTime, reply)
}

func printVersion(machineReadable bool) {
	if machineReadable {
		return
	}

	_, _ = fmt.Printf("dnslookup %s\n", VersionString)

	if len(os.Args) == 2 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		os.Exit(0)
	}
}

func checkArgs(insecureSkipVerify bool) {
	if insecureSkipVerify {
		_, _ = fmt.Println("TLS verification has been disabled")
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		usage()
		os.Exit(0)
	}

	if len(os.Args) < 2 || len(os.Args) > 5 {
		log.Printf("Wrong number of arguments")
		usage()

		os.Exit(1)
	}
}

func getTimeout() (timeout int) {
	timeout = 10

	timeoutStr := os.Getenv("TIMEOUT")
	if timeoutStr == "" {
		return timeout
	}

	i, err := strconv.Atoi(timeoutStr)
	if err != nil {
		log.Printf("Wrong timeout value: %s", timeoutStr)
		usage()

		os.Exit(1)
	}

	return i
}

func getServer() (server string) {
	if len(os.Args) > 2 {
		return os.Args[2]
	}

	sysr, err := sysresolv.NewSystemResolvers(nil, 53)
	if err != nil {
		log.Printf("Cannot get system resolvers: %v", err)
		os.Exit(1)
	}

	return sysr.Addrs()[0].String()
}

func getHTTPVersions(http3Enabled bool) (httpVersions []upstream.HTTPVersion) {
	if http3Enabled {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	return httpVersions
}

func applyBootstrap(opts *upstream.Options) {
	if len(os.Args) != 4 {
		return
	}

	ip := net.ParseIP(os.Args[3])
	if ip == nil {
		log.Fatalf("invalid IP specified: %s", os.Args[3])
	}

	opts.Bootstrap = &singleIPResolver{ip: ip}
}

func setupDNSCrypt(server string) (stamped string) {
	if len(os.Args) != 5 {
		return server
	}

	// DNSCrypt parameters
	providerName := os.Args[3]
	serverPkStr := os.Args[4]

	serverPk, err := hex.DecodeString(strings.ReplaceAll(serverPkStr, ":", ""))
	if err != nil {
		log.Fatalf("Invalid server PK %s: %s", serverPkStr, err)
	}

	var stamp dnsstamps.ServerStamp
	stamp.Proto = dnsstamps.StampProtoTypeDNSCrypt
	stamp.ServerAddrStr = server
	stamp.ProviderName = providerName
	stamp.ServerPk = serverPk

	return stamp.String()
}

func printReply(machineReadable bool, server string, startTime time.Time, reply *dns.Msg) {
	if !machineReadable {
		_, _ = fmt.Printf("Server: %s\n\n", server)
		_, _ = fmt.Printf("dnslookup result (elapsed %v):\n", time.Since(startTime))
		_, _ = fmt.Println(reply.String())

		return
	}

	// Prevent JSON parsing from skewing results
	endTime := time.Now()

	var JSONreply jsonMsg
	JSONreply.Msg = *reply
	JSONreply.Elapsed = endTime.Sub(startTime)

	b, err := json.MarshalIndent(JSONreply, "", "  ")
	if err != nil {
		log.Fatalf("Cannot marshal json: %s", err)
	}

	_, _ = fmt.Println(string(b))
}

func getEDNSOpt() (option *dns.EDNS0_LOCAL) {
	ednsOpt := os.Getenv("EDNSOPT")
	if ednsOpt == "" {
		return nil
	}

	option, err := parseEDNSOpt(ednsOpt)
	if err != nil {
		log.Printf("invalid EDNSOPT %s: %v", ednsOpt, err)
		usage()

		os.Exit(1)
	}

	return option
}

// getQuestion returns a DNS question for the query.
func getQuestion() (q dns.Question) {
	domain := os.Args[1]
	rrType := getRRType()
	qClass := getClass()

	// If the user tries to query an IP address and does not specify any
	// query type, convert to PTR automatically.
	ip := net.ParseIP(domain)
	if os.Getenv("RRTYPE") == "" && ip != nil {
		domain = ipToPtr(ip)
		rrType = dns.TypePTR
	}

	q.Name = dns.Fqdn(domain)
	q.Qtype = rrType
	q.Qclass = qClass

	return q
}

func ipToPtr(ip net.IP) (ptr string) {
	if ip.To4() != nil {
		return ip4ToPtr(ip)
	}

	return ip6ToPtr(ip)
}

func ip4ToPtr(ip net.IP) (ptr string) {
	parts := strings.Split(ip.String(), ".")
	for i := range parts {
		ptr = parts[i] + "." + ptr
	}
	ptr = ptr + "in-addr.arpa."

	return
}

func ip6ToPtr(ip net.IP) (ptr string) {
	addr, _ := netip.ParseAddr(ip.String())
	str := addr.StringExpanded()

	// Remove colons and reverse the order of characters.
	str = strings.ReplaceAll(str, ":", "")
	reversed := ""
	for i := len(str) - 1; i >= 0; i-- {
		reversed += string(str[i])
		if i != 0 {
			reversed += "."
		}
	}

	ptr = reversed + ".ip6.arpa."

	return ptr
}

func getSubnet() (option *dns.EDNS0_SUBNET) {
	subnetStr := os.Getenv("SUBNET")
	if subnetStr == "" {
		return nil
	}

	option, err := parseSubnet(subnetStr)
	if err != nil {
		log.Printf("invalid SUBNET %s: %v", subnetStr, err)
		usage()

		os.Exit(1)
	}

	return option
}

func getClass() (class uint16) {
	classStr := os.Getenv("CLASS")
	var ok bool
	class, ok = dns.StringToClass[classStr]
	if !ok {
		if classStr != "" {
			log.Printf("Invalid CLASS: %q", classStr)
			usage()

			os.Exit(1)
		}

		class = dns.ClassINET
	}
	return class
}

func getRRType() (rrType uint16) {
	rrTypeStr := os.Getenv("RRTYPE")
	var ok bool
	rrType, ok = dns.StringToType[rrTypeStr]
	if !ok {
		if rrTypeStr != "" {
			log.Printf("Invalid RRTYPE: %q", rrTypeStr)
			usage()

			os.Exit(1)
		}

		rrType = dns.TypeA
	}
	return rrType
}

func usage() {
	_, _ = fmt.Println("Usage: dnslookup <domain> <server> [<providerName> <serverPk>]")
	_, _ = fmt.Println("<domain>: mandatory, domain name to lookup")
	_, _ = fmt.Println("<server>: mandatory, server address. Supported: plain, tcp:// (TCP), tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ)")
	_, _ = fmt.Println("<providerName>: optional, DNSCrypt provider name")
	_, _ = fmt.Println("<serverPk>: optional, DNSCrypt server public key")
}

// singleIPResolver represents a resolver that resolves a single IP address.
// This type implements the upstream.Resolver interface.
type singleIPResolver struct {
	ip net.IP
}

// type check
var _ upstream.Resolver = (*singleIPResolver)(nil)

// LookupNetIP implements the upstream.Resolver interface for *singleIPResolver.
func (s *singleIPResolver) LookupNetIP(_ context.Context, _ string, _ string) (addrs []netip.Addr, err error) {
	ip, ok := netip.AddrFromSlice(s.ip)

	if !ok {
		return nil, fmt.Errorf("invalid IP: %s", s.ip)
	}

	return []netip.Addr{ip}, nil
}
