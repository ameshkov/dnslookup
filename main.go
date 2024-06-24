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

// nolint: gocyclo
func main() {
	// parse env variables
	machineReadable := os.Getenv("JSON") == "1"
	insecureSkipVerify := os.Getenv("VERIFY") == "0"
	timeoutStr := os.Getenv("TIMEOUT")
	http3Enabled := os.Getenv("HTTP3") == "1"
	verbose := os.Getenv("VERBOSE") == "1"
	padding := os.Getenv("PAD") == "1"
	do := os.Getenv("DNSSEC") == "1"
	subnetOpt := getSubnet()
	ednsOpt := getEDNSOpt()

	if verbose {
		log.SetLevel(log.DEBUG)
	}

	timeout := 10

	if !machineReadable {
		_, _ = os.Stdout.WriteString(fmt.Sprintf("dnslookup %s\n", VersionString))

		if len(os.Args) == 2 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
			os.Exit(0)
		}
	}

	if insecureSkipVerify {
		_, _ = os.Stdout.WriteString("TLS verification has been disabled\n")
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

	question := getQuestion()

	if timeoutStr != "" {
		i, err := strconv.Atoi(timeoutStr)
		if err != nil {
			log.Printf("Wrong timeout value: %s", timeoutStr)
			usage()
			os.Exit(1)
		}

		timeout = i
	}

	var server string
	if len(os.Args) > 2 {
		server = os.Args[2]
	} else {
		sysr, err := sysresolv.NewSystemResolvers(nil, 53)
		if err != nil {
			log.Printf("Cannot get system resolvers: %v", err)
			os.Exit(1)
		}

		server = sysr.Addrs()[0].String()
	}

	var httpVersions []upstream.HTTPVersion
	if http3Enabled {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	opts := &upstream.Options{
		Timeout:            time.Duration(timeout) * time.Second,
		InsecureSkipVerify: insecureSkipVerify,
		HTTPVersions:       httpVersions,
	}

	if len(os.Args) == 4 {
		ip := net.ParseIP(os.Args[3])
		if ip == nil {
			log.Fatalf("invalid IP specified: %s", os.Args[3])
		}

		opts.Bootstrap = &singleIPResolver{ip: ip}
	}

	if len(os.Args) == 5 {
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
		server = stamp.String()
	}

	u, err := upstream.AddressToUpstream(server, opts)
	if err != nil {
		log.Fatalf("Cannot create an upstream: %s", err)
	}

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{question}

	opt := getOrCreateOpt(req, do)

	if subnetOpt != nil {
		opt.Option = append(opt.Option, subnetOpt)
	}

	if ednsOpt != nil {
		opt.Option = append(opt.Option, ednsOpt)
	}

	if padding {
		opt.Option = append(opt.Option, newEDNS0Padding(req))
	}

	startTime := time.Now()
	reply, err := u.Exchange(req)
	if err != nil {
		log.Fatalf("Cannot make the DNS request: %s", err)
	}

	if !machineReadable {
		msg := fmt.Sprintf("dnslookup result (elapsed %v):\n", time.Now().Sub(startTime))
		_, _ = os.Stdout.WriteString(fmt.Sprintf("Server: %s\n\n", server))
		_, _ = os.Stdout.WriteString(msg)
		_, _ = os.Stdout.WriteString(reply.String() + "\n")
	} else {
		// Prevent JSON parsing from skewing results
		endTime := time.Now()

		var JSONreply jsonMsg
		JSONreply.Msg = *reply
		JSONreply.Elapsed = endTime.Sub(startTime)

		var b []byte
		b, err = json.MarshalIndent(JSONreply, "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		_, _ = os.Stdout.WriteString(string(b) + "\n")
	}
}

func getOrCreateOpt(req *dns.Msg, do bool) (opt *dns.OPT) {
	opt = req.IsEdns0()
	if opt == nil {
		req.SetEdns0(udpBufferSize, do)
		opt = req.IsEdns0()
	}

	return opt
}

func getEDNSOpt() (option *dns.EDNS0_LOCAL) {
	ednsOpt := os.Getenv("EDNSOPT")
	if ednsOpt == "" {
		return nil
	}

	parts := strings.Split(ednsOpt, ":")
	code, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Printf("invalid EDNSOPT %s: %v", ednsOpt, err)
		usage()

		os.Exit(1)
	}

	var value []byte
	if len(parts) > 1 {
		value, err = hex.DecodeString(parts[1])
		if err != nil {
			log.Printf("invalid EDNSOPT %s: %v", ednsOpt, err)
			usage()

			os.Exit(1)
		}
	}

	return &dns.EDNS0_LOCAL{
		Code: uint16(code),
		Data: value,
	}
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

	_, ipNet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		log.Printf("invalid SUBNET %s: %v", subnetStr, err)
		usage()

		os.Exit(1)
	}

	ones, _ := ipNet.Mask.Size()

	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ipNet.IP,
	}
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
	_, _ = os.Stdout.WriteString("Usage: dnslookup <domain> <server> [<providerName> <serverPk>]\n")
	_, _ = os.Stdout.WriteString("<domain>: mandatory, domain name to lookup\n")
	_, _ = os.Stdout.WriteString("<server>: mandatory, server address. Supported: plain, tcp:// (TCP), tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ)\n")
	_, _ = os.Stdout.WriteString("<providerName>: optional, DNSCrypt provider name\n")
	_, _ = os.Stdout.WriteString("<serverPk>: optional, DNSCrypt server public key\n")
}

// requestPaddingBlockSize is used to pad responses over DoT and DoH according
// to RFC 8467.
const requestPaddingBlockSize = 128
const udpBufferSize = dns.DefaultMsgSize

// newEDNS0Padding constructs a new OPT RR EDNS0 Padding for the extra section.
func newEDNS0Padding(req *dns.Msg) (option *dns.EDNS0_PADDING) {
	msgLen := req.Len()
	padLen := requestPaddingBlockSize - msgLen%requestPaddingBlockSize

	// Truncate padding to fit in UDP buffer.
	if msgLen+padLen > udpBufferSize {
		padLen = udpBufferSize - msgLen
		if padLen < 0 {
			padLen = 0
		}
	}

	return &dns.EDNS0_PADDING{Padding: make([]byte, padLen)}
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
