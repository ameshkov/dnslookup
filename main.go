// Package main is the command-line tool that does DNS lookups using
// dnsproxy/upstream.  See README.md for more information.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
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

// defaultTimeout is the default query timeout in seconds.
const defaultTimeout = 10

// cliFlags holds the command-line flags.  Every flag has a matching
// environment variable which is used when the flag is not set; see usage.
type cliFlags struct {
	json    *bool
	verify  *bool
	timeout *int
	http3   *bool
	verbose *bool
	pad     *bool
	dnssec  *bool
	rrtype  *string
	class   *string
	subnet  *string
	ednsopt *string
	version *bool
	help    *bool
}

// newFlagSet creates a flag set with all supported command-line flags.
func newFlagSet() (fs *flag.FlagSet, f *cliFlags) {
	fs = flag.NewFlagSet("dnslookup", flag.ContinueOnError)
	fs.Usage = usage

	f = &cliFlags{}
	f.json = fs.Bool("json", false, "print the result in machine-readable JSON format (env: JSON)")
	f.verify = fs.Bool("verify", true, "verify the TLS certificate, use --verify=false to disable (env: VERIFY)")
	f.timeout = fs.Int("timeout", defaultTimeout, "query timeout in seconds (env: TIMEOUT)")
	f.http3 = fs.Bool("http3", false, "enable HTTP/3 support for DNS-over-HTTPS (env: HTTP3)")
	f.verbose = fs.Bool("verbose", false, "verbose logging (env: VERBOSE)")
	f.pad = fs.Bool("pad", false, "add EDNS0 Padding to the request (env: PAD)")
	f.dnssec = fs.Bool("dnssec", false, "set the DNSSEC DO bit in the request (env: DNSSEC)")
	f.rrtype = fs.String("rrtype", "", "resource record type to query, e.g. A, AAAA, HTTPS (env: RRTYPE)")
	f.class = fs.String("class", "", "query class, e.g. IN, CH (env: CLASS)")
	f.subnet = fs.String("subnet", "", "EDNS Client Subnet in CIDR notation, e.g. 1.2.3.4/24 (env: SUBNET)")
	f.ednsopt = fs.String("ednsopt", "", "EDNS option as code[:value], e.g. 65074:3132333435363738 (env: EDNSOPT)")
	f.version = fs.Bool("version", false, "print the version and exit")
	f.help = fs.Bool("help", false, "print this help and exit")
	fs.BoolVar(f.version, "v", false, "print the version and exit")
	fs.BoolVar(f.help, "h", false, "print this help and exit")

	return fs, f
}

// parseArgs parses the command-line arguments.  Unlike the standard flag
// parsing, flags may be given before, after, or between the positional
// arguments.
func parseArgs(fs *flag.FlagSet, args []string) (positional []string, err error) {
	for len(args) > 0 {
		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}

		if err = fs.Parse(args); err != nil {
			return nil, err
		}

		args = fs.Args()
		if len(args) > 0 {
			positional = append(positional, args[0])
			args = args[1:]
		}
	}

	return positional, nil
}

// nolint: gocyclo
func main() {
	fs, flags := newFlagSet()

	args, err := parseArgs(fs, os.Args[1:])
	if err != nil {
		// The error message and the usage have been printed by the flag
		// set.

		os.Exit(1)
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Environment variables provide the defaults; command-line flags take
	// precedence over them.
	machineReadable := os.Getenv("JSON") == "1"
	insecureSkipVerify := os.Getenv("VERIFY") == "0"
	http3Enabled := os.Getenv("HTTP3") == "1"
	verbose := os.Getenv("VERBOSE") == "1"
	padding := os.Getenv("PAD") == "1"
	do := os.Getenv("DNSSEC") == "1"
	rrTypeStr := os.Getenv("RRTYPE")
	classStr := os.Getenv("CLASS")
	subnetStr := os.Getenv("SUBNET")
	ednsOptStr := os.Getenv("EDNSOPT")

	timeout := defaultTimeout
	if !set["timeout"] {
		if envTimeout := os.Getenv("TIMEOUT"); envTimeout != "" {
			i, err := strconv.Atoi(envTimeout)
			if err != nil {
				log.Printf("Wrong timeout value: %s", envTimeout)
				usage()
				os.Exit(1)
			}

			timeout = i
		}
	} else {
		timeout = *flags.timeout
	}

	if set["json"] {
		machineReadable = *flags.json
	}

	if set["verify"] {
		insecureSkipVerify = !*flags.verify
	}

	if set["http3"] {
		http3Enabled = *flags.http3
	}

	if set["verbose"] {
		verbose = *flags.verbose
	}

	if set["pad"] {
		padding = *flags.pad
	}

	if set["dnssec"] {
		do = *flags.dnssec
	}

	if set["rrtype"] {
		rrTypeStr = *flags.rrtype
	}

	if set["class"] {
		classStr = *flags.class
	}

	if set["subnet"] {
		subnetStr = *flags.subnet
	}

	if set["ednsopt"] {
		ednsOptStr = *flags.ednsopt
	}

	subnetOpt := getSubnet(subnetStr)
	ednsOpt := getEDNSOpt(ednsOptStr)

	if verbose {
		log.SetLevel(log.DEBUG)
	}

	if !machineReadable {
		_, _ = fmt.Printf("dnslookup %s\n", VersionString)
	}

	if *flags.version {
		os.Exit(0)
	}

	if insecureSkipVerify {
		_, _ = fmt.Println("TLS verification has been disabled")
	}

	if *flags.help {
		usage()
		os.Exit(0)
	}

	if len(args) < 1 || len(args) > 4 {
		log.Printf("Wrong number of arguments")
		usage()
		os.Exit(1)
	}

	question := getQuestion(args[0], rrTypeStr, classStr)

	var server string
	if len(args) > 1 {
		server = args[1]
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

	if len(args) == 3 {
		ip := net.ParseIP(args[2])
		if ip == nil {
			log.Fatalf("invalid IP specified: %s", args[2])
		}

		opts.Bootstrap = &singleIPResolver{ip: ip}
	}

	if len(args) == 4 {
		// DNSCrypt parameters
		providerName := args[2]
		serverPkStr := args[3]

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

	// An OPT record is required to signal the DNSSEC DO bit, so create it
	// even when there are no other EDNS0 options.
	if do {
		getOrCreateOpt(req, do)
	}

	if subnetOpt != nil {
		opt := getOrCreateOpt(req, do)
		opt.Option = append(opt.Option, subnetOpt)
	}

	if ednsOpt != nil {
		opt := getOrCreateOpt(req, do)
		opt.Option = append(opt.Option, ednsOpt)
	}

	if padding {
		opt := getOrCreateOpt(req, do)
		opt.Option = append(opt.Option, newEDNS0Padding(req))
	}

	startTime := time.Now()
	reply, err := u.Exchange(req)
	if err != nil {
		log.Fatalf("Cannot make the DNS request: %s", err)
	}

	if !machineReadable {
		_, _ = fmt.Printf("Server: %s\n\n", server)
		_, _ = fmt.Printf("dnslookup result (elapsed %v):\n", time.Since(startTime))
		_, _ = fmt.Println(reply.String())
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

		_, _ = fmt.Println(string(b))
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

func getEDNSOpt(ednsOpt string) (option *dns.EDNS0_LOCAL) {
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
		// #nosec G115 -- Assume user provided code fit in uint16.
		Code: uint16(code),
		Data: value,
	}
}

// getQuestion returns a DNS question for the query.
func getQuestion(domain, rrTypeStr, classStr string) (q dns.Question) {
	rrType := getRRType(rrTypeStr)
	qClass := getClass(classStr)

	// If the user tries to query an IP address and does not specify any
	// query type, convert to PTR automatically.
	if ip := net.ParseIP(domain); ip != nil && rrTypeStr == "" {
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

func getSubnet(subnetStr string) (option *dns.EDNS0_SUBNET) {
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
		Code:   dns.EDNS0SUBNET,
		Family: 1,
		// #nosec G115 -- Assume that ones always fit in uint8.
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ipNet.IP,
	}
}

func getClass(classStr string) (class uint16) {
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

func getRRType(rrTypeStr string) (rrType uint16) {
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
	_, _ = fmt.Println("Usage: dnslookup [<options>] <domain> [<server> [<providerName> <serverPk>]]")
	_, _ = fmt.Println("<domain>: mandatory, domain name to lookup")
	_, _ = fmt.Println("<server>: optional, server address. Supported: plain, tcp:// (TCP), tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ)")
	_, _ = fmt.Println("<providerName>: optional, DNSCrypt provider name")
	_, _ = fmt.Println("<serverPk>: optional, DNSCrypt server public key")
	_, _ = fmt.Println("Options (flags override the corresponding environment variables):")
	_, _ = fmt.Printf("  %-24s %s\n", "--rrtype <type>", "resource record type to query (env RRTYPE, default A)")
	_, _ = fmt.Printf("  %-24s %s\n", "--class <class>", "query class (env CLASS, default IN)")
	_, _ = fmt.Printf("  %-24s %s\n", "--subnet <subnet>", "EDNS Client Subnet in CIDR notation (env SUBNET)")
	_, _ = fmt.Printf("  %-24s %s\n", "--ednsopt <code[:value]>", "EDNS option (env EDNSOPT)")
	_, _ = fmt.Printf("  %-24s %s\n", "--dnssec", "set the DNSSEC DO bit in the request (env DNSSEC=1)")
	_, _ = fmt.Printf("  %-24s %s\n", "--pad", "add EDNS0 Padding to the request (env PAD=1)")
	_, _ = fmt.Printf("  %-24s %s\n", "--timeout <seconds>", "query timeout in seconds (env TIMEOUT, default 10)")
	_, _ = fmt.Printf("  %-24s %s\n", "--json", "machine-readable JSON output (env JSON=1)")
	_, _ = fmt.Printf("  %-24s %s\n", "--verify=<bool>", "verify the TLS certificate, --verify=false disables (env VERIFY, default true)")
	_, _ = fmt.Printf("  %-24s %s\n", "--http3", "enable HTTP/3 support for DNS-over-HTTPS (env HTTP3=1)")
	_, _ = fmt.Printf("  %-24s %s\n", "--verbose", "verbose logging (env VERBOSE=1)")
	_, _ = fmt.Printf("  %-24s %s\n", "-v, --version", "print the version and exit")
	_, _ = fmt.Printf("  %-24s %s\n", "-h, --help", "print this help and exit")
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
