package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// VersionString -- see the makefile
var VersionString = "undefined"

func main() {
	// parse env variables
	machineReadable := os.Getenv("JSON") == "1"
	insecureSkipVerify := os.Getenv("VERIFY") == "0"
	timeoutStr := os.Getenv("TIMEOUT")
	class := getClass()
	rrType := getRRType()

	timeout := 10

	if !machineReadable {
		os.Stdout.WriteString(fmt.Sprintf("dnslookup v. %s\n", VersionString))

		if len(os.Args) == 2 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
			os.Exit(0)
		}
	}

	if insecureSkipVerify {
		os.Stdout.WriteString("TLS verification has been disabled\n")
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		usage()
		os.Exit(0)
	}

	if len(os.Args) != 3 && len(os.Args) != 4 && len(os.Args) != 5 {
		log.Printf("Wrong number of arguments")
		usage()
		os.Exit(1)
	}

	if timeoutStr != "" {
		i, err := strconv.Atoi(timeoutStr)
		if err != nil {
			log.Printf("Wrong timeout value: %s", timeoutStr)
			usage()
			os.Exit(1)
		}

		timeout = i
	}

	domain := os.Args[1]
	server := os.Args[2]

	opts := &upstream.Options{
		Timeout:            time.Duration(timeout) * time.Second,
		InsecureSkipVerify: insecureSkipVerify,
	}

	if len(os.Args) == 4 {
		ip := net.ParseIP(os.Args[3])
		if ip == nil {
			log.Fatalf("invalid IP specified: %s", os.Args[3])
		}
		opts.ServerIPAddrs = []net.IP{ip}
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
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: domain + ".", Qtype: rrType, Qclass: class},
	}

	var reply *dns.Msg
	if isH3(server) {
		var err error
		reply, err = doh3(server, req, time.Duration(timeout)*time.Second)
		if err != nil {
			log.Fatalf("Cannot make the DNS request: %s", err)
		}
	} else {
		u, err := upstream.AddressToUpstream(server, opts)
		if err != nil {
			log.Fatalf("Cannot create an upstream: %s", err)
		}

		reply, err = u.Exchange(&req)
		if err != nil {
			log.Fatalf("Cannot make the DNS request: %s", err)
		}
	}

	if !machineReadable {
		os.Stdout.WriteString("dnslookup result:\n")
		os.Stdout.WriteString(reply.String() + "\n")
	} else {
		b, err := json.MarshalIndent(reply, "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		os.Stdout.WriteString(string(b) + "\n")
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
	os.Stdout.WriteString("Usage: dnslookup <domain> <server> [<providerName> <serverPk>]\n")
	os.Stdout.WriteString("<domain>: mandatory, domain name to lookup\n")
	os.Stdout.WriteString("<server>: mandatory, server address. Supported: plain, tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ), h3:// (DOH3)\n")
	os.Stdout.WriteString("<providerName>: optional, DNSCrypt provider name\n")
	os.Stdout.WriteString("<serverPk>: optional, DNSCrypt server public key\n")
}
