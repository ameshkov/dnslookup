package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
)

// VersionString -- see the makefile
var VersionString = "undefined"

func main() {
	machineReadable := os.Getenv("JSON") == "1"

	if !machineReadable {
		os.Stdout.WriteString(fmt.Sprintf("dnslookup %s\n", VersionString))
	}

	if len(os.Args) == 1 && os.Args[0] == "-h" {
		usage()
		os.Exit(1)
	}

	if len(os.Args) != 3 && len(os.Args) != 4 && len(os.Args) != 5 {
		log.Printf("Wrong number of arguments")
		usage()
		os.Exit(1)
	}

	domain := os.Args[1]
	server := os.Args[2]

	opts := upstream.Options{Timeout: 10 * time.Second}

	if len(os.Args) == 4 {
		opts.ServerIP = net.ParseIP(os.Args[3])
		if opts.ServerIP == nil {
			log.Fatalf("invalid IP specified: %s", os.Args[3])
		}
	}

	if len(os.Args) == 5 {
		// DNSCrypt parameters
		providerName := os.Args[3]
		serverPkStr := os.Args[4]

		serverPk, err := hex.DecodeString(strings.Replace(serverPkStr, ":", "", -1))
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

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: domain + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	reply, err := u.Exchange(&req)
	if err != nil {
		log.Fatalf("Cannot make the DNS request: %s", err)
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

func usage() {
	os.Stdout.WriteString("Usage: dnslookup <domain> <server> [<providerName> <serverPk>]\n")
	os.Stdout.WriteString("<domain>: mandatory, domain name to lookup\n")
	os.Stdout.WriteString("<server>: mandatory, server address. Supported: plain, tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt)\n")
	os.Stdout.WriteString("<providerName>: optional, DNSCrypt provider name\n")
	os.Stdout.WriteString("<serverPk>: optional, DNSCrypt server public key\n")
}
