package main

import (
	"encoding/hex"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ameshkov/dnsstamps"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) != 3 && len(os.Args) != 5 {
		log.Printf("Wrong number of arguments")
		usage()
		os.Exit(1)
	}

	domain := os.Args[1]
	server := os.Args[2]

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

	log.Printf("Domain: %s", domain)
	log.Printf("Server: %s", server)

	u, err := upstream.AddressToUpstream(server, upstream.Options{Timeout: 10 * time.Second})
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

	_,_ = os.Stdout.WriteString("dnslookup result:")
	_,_ = os.Stdout.WriteString(reply.String())
}

func usage() {
	log.Print("Usage: dnslookup <domain> <server> [<providerName> <serverPk>]")
	log.Print("<domain>: mandatory, domain name to lookup")
	log.Print("<server>: mandatory, server address. Supported: plain, tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt)")
	log.Print("<providerName>: optional, DNSCrypt provider name")
	log.Print("<serverPk>: optional, DNSCrypt server public key")
}
