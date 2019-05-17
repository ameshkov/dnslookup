package main

import (
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		log.Printf("Wrong number of arguments")
		usage()
		os.Exit(1)
	}

	domain := os.Args[1]
	server := os.Args[2]

	log.Printf("Domain: %s", domain)
	log.Printf("Server: %s", server)

	u, err := upstream.AddressToUpstream(server, upstream.Options{})
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

	log.Print("dnslookup result:")
	log.Print(reply.String())
}

func usage() {
	log.Print("Usage: dnslookup [domain] [server]")
	log.Print("[domain]: domain name to lookup")
	log.Print("[server]: server address. Supported: plain, tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt)")
}