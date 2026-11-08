package main

import (
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// requestPaddingBlockSize is the block length used to pad requests according
// to RFC 8467 (block-length padding, section 4.1).
const requestPaddingBlockSize = 128
const udpBufferSize = dns.DefaultMsgSize

// requestOptions carries the EDNS-related options of a query.
type requestOptions struct {
	DNSSEC  bool              // set the DO bit (RFC 3225, RFC 4035 §4.9.1)
	Subnet  *dns.EDNS0_SUBNET // EDNS Client Subnet option, nil if absent
	EDNSOpt *dns.EDNS0_LOCAL  // arbitrary EDNS option, nil if absent
	Padding bool              // RFC 8467 block-length padding of the request
}

// buildRequest builds the DNS query for q.  An OPT record is added when, and
// only when, at least one field of opts is set (DNSSEC alone included).  The
// returned message packs without error.
func buildRequest(q dns.Question, opts requestOptions) (req *dns.Msg, err error) {
	req = &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{q}

	if opts.Subnet != nil || opts.EDNSOpt != nil || opts.DNSSEC || opts.Padding {
		req.SetEdns0(udpBufferSize, opts.DNSSEC)
		opt := req.IsEdns0()

		if opts.Subnet != nil {
			opt.Option = append(opt.Option, opts.Subnet)
		}

		if opts.EDNSOpt != nil {
			opt.Option = append(opt.Option, opts.EDNSOpt)
		}

		if opts.Padding {
			// The padding option itself needs 4 bytes for its header, so the
			// message without padding plus 4 bytes must fit in the UDP buffer.
			if req.Len()+4 > udpBufferSize {
				return nil, errors.New("request too large for padding")
			}

			opt.Option = append(opt.Option, newEDNS0Padding(req))
		}
	}

	// Pack before returning so that serialization errors (e.g. a malformed
	// question name) are reported by buildRequest itself.
	if _, err = req.Pack(); err != nil {
		return nil, err
	}

	return req, nil
}

// parseSubnet parses a CIDR prefix into an ECS option: Family 1 and a 4-byte
// address for IPv4, Family 2 and a 16-byte address for IPv6, SourceNetmask set
// to the prefix length, SourceScope 0.
func parseSubnet(cidr string) (opt *dns.EDNS0_SUBNET, err error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipNet.Mask.Size()

	// The family is decided by the mask width, never by To4(): an IPv4-mapped
	// IPv6 prefix such as ::ffff:192.0.2.0/120 must stay family 2.
	family := uint16(1)
	address := ipNet.IP.To4()
	if bits == 128 {
		family = 2
		address = ipNet.IP.To16()
	}

	return &dns.EDNS0_SUBNET{
		Code:   dns.EDNS0SUBNET,
		Family: family,
		// #nosec G115 -- Assume that ones always fit in uint8.
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       address,
	}, nil
}

// parseEDNSOpt parses "code" or "code:hexvalue".  code must be a decimal
// integer in [0, 65535]; hexvalue must be valid hexadecimal; any further ':'
// is an error.
func parseEDNSOpt(s string) (opt *dns.EDNS0_LOCAL, err error) {
	parts := strings.Split(s, ":")
	if len(parts) > 2 {
		return nil, errors.New("too many ':' separators")
	}

	code, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}
	if code < 0 || code > 65535 {
		return nil, errors.New("EDNSOPT code out of range [0, 65535]")
	}

	var value []byte
	if len(parts) == 2 {
		value, err = hex.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	}

	return &dns.EDNS0_LOCAL{
		// #nosec G115 -- The range check above guarantees that code fits in uint16.
		Code: uint16(code),
		Data: value,
	}, nil
}

// newEDNS0Padding constructs a new OPT RR EDNS0 Padding for the extra section.
func newEDNS0Padding(req *dns.Msg) (option *dns.EDNS0_PADDING) {
	// msgLen is the packed length of req including the 4-byte header of the
	// padding option itself.
	msgLen := req.Len() + 4
	padLen := (requestPaddingBlockSize - msgLen%requestPaddingBlockSize) % requestPaddingBlockSize

	return &dns.EDNS0_PADDING{Padding: make([]byte, padLen)}
}
