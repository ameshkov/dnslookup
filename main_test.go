package main

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mustBuildRequest(
	t *testing.T,
	q dns.Question,
	dnssec bool,
	subnet *dns.EDNS0_SUBNET,
	ednsOpt *dns.EDNS0_LOCAL,
	padding bool,
) *dns.Msg {
	t.Helper()

	req, err := buildRequest(q, requestOptions{
		DNSSEC:  dnssec,
		Subnet:  subnet,
		EDNSOpt: ednsOpt,
		Padding: padding,
	})
	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}

	return req
}

func TestBuildRequest_EDNS(t *testing.T) {
	t.Parallel()

	defaultQ := dns.Question{
		Name:   "example.org.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	cases := []struct {
		name        string
		q           dns.Question
		dnssec      bool
		padding     bool
		wantOPT     bool
		wantDO      bool
		wantPadding bool
	}{
		{
			name:    "do_bit_alone",
			q:       defaultQ,
			dnssec:  true,
			wantOPT: true,
			wantDO:  true,
		},
		{
			name:    "no_option_means_no_opt",
			q:       defaultQ,
			wantOPT: false,
		},
		{
			name:        "do_bit_with_padding",
			q:           defaultQ,
			dnssec:      true,
			padding:     true,
			wantOPT:     true,
			wantDO:      true,
			wantPadding: true,
		},
		{
			name:        "padding_without_do_bit",
			q:           defaultQ,
			padding:     true,
			wantOPT:     true,
			wantDO:      false,
			wantPadding: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := mustBuildRequest(t, tc.q, tc.dnssec, nil, nil, tc.padding)
			if _, err := req.Pack(); err != nil {
				t.Fatalf("Pack failed: %v", err)
			}

			opt := req.IsEdns0()
			if !tc.wantOPT {
				if opt != nil {
					t.Fatalf("expected IsEdns0() == nil, got OPT record")
				}
				if len(req.Extra) != 0 {
					t.Fatalf("expected len(Extra) == 0, got %d", len(req.Extra))
				}

				return
			}

			if opt == nil {
				t.Fatalf("expected IsEdns0() != nil, got nil")
			}
			if len(req.Extra) != 1 {
				t.Fatalf("expected len(Extra) == 1, got %d", len(req.Extra))
			}
			if _, ok := req.Extra[0].(*dns.OPT); !ok {
				t.Fatalf("expected Extra[0] to be *dns.OPT, got %T", req.Extra[0])
			}
			if opt.Do() != tc.wantDO {
				t.Fatalf("expected Do() == %v, got %v", tc.wantDO, opt.Do())
			}

			hasPadding := false
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_PADDING); ok {
					hasPadding = true
				}
			}
			if hasPadding != tc.wantPadding {
				t.Fatalf("expected padding option present == %v, got %v", tc.wantPadding, hasPadding)
			}
		})
	}
}

func TestParseSubnet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		cidr        string
		wantErr     bool
		wantFamily  uint16
		wantAddrLen int
		wantMask    uint8
		wantScope   uint8
		wantAddr    net.IP
	}{
		{
			name:        "ecs_ipv4",
			cidr:        "1.2.3.0/24",
			wantFamily:  1,
			wantAddrLen: net.IPv4len,
			wantMask:    24,
			wantScope:   0,
			wantAddr:    net.IPv4(1, 2, 3, 0).To4(),
		},
		{
			name:    "ipv4_without_prefix_rejected",
			cidr:    "1.2.3.4",
			wantErr: true,
		},
		{
			name:        "ecs_ipv6",
			cidr:        "2001:db8::/56",
			wantFamily:  2,
			wantAddrLen: net.IPv6len,
			wantMask:    56,
			wantScope:   0,
			wantAddr:    net.ParseIP("2001:db8::").To16(),
		},
		{
			name:    "ipv6_mask_129_rejected",
			cidr:    "2001:db8::/129",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opt, err := parseSubnet(tc.cidr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.cidr)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseSubnet(%q) unexpected error: %v", tc.cidr, err)
			}
			if opt == nil {
				t.Fatalf("parseSubnet(%q) returned nil option", tc.cidr)
			}
			if opt.Code != dns.EDNS0SUBNET {
				t.Fatalf("expected Code %d, got %d", dns.EDNS0SUBNET, opt.Code)
			}
			if opt.Family != tc.wantFamily {
				t.Fatalf("expected Family %d, got %d", tc.wantFamily, opt.Family)
			}
			if len(opt.Address) != tc.wantAddrLen {
				t.Fatalf("expected len(Address) == %d, got %d", tc.wantAddrLen, len(opt.Address))
			}
			if !opt.Address.Equal(tc.wantAddr) {
				t.Fatalf("expected Address %v, got %v", tc.wantAddr, opt.Address)
			}
			if opt.SourceNetmask != tc.wantMask {
				t.Fatalf("expected SourceNetmask %d, got %d", tc.wantMask, opt.SourceNetmask)
			}
			if opt.SourceScope != tc.wantScope {
				t.Fatalf("expected SourceScope %d, got %d", tc.wantScope, opt.SourceScope)
			}

			q := dns.Question{
				Name:   "example.org.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			req := mustBuildRequest(t, q, false, opt, nil, false)
			if _, err = req.Pack(); err != nil {
				t.Fatalf("Pack with Subnet failed: %v", err)
			}
		})
	}
}

func TestPaddingBlock128(t *testing.T) {
	t.Parallel()

	label63 := strings.Repeat("a", 63) + "."
	name253 := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 60) + "."

	cases := []struct {
		name       string
		qname      string
		withExtras bool
	}{
		{
			name:  "padding_one_letter_name",
			qname: "a.",
		},
		{
			name:  "padding_example_org",
			qname: "example.org.",
		},
		{
			name:  "padding_63_byte_label",
			qname: label63,
		},
		{
			name:  "padding_253_byte_name",
			qname: name253,
		},
		{
			name:       "padding_253_byte_name_with_subnet_and_ednsopt",
			qname:      name253,
			withExtras: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var subnet *dns.EDNS0_SUBNET
			var ednsOpt *dns.EDNS0_LOCAL
			if tc.withExtras {
				var err error
				subnet, err = parseSubnet("1.2.3.0/24")
				if err != nil {
					t.Fatalf("parseSubnet failed: %v", err)
				}
				ednsOpt, err = parseEDNSOpt("65074:3132")
				if err != nil {
					t.Fatalf("parseEDNSOpt failed: %v", err)
				}
			}

			q := dns.Question{
				Name:   tc.qname,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			req := mustBuildRequest(t, q, false, subnet, ednsOpt, true)

			packed, err := req.Pack()
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if len(packed)%requestPaddingBlockSize != 0 {
				t.Fatalf("expected len(packed) %% %d == 0, got len(packed) == %d", requestPaddingBlockSize, len(packed))
			}
			if len(packed) > udpBufferSize {
				t.Fatalf("expected len(packed) <= %d, got %d", udpBufferSize, len(packed))
			}

			probe := &dns.Msg{}
			probe.Id = req.Id
			probe.RecursionDesired = req.RecursionDesired
			probe.Question = []dns.Question{q}
			probe.SetEdns0(udpBufferSize, false)
			probeOpt := probe.IsEdns0()
			if subnet != nil {
				probeOpt.Option = append(probeOpt.Option, subnet)
			}
			if ednsOpt != nil {
				probeOpt.Option = append(probeOpt.Option, ednsOpt)
			}
			padOpt := newEDNS0Padding(probe)
			if padOpt == nil {
				t.Fatalf("newEDNS0Padding returned nil")
			}
			probeOpt.Option = append(probeOpt.Option, padOpt)
			probePacked, err := probe.Pack()
			if err != nil {
				t.Fatalf("probe.Pack failed: %v", err)
			}
			if len(probePacked) != len(packed) {
				t.Fatalf("expected packed length %d matching newEDNS0Padding probe, got %d", len(probePacked), len(packed))
			}
		})
	}
}

func TestParseEDNSOpt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    string
		wantErr  bool
		wantCode uint16
		wantData []byte
	}{
		{
			name:     "ednsopt_code_with_data",
			input:    "65074:3132",
			wantCode: 65074,
			wantData: []byte{0x31, 0x32},
		},
		{
			name:     "ednsopt_code_without_data",
			input:    "65074",
			wantCode: 65074,
			wantData: nil,
		},
		{
			name:    "ednsopt_code_70000_rejected",
			input:   "70000:00",
			wantErr: true,
		},
		{
			name:    "ednsopt_negative_code_rejected",
			input:   "-1",
			wantErr: true,
		},
		{
			name:    "ednsopt_non_numeric_code_rejected",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "ednsopt_bad_hex_rejected",
			input:   "1:zz",
			wantErr: true,
		},
		{
			name:    "ednsopt_extra_separator_rejected",
			input:   "1:00:ff",
			wantErr: true,
		},
		{
			name:    "ednsopt_empty_rejected",
			input:   "",
			wantErr: true,
		},
		{
			name:     "ednsopt_code_65535_accepted",
			input:    "65535:ff",
			wantCode: 65535,
			wantData: []byte{0xff},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opt, err := parseEDNSOpt(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.input)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseEDNSOpt(%q) unexpected error: %v", tc.input, err)
			}
			if opt == nil {
				t.Fatalf("parseEDNSOpt(%q) returned nil option", tc.input)
			}
			if opt.Code != tc.wantCode {
				t.Fatalf("expected Code %d, got %d", tc.wantCode, opt.Code)
			}
			if !bytes.Equal(opt.Data, tc.wantData) {
				t.Fatalf("expected Data %x, got %x", tc.wantData, opt.Data)
			}
		})
	}
}

func TestBuildRequest_QuestionPreserved(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		q    dns.Question
	}{
		{
			name: "question_preserved",
			q: dns.Question{
				Name:   "example.org.",
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := mustBuildRequest(t, tc.q, false, nil, nil, false)
			if len(req.Question) != 1 {
				t.Fatalf("expected len(Question) == 1, got %d", len(req.Question))
			}
			got := req.Question[0]
			if got.Name != tc.q.Name {
				t.Fatalf("expected Question[0].Name %q, got %q", tc.q.Name, got.Name)
			}
			if got.Qtype != tc.q.Qtype {
				t.Fatalf("expected Question[0].Qtype %d, got %d", tc.q.Qtype, got.Qtype)
			}
			if got.Qclass != tc.q.Qclass {
				t.Fatalf("expected Question[0].Qclass %d, got %d", tc.q.Qclass, got.Qclass)
			}
			if !req.RecursionDesired {
				t.Fatalf("expected RecursionDesired == true, got false")
			}
		})
	}
}

func TestParseSubnet_MappedPrefix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		cidr        string
		wantFamily  uint16
		wantAddrLen int
		wantMask    uint8
		wantScope   uint8
		wantAddr    net.IP
	}{
		{
			name:        "ipv4_mapped_prefix_stays_ipv6",
			cidr:        "::ffff:192.0.2.0/120",
			wantFamily:  2,
			wantAddrLen: net.IPv6len,
			wantMask:    120,
			wantScope:   0,
			wantAddr:    net.ParseIP("::ffff:192.0.2.0").To16(),
		},
		{
			name:        "ipv4_prefix_stays_ipv4",
			cidr:        "192.0.2.0/24",
			wantFamily:  1,
			wantAddrLen: net.IPv4len,
			wantMask:    24,
			wantScope:   0,
			wantAddr:    net.IPv4(192, 0, 2, 0).To4(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opt, err := parseSubnet(tc.cidr)
			if err != nil {
				t.Fatalf("parseSubnet(%q) unexpected error: %v", tc.cidr, err)
			}
			if opt == nil {
				t.Fatalf("parseSubnet(%q) returned nil option", tc.cidr)
			}
			if opt.Code != dns.EDNS0SUBNET {
				t.Fatalf("expected Code %d, got %d", dns.EDNS0SUBNET, opt.Code)
			}
			if opt.Family != tc.wantFamily {
				t.Fatalf("expected Family %d, got %d", tc.wantFamily, opt.Family)
			}
			if len(opt.Address) != tc.wantAddrLen {
				t.Fatalf("expected len(Address) == %d, got %d", tc.wantAddrLen, len(opt.Address))
			}
			if !opt.Address.Equal(tc.wantAddr) {
				t.Fatalf("expected Address %v, got %v", tc.wantAddr, opt.Address)
			}
			if opt.SourceNetmask != tc.wantMask {
				t.Fatalf("expected SourceNetmask %d, got %d", tc.wantMask, opt.SourceNetmask)
			}
			if opt.SourceScope != tc.wantScope {
				t.Fatalf("expected SourceScope %d, got %d", tc.wantScope, opt.SourceScope)
			}

			q := dns.Question{
				Name:   "example.org.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			req := mustBuildRequest(t, q, false, opt, nil, false)
			if _, err = req.Pack(); err != nil {
				t.Fatalf("Pack with Subnet failed: %v", err)
			}
		})
	}
}

func TestBuildRequest_PaddingBudget(t *testing.T) {
	t.Parallel()

	ednsInput := "65074:" + strings.Repeat("00", 4052)
	defaultQ := dns.Question{
		Name:   "example.org.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	cases := []struct {
		name    string
		q       dns.Question
		padding bool
		wantErr bool
	}{
		{
			name:    "padding_over_budget_rejected",
			q:       defaultQ,
			padding: true,
			wantErr: true,
		},
		{
			name:    "large_option_without_padding_accepted",
			q:       defaultQ,
			padding: false,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ednsOpt, err := parseEDNSOpt(ednsInput)
			if err != nil {
				t.Fatalf("parseEDNSOpt failed: %v", err)
			}

			req, err := buildRequest(tc.q, requestOptions{
				EDNSOpt: ednsOpt,
				Padding: tc.padding,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error from buildRequest, got nil")
				}

				return
			}
			if err != nil {
				t.Fatalf("buildRequest unexpected error: %v", err)
			}
			if req == nil {
				t.Fatalf("buildRequest returned nil message")
			}

			packed, err := req.Pack()
			if err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
			if len(packed) > udpBufferSize {
				t.Fatalf("expected len(packed) <= %d, got %d", udpBufferSize, len(packed))
			}
		})
	}
}

func TestBuildRequest_PackError(t *testing.T) {
	t.Parallel()

	label64 := strings.Repeat("a", 64) + "."
	label63 := strings.Repeat("a", 63) + "."

	cases := []struct {
		name    string
		qname   string
		wantErr bool
	}{
		{
			name:    "unpackable_64_byte_label_rejected",
			qname:   label64,
			wantErr: true,
		},
		{
			name:    "packable_63_byte_label_accepted",
			qname:   label63,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q := dns.Question{
				Name:   tc.qname,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}

			req, err := buildRequest(q, requestOptions{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error from buildRequest for %q, got nil", tc.qname)
				}

				return
			}
			if err != nil {
				t.Fatalf("buildRequest(%q) unexpected error: %v", tc.qname, err)
			}
			if req == nil {
				t.Fatalf("buildRequest(%q) returned nil message", tc.qname)
			}
			if _, err = req.Pack(); err != nil {
				t.Fatalf("Pack failed: %v", err)
			}
		})
	}
}

func TestParseEDNSOpt_Diagnostics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		input         string
		wantErr       bool
		wantErrSubstr string
		wantCode      uint16
		wantData      []byte
	}{
		{
			name:          "non_numeric_code_keeps_atoi_message",
			input:         "abc",
			wantErr:       true,
			wantErrSubstr: "strconv.Atoi",
		},
		{
			name:          "out_of_range_code_message",
			input:         "70000",
			wantErr:       true,
			wantErrSubstr: "out of range",
		},
		{
			name:     "code_65535_accepted",
			input:    "65535",
			wantCode: 65535,
			wantData: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opt, err := parseEDNSOpt(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.input)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("expected error for %q to contain %q, got %q", tc.input, tc.wantErrSubstr, err.Error())
				}

				return
			}
			if err != nil {
				t.Fatalf("parseEDNSOpt(%q) unexpected error: %v", tc.input, err)
			}
			if opt == nil {
				t.Fatalf("parseEDNSOpt(%q) returned nil option", tc.input)
			}
			if opt.Code != tc.wantCode {
				t.Fatalf("expected Code %d, got %d", tc.wantCode, opt.Code)
			}
			if !bytes.Equal(opt.Data, tc.wantData) {
				t.Fatalf("expected Data %x, got %x", tc.wantData, opt.Data)
			}
		})
	}
}
