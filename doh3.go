package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

func isH3(server string) bool {
	u, err := url.Parse(server)
	return err == nil && u.Scheme == "h3"
}

func h3ToHTTPs(server string) string {
	u, _ := url.Parse(server)
	u.Scheme = "https"
	return u.String()
}

func doh3(server string, d dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	server = h3ToHTTPs(server)
	buf, err := d.Pack()
	if err != nil {
		return nil, err
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	var qconf quic.Config
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: false,
		},
		QuicConfig: &qconf,
		//Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
		//	switch addr {
		//	case "cloudflare-dns.com:443":
		//		{
		//			addr = "1.1.1.1:443"
		//		}
		//	case "dns.google:443":
		//		{
		//			addr = "8.8.8.8:443"
		//		}
		//	}
		//	return quic.DialAddrEarly(addr, tlsCfg, cfg)
		//},
	}
	defer roundTripper.Close()

	hclient := &http.Client{
		Transport: roundTripper,
		Timeout:   timeout,
	}

	req, err := http.NewRequest(http.MethodGet, server+"?dns="+base64.RawURLEncoding.EncodeToString(buf), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-message")

	rsp, err := hclient.Do(req)
	if err != nil {
		return nil, err
	}

	defer rsp.Body.Close()

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	reply := &dns.Msg{}
	err = reply.Unpack(body)
	if err != nil {
		return nil, err
	}

	return reply, nil
}
