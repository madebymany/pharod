package main

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func startDns() {
	dnsSuffix := "." + DnsTld + "."
	parseDnsName := func(name string) (out string, err error) {
		if strings.HasSuffix(name, dnsSuffix) {
			return strings.ToLower(strings.TrimSuffix(name, dnsSuffix)), nil
		} else {
			return "", fmt.Errorf("nxdomain: %s", name)
		}
	}

	s := dns.Server{
		Addr: "127.0.0.1:49152",
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, qMsg *dns.Msg) {
			rMsg := new(dns.Msg)
			if len(qMsg.Question) == 0 {
				rMsg.SetRcode(qMsg, dns.RcodeServerFailure)
			} else {
				query := qMsg.Question[0]
				qname, err := parseDnsName(query.Name)

				if ip, ok := dnsZone[qname]; err == nil && query.Qtype == dns.TypeA && ok {
					rMsg.SetReply(qMsg)
					rr := new(dns.A)
					rr.Hdr = dns.RR_Header{Name: query.Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 0}
					rr.A = ip
					rMsg.Answer = append(rMsg.Answer, rr)
				} else {
					rMsg.SetRcode(qMsg, dns.RcodeNameError)
				}
			}

			w.WriteMsg(rMsg)
		}),
	}
	s.ListenAndServe()
}
