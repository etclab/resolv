package main

import (
	"log"
	"net/netip"
	"slices"
	"strings"

	"github.com/etclab/netx"
	"github.com/etclab/resolv"
	"github.com/miekg/dns"
)

type DNSSECProbeResult struct {
	ApexDomain            string
	DNSKEYs               []*dns.DNSKEY
	ParentZoneApexDomain  string
	ParentZoneNameservers []*resolv.Nameserver
	DS                    *dns.DS
}

func NewDNSSECProbeResult() *DNSSECProbeResult {
	r := new(DNSSECProbeResult)
	return r
}

func createDNSClient(serverIP netip.Addr) *resolv.Client {
	c := &resolv.Client{
		AD:        false,
		CD:        true,
		DO:        true,
		RD:        false, // N.B., we're assuming the client queries an authoritative nameserver
		MaxCNAMEs: 5,     // FIXME: don't hardcode
	}

	c.Transport = &resolv.Do53UDP{
		Server:           netx.TryJoinHostPort(serverIP.String(), "53"),
		UDPBufSize:       resolv.DefaultUDPBufSize,
		IgnoreTruncation: false,
		Timeout:          resolv.DefaultTimeout,
	}
	return c
}

func DoDNSSECProbe(c *resolv.Client, domain string) *DNSSECProbeResult {
	r := NewDNSSECProbeResult()

	apex, err := c.GetApexDomain(domain)
	if err != nil {
		log.Printf("[SMH] Can't get apex for %s", domain)
		return r
	}
	r.ApexDomain = apex

	resp, err := c.Lookup(r.ApexDomain, dns.TypeDNSKEY)
	if err == nil {
		r.DNSKEYs = resolv.CollectRRs[*dns.DNSKEY](resp.Answer)
	}

	labels := dns.SplitDomainName(apex)
	labels = slices.Delete(labels, 0, 1)
	target := dns.Fqdn(strings.Join(labels, "."))
	parentApex, err := c.GetApexDomain(target)
	if err != nil {
		log.Printf("[SMH] Can't get parent apex for %s", domain)
		return r
	}
	r.ParentZoneApexDomain = parentApex

	nameservers, err := c.GetNameservers(r.ParentZoneApexDomain)
	if err != nil {
		log.Printf("[SMH] Can't get parent apex nameservers for %s (apex=%s, parent apex=%s)", domain, r.ApexDomain, r.ParentZoneApexDomain)
		return r
	}
	r.ParentZoneNameservers = nameservers

	// TODO: create a separate client for this query
outer:
	for _, nameserver := range r.ParentZoneNameservers {
		for _, addr := range nameserver.Addrs {
			tmpClient := createDNSClient(addr)
			// Query the parent for the DS of the child
			resp, err := tmpClient.Lookup(apex, dns.TypeDS)
			tmpClient.Close()
			if err == nil {
				r.DS = resolv.CollectRRs[*dns.DS](resp.Answer)[0]
				break outer
			}
			if err == resolv.ErrRcode || err == resolv.ErrNoData || err == resolv.ErrInvalidCNAMEs || err == resolv.ErrMaxCNAMEs || err == resolv.ErrBadData {
				// we got a response, but it doesn't have a DS resource record
				log.Printf("[SMH] expected error when querying parent apex nameserver domain=%s apex=%s parent_apex=%s ns=%v: %v", domain, r.ApexDomain, r.ParentZoneApexDomain, addr, err)
				break outer
			}
			log.Printf("[SMH] possible network error when querying parent apex nameserver domain=%s apex=%s parent_apex=%s ns=%v: %v", domain, r.ApexDomain, r.ParentZoneApexDomain, addr, err)
			// we assume a network error and move onto the next DNS server address.
		}
	}

	return r
}
