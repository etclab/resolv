package main

import (
	"fmt"
	"net/netip"

	"github.com/etclab/resolv"
	"github.com/miekg/dns"
)

type SRVProbeResult struct {
	Services map[string][]*ServiceInstanceInfoX
}

func NewSRVProbeResult() *SRVProbeResult {
	r := new(SRVProbeResult)
	r.Services = make(map[string][]*ServiceInstanceInfoX)
	return r
}

func getServiceIPs(c *resolv.Client, srvTarget string, resp *dns.Msg) []netip.Addr {
	var err error
	var addrs []netip.Addr

	// Check if Response includes A records in the Additional section
	as := resolv.CollectRRs[*dns.A](resp.Extra)
	for _, a := range as {
		if a.Hdr.Name != srvTarget {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A)
		if !ok {
			continue
		}
		addrs = append(addrs, addr)
	}

	// Check if Response includes AAAA records in the Additional section
	aaaas := resolv.CollectRRs[*dns.AAAA](resp.Extra)
	for _, aaaa := range aaaas {
		if aaaa.Hdr.Name != srvTarget {
			continue
		}
		addr, ok := netip.AddrFromSlice(aaaa.AAAA)
		if !ok {
			continue
		}
		addrs = append(addrs, addr)
	}

	if len(addrs) == 0 {
		// not an error if fails
		addrs, err = c.GetIPs(srvTarget)
		if err != nil {
			addrs = nil // paranoid
		}
	}

	return addrs
}

func SRVQuery(c *resolv.Client, domainname string, validate bool) []*ServiceInstanceInfoX {
	var results []*ServiceInstanceInfoX

	resp, err := c.Lookup(domainname, dns.TypeSRV)
	if err != nil {
		return nil
	}

	var srvValidated DNSSECValidationResult
	if validate {
		srvValidated = CheckDNSSECValidation(c, domainname, dns.TypeSRV)
	}

	srvs := resolv.CollectRRs[*dns.SRV](resp.Answer)
	for _, srv := range srvs {
		infox := &ServiceInstanceInfoX{
			ServiceInstanceInfo: resolv.ServiceInstanceInfo{
				Name:     domainname,
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
			},
		}
		infox.SrvValidated = srvValidated

		if infox.Target != "." {
			infox.Addrs = getServiceIPs(c, infox.Target, resp)
			infox.AValidated = CheckDNSSECValidation(c, infox.Target, dns.TypeA)
			infox.AAAAValidated = CheckDNSSECValidation(c, infox.Target, dns.TypeAAAA)
		}
		results = append(results, infox)
	}

	return results
}

func DoSRVProbe(c *resolv.Client, domain string, serviceNames []string, validate bool) *SRVProbeResult {
	r := NewSRVProbeResult()

	var foundFlag bool
	for _, service := range serviceNames {
		name := fmt.Sprintf("%s.%s", service, domain)
		infoxs := SRVQuery(c, name, validate)
		if infoxs == nil {
			continue
		}
		r.Services[service] = infoxs
		foundFlag = true
	}

	if foundFlag {
		return r
	}
	return nil
}
