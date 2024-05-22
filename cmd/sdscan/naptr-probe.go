package main

import (
	"strings"

	"github.com/etclab/resolv"
	"github.com/miekg/dns"
)

type NAPTRInfo struct {
	// NAPTR Record
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string

	// NAPTR record(s) DNSSEC validation
	NAPTRValidated DNSSECValidationResult

	// If NAPTR record has Flags with an "s", then make an SRV
	// query to Replacement.
	Services []*ServiceInstanceInfoX
}

type NAPTRProbeResult struct {
	NAPTRs []*NAPTRInfo
}

func NewNAPTRProbeResult() *NAPTRProbeResult {
	r := new(NAPTRProbeResult)
	return r
}

func DoNAPTRProbe(c *resolv.Client, domain string, validate bool) *NAPTRProbeResult {
	r := NewNAPTRProbeResult()

	resp, err := c.Lookup(domain, dns.TypeNAPTR)
	if err != nil {
		return nil
	}

	var naptrValidated DNSSECValidationResult
	if validate {
		naptrValidated = CheckDNSSECValidation(c, domain, dns.TypeNAPTR)
	}

	naptrs := resolv.CollectRRs[*dns.NAPTR](resp.Answer)
	for _, naptr := range naptrs {
		ninfo := &NAPTRInfo{
			Order:          naptr.Order,
			Preference:     naptr.Preference,
			Flags:          naptr.Flags,
			Service:        naptr.Service,
			Regexp:         naptr.Regexp,
			Replacement:    naptr.Replacement,
			NAPTRValidated: naptrValidated,
		}

		flags := strings.ToLower(naptr.Flags)
		if strings.Contains(flags, "s") && naptr.Replacement != "." && strings.TrimSpace(naptr.Replacement) != "" {
			infoxs := SRVQuery(c, naptr.Replacement, validate)
			if infoxs != nil {
				ninfo.Services = infoxs
			}
		}

		r.NAPTRs = append(r.NAPTRs, ninfo)
	}

	return r
}
