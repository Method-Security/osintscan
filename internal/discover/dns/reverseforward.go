package dns

import (
	"net"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
)

func GetReverseForwardDNSLookup(fqdn string) dnsfern.DiscoverDnsReverseForwardReport {
	report := dnsfern.DiscoverDnsReverseForwardReport{
		Domain: fqdn,
	}
	errors := []string{}

	// Resolve the IP addresses for the given FQDN
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	lookUps := []*dnsfern.LookUpDetails{}
	for _, ip := range ips {
		// Perform a reverse lookup (PTR record)
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			errors = append(errors, err.Error())
		}

		// Store resolved hostnames per IP
		lookUps = append(lookUps, &dnsfern.LookUpDetails{
			Ip:      ip.String(),
			DnsPtrs: names,
		})
	}
	report.LookUps = lookUps
	report.Errors = errors
	return report
}
