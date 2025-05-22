package dns

import (
	"net"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
)

// GetReverseForwardDNSLookup performs both forward (A/AAAA) and reverse (PTR) DNS lookups for a given FQDN.
// Returns a report containing all resolved IPs and their associated hostnames, along with any errors encountered.
func GetReverseForwardDNSLookup(fqdn string) dnsfern.DiscoverDnsReverseForwardReport {
	report := dnsfern.DiscoverDnsReverseForwardReport{
		Domain: fqdn,
	}
	errors := []string{}

	// Resolve the IP addresses for the given FQDN (forward lookup)
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	lookUps := []*dnsfern.LookUpDetails{}
	for _, ip := range ips {
		// Perform a reverse lookup (PTR record) for each IP
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
