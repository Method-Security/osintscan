package dns

import (
	"net"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
)

// GetForwardReverseDNSLookup performs both forward (A/AAAA) and reverse (PTR) DNS lookups for a given FQDN.
// Returns a report containing all resolved IPs and their associated hostnames, along with any errors encountered.
func GetForwardReverseDNSLookup(config dnsfern.DiscoverDnsForwardReverseConfig) dnsfern.DiscoverDnsForwardReverseReport {
	errors := []string{}

	lookUps, err := getLookups(config.Domain, errors)
	if err != nil {
		errors = append(errors, err.Error())
	}

	results := dnsfern.DiscoverDnsForwardReverseResult{
		Lookups: lookUps,
	}

	report := dnsfern.DiscoverDnsForwardReverseReport{
		Config: &config,
		Result: &results,
		Errors: errors,
	}
	return report
}

func getLookups(domain string, errors []string) ([]*dnsfern.LookupDetails, error) {
	// Resolve the IP addresses for the given FQDN (forward lookup)
	ips, err := net.LookupIP(domain)
	if err != nil {
		errors = append(errors, err.Error())
	}

	lookUps := []*dnsfern.LookupDetails{}
	for _, ip := range ips {
		// Perform a reverse lookup (PTR record) for each IP
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			errors = append(errors, err.Error())
		}

		// Store resolved hostnames per IP
		ipStr := ip.String()
		lookUps = append(lookUps, &dnsfern.LookupDetails{
			ForwardIp:   &ipStr,
			ReversePtrs: names,
		})
	}

	return lookUps, nil
}
