package dns

import (
	// Standard
	"context"
	"math/rand"
	"net"

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	// Utils
	"github.com/Method-Security/osintscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetForwardDNSLookup performs forward (A/AAAA) DNS lookups for a given FQDN.
// Returns a report containing all resolved IPs, along with any errors encountered.
func GetForwardDNSLookup(config dnsfern.DiscoverDnsForwardConfig) dnsfern.DiscoverDnsForwardReverseReport {
	errors := []string{}

	lookUps, errs := getLookups(config.Domain, config.DnsResolvers)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}

	results := dnsfern.DiscoverDnsForwardResult{
		Lookups: lookUps,
	}

	report := dnsfern.DiscoverDnsForwardReverseReport{
		Config: &config,
		Result: &results,
		Errors: errors,
	}
	return report
}

func getLookups(domain string, dnsResolvers []string) ([]*dnsfern.LookupDetails, []string) {
	ctx := context.Background()
	log := svc1log.FromContext(ctx)
	errors := []string{}

	// Pick a random resolver from the list
	resolver := utils.GetResolver(dnsResolvers[rand.Intn(len(dnsResolvers))], log)

	// Resolve the IP addresses for the given FQDN (forward lookup)
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		errors = append(errors, err.Error())
		return []*dnsfern.LookupDetails{}, errors
	}

	lookUps := []*dnsfern.LookupDetails{}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Store domain and IP address for each resolved IP
		lookUps = append(lookUps, &dnsfern.LookupDetails{
			Domain:    domain,
			IpAddress: &ipStr,
		})
	}

	return lookUps, errors
}
