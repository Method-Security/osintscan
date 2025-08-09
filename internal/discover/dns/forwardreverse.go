package dns

import (
	"context"
	"math/rand"
	"net"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/Method-Security/osintscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetForwardReverseDNSLookup performs both forward (A/AAAA) and reverse (PTR) DNS lookups for a given FQDN.
// Returns a report containing all resolved IPs and their associated hostnames, along with any errors encountered.
func GetForwardReverseDNSLookup(config dnsfern.DiscoverDnsForwardReverseConfig) dnsfern.DiscoverDnsForwardReverseReport {
	errors := []string{}

	lookUps, errs := getLookups(config.Domain, config.DnsResolvers)
	if len(errs) > 0 {
		errors = append(errors, errs...)
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

func getLookups(domain string, dnsResolvers []string) ([]*dnsfern.LookupDetails, []string) {
	ctx := context.Background()
	log := svc1log.FromContext(ctx)
	errors := []string{}

	resolver := func() *net.Resolver {
		if len(dnsResolvers) == 0 {
			return utils.GetResolver("", log)
		}
		return utils.GetResolver(dnsResolvers[rand.Intn(len(dnsResolvers))], log)
	}()

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

		// Perform a reverse lookup (PTR record) for each IP
		names, err := resolver.LookupAddr(ctx, ip.String())
		if err != nil {
			errors = append(errors, err.Error())
		}

		// Store resolved hostnames per IP
		lookUps = append(lookUps, &dnsfern.LookupDetails{
			ForwardIp:   &ipStr,
			ReversePtrs: names,
		})
	}

	return lookUps, errors
}
