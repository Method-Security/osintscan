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
func GetForwardDNSLookup(ctx context.Context, config dnsfern.DiscoverDnsForwardConfig) dnsfern.DiscoverDnsForwardReport {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting forward DNS lookup", svc1log.SafeParam("domain", config.Domain))

	lookUps, errs := getLookups(ctx, config.Domain, config.DnsResolvers)
	if len(errs) > 0 {
		errors = append(errors, errs...)
		log.Warn("Forward DNS lookup encountered errors", svc1log.SafeParam("domain", config.Domain), svc1log.SafeParam("error_count", len(errs)))
	}

	results := dnsfern.DiscoverDnsForwardResult{
		Lookups: lookUps,
	}

	report := dnsfern.DiscoverDnsForwardReport{
		Config: &config,
		Result: &results,
		Errors: errors,
	}

	log.Info("Completed forward DNS lookup",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("resolved_ips", len(lookUps)),
		svc1log.SafeParam("error_count", len(errors)))

	return report
}

func getLookups(ctx context.Context, domain string, dnsResolvers []string) ([]*dnsfern.LookupDetails, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	// Pick a random resolver from the list
	resolverIndex := rand.Intn(len(dnsResolvers))
	resolverAddress := dnsResolvers[resolverIndex]
	resolver := utils.GetResolver(resolverAddress, log)

	log.Debug("Performing DNS lookup",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("resolver", resolverAddress))

	// Resolve the IP addresses for the given FQDN (forward lookup)
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		log.Warn("DNS lookup failed",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("resolver", resolverAddress),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
		return []*dnsfern.LookupDetails{}, errors
	}

	log.Debug("DNS lookup successful",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("ip_count", len(ips)))

	lookUps := []*dnsfern.LookupDetails{}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Debug("Skipping invalid IP", svc1log.SafeParam("ip", ipStr))
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
