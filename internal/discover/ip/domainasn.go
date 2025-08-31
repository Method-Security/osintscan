package ip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	ipfern "github.com/Method-Security/osintscan/generated/go/discover/ip"
	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetDomainASNLookup performs reverse DNS and ASN lookups for IP addresses or CIDR ranges
func GetDomainASNLookup(ctx context.Context, config *ipfern.DiscoverIpDomainAsnConfig) *ipfern.DiscoverIpDomainAsnReport {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	// Collect all IPs to process
	allIPs, err := explodeIPsFromConfig(config)
	if err != nil {
		errors = append(errors, err.Error())
		return &ipfern.DiscoverIpDomainAsnReport{
			Config: config,
			Result: &ipfern.DiscoverIpDomainAsnResult{},
			Errors: errors,
		}
	}

	log.Info("Starting IP domain/ASN lookup", svc1log.SafeParam("total_ips", len(allIPs)))

	// Perform concurrent lookups
	lookups, lookupErrors := performConcurrentLookups(ctx, allIPs, config.DnsResolvers)
	if len(lookupErrors) > 0 {
		errors = append(errors, lookupErrors...)
	}

	result := &ipfern.DiscoverIpDomainAsnResult{
		Lookups: lookups,
	}

	return &ipfern.DiscoverIpDomainAsnReport{
		Config: config,
		Result: result,
		Errors: errors,
	}
}

// explodeIPsFromConfig extracts and expands all IPs from the configuration
func explodeIPsFromConfig(config *ipfern.DiscoverIpDomainAsnConfig) ([]string, error) {
	return utils.ExplodeIPsFromAddressesAndCIDR(config.IpAddresses, config.Cidr)
}

// performConcurrentLookups performs reverse DNS and ASN lookups concurrently
func performConcurrentLookups(ctx context.Context, ips []string, dnsResolvers []string) ([]*ipfern.LookupDetails, []string) {
	log := svc1log.FromContext(ctx)
	const maxWorkers = 50 // Limit concurrency to avoid overwhelming resolvers

	lookups := make([]*ipfern.LookupDetails, 0, len(ips))
	errors := []string{}
	lookupsMutex := &sync.Mutex{}

	semaphore := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	var completedCount int64
	var resolverIndex int64

	// Create resolvers
	resolvers := make([]*net.Resolver, len(dnsResolvers))
	for i, dnsResolver := range dnsResolvers {
		resolvers[i] = utils.GetResolver(dnsResolver, log)
	}

	for _, ip := range ips {
		wg.Add(1)

		go func(ip string) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}

			// Use round robin for resolver selection
			currentIndex := atomic.AddInt64(&resolverIndex, 1) - 1
			resolverIdx := currentIndex % int64(len(resolvers))
			resolver := resolvers[resolverIdx]

			// Perform lookups
			lookup := performSingleLookup(ctx, ip, resolver)
			completed := atomic.AddInt64(&completedCount, 1)

			if completed%100 == 0 || completed == int64(len(ips)) {
				log.Info("Lookup progress",
					svc1log.SafeParam("completed", completed),
					svc1log.SafeParam("total", len(ips)))
			}

			lookupsMutex.Lock()
			lookups = append(lookups, lookup)
			lookupsMutex.Unlock()
		}(ip)
	}

	wg.Wait()
	return lookups, errors
}

// performSingleLookup performs reverse DNS and ASN lookup for a single IP
func performSingleLookup(ctx context.Context, ip string, resolver *net.Resolver) *ipfern.LookupDetails {
	lookup := &ipfern.LookupDetails{
		IpAddress: ip,
	}

	// Perform reverse DNS lookup
	if domain := performReverseDNSLookup(ctx, ip, resolver); domain != "" {
		lookup.Domain = &domain
	}

	// Perform ASN lookup using Cymru DNS service and WHOIS
	if asns, err := performASNLookup(ctx, ip); err == nil && len(asns) > 0 {
		lookup.Asns = asns
	}

	return lookup
}

// performReverseDNSLookup performs reverse DNS lookup for an IP
func performReverseDNSLookup(ctx context.Context, ip string, resolver *net.Resolver) string {
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Return the first hostname found
	return names[0]
}

// performASNLookup performs comprehensive ASN lookup using multiple sources (Cymru and WHOIS) with deduplication
func performASNLookup(ctx context.Context, ip string) ([]string, error) {
	log := svc1log.FromContext(ctx)
	allASNs := make(map[string]bool) // Use map to deduplicate ASNs

	// Try Cymru DNS first (primary source)
	cymruASNs, err := utils.IPASNLookupMultiple(ctx, ip)
	if err == nil && len(cymruASNs) > 0 {
		for _, asn := range cymruASNs {
			if asn != "" {
				allASNs[asn] = true
			}
		}
		log.Debug("Cymru ASN lookup successful", svc1log.SafeParam("ip", ip), svc1log.SafeParam("asns", cymruASNs))
	} else {
		log.Debug("Cymru ASN lookup failed", svc1log.SafeParam("ip", ip), svc1log.SafeParam("error", err))
	}

	// Try WHOIS lookup as additional source
	whoisASNs, err := utils.WhoisASNWithContext(ctx, ip)
	if err == nil && len(whoisASNs) > 0 {
		// WhoisASNWithContext returns []string now, so we need to handle it properly
		for _, asn := range whoisASNs {
			if asn != "" {
				// Ensure AS prefix for consistency
				if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
					asn = "AS" + asn
				}
				allASNs[asn] = true
			}
		}
		log.Debug("WHOIS ASN lookup successful", svc1log.SafeParam("ip", ip), svc1log.SafeParam("asns", whoisASNs))
	} else {
		log.Debug("WHOIS ASN lookup failed", svc1log.SafeParam("ip", ip), svc1log.SafeParam("error", err))
	}

	// Convert deduplicated map to slice
	result := make([]string, 0, len(allASNs))
	for asn := range allASNs {
		result = append(result, asn)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no ASNs found for IP %s from any source", ip)
	}

	if len(result) > 1 {
		log.Info("Multi-source ASN lookup completed",
			svc1log.SafeParam("ip", ip),
			svc1log.SafeParam("total_asns", len(result)),
			svc1log.SafeParam("asns", result))
	}

	return result, nil
}
