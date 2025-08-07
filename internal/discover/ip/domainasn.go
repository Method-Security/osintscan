package ip

import (
	"context"
	"fmt"
	"net"
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
	allIPs := []string{}

	// Add individual IPs
	if config.Ips != nil {
		for _, ip := range config.Ips {
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ip)
			}
			allIPs = append(allIPs, ip)
		}
	}

	// Add CIDR range IPs
	if config.Cidr != nil && *config.Cidr != "" {
		cidrIPs, err := expandCIDR(*config.Cidr)
		if err != nil {
			return nil, fmt.Errorf("error expanding CIDR %s: %w", *config.Cidr, err)
		}
		allIPs = append(allIPs, cidrIPs...)
	}

	return allIPs, nil
}

// expandCIDR expands a CIDR range into individual IP addresses
func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
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
		Ip: ip,
	}

	// Perform reverse DNS lookup
	if domain := performReverseDNSLookup(ctx, ip, resolver); domain != "" {
		lookup.Domain = &domain
	}

	// Perform ASN lookup using whois
	if asn := performASNLookup(ctx, ip); asn != "" {
		lookup.Asn = &asn
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

// performASNLookup performs ASN lookup using Cymru DNS service
func performASNLookup(ctx context.Context, ip string) string {
	// Use Cymru DNS service with fallback to whois
	asn, err := utils.IPASNLookupWithFallback(ctx, ip)
	if err != nil {
		return ""
	}
	return asn
}
