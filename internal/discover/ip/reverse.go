package ip

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	ipfern "github.com/Method-Security/osintscan/generated/go/discover/ip"
	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetReverseLookup performs reverse DNS lookups for a list of IP addresses
func GetReverseLookup(ctx context.Context, config *ipfern.DiscoverIpReverseConfig) *ipfern.DiscoverDnsReverseReport {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	// Validate IPs
	if err := validateIPAddresses(config.Ips); err != nil {
		errors = append(errors, err.Error())
		return &ipfern.DiscoverDnsReverseReport{
			Config: config,
			Result: &ipfern.DiscoverIpReverseResult{},
			Errors: errors,
		}
	}

	// Determine thread count: 0 means use number of CPUs
	threads := config.Threads
	if threads == 0 {
		threads = runtime.NumCPU()
	}

	log.Info("Starting reverse DNS lookup",
		svc1log.SafeParam("total_ips", len(config.Ips)),
		svc1log.SafeParam("threads", threads))

	dnsResolvers := config.DnsResolvers

	// Perform concurrent reverse lookups
	lookups, lookupErrors := performConcurrentReverseLookups(ctx, config.Ips, dnsResolvers, threads)
	if len(lookupErrors) > 0 {
		errors = append(errors, lookupErrors...)
	}

	result := &ipfern.DiscoverIpReverseResult{
		Lookups: lookups,
	}

	log.Info("Completed reverse DNS lookup",
		svc1log.SafeParam("total_lookups", len(lookups)),
		svc1log.SafeParam("errors", len(errors)))

	return &ipfern.DiscoverDnsReverseReport{
		Config: config,
		Result: result,
		Errors: errors,
	}
}

// validateIPAddresses validates that all provided strings are valid IP addresses
func validateIPAddresses(ips []string) error {
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses provided")
	}

	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}
	}

	return nil
}

// performConcurrentReverseLookups performs reverse DNS lookups concurrently using round-robin resolver selection
func performConcurrentReverseLookups(ctx context.Context, ips []string, dnsResolvers []string, threads int) ([]*ipfern.ReverseDetails, []string) {
	log := svc1log.FromContext(ctx)
	maxWorkers := threads // Use configured thread count for concurrency control
	if maxWorkers == 0 {
		maxWorkers = runtime.NumCPU()
	}

	lookups := make([]*ipfern.ReverseDetails, 0, len(ips))
	errors := []string{}
	lookupsMutex := &sync.Mutex{}
	errorsMutex := &sync.Mutex{}

	semaphore := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	var resolverIndex int64

	// Create resolvers for round-robin usage
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

			// Perform reverse lookup
			lookup, err := performSingleReverseLookup(ctx, ip, resolver)
			if err != nil {
				errorsMutex.Lock()
				errors = append(errors, fmt.Sprintf("reverse lookup failed for %s: %s", ip, err.Error()))
				errorsMutex.Unlock()
			}

			if lookup != nil {
				log.Info("Reverse lookup completed", svc1log.SafeParam("ip", ip))
				lookupsMutex.Lock()
				lookups = append(lookups, lookup)
				lookupsMutex.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return lookups, errors
}

// performSingleReverseLookup performs a reverse DNS lookup for a single IP address
func performSingleReverseLookup(ctx context.Context, ip string, resolver *net.Resolver) (*ipfern.ReverseDetails, error) {
	// Perform reverse DNS lookup to get all PTR records
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		// Return the lookup details even if reverse lookup fails, but with empty PTR records
		return &ipfern.ReverseDetails{
			Ip: ip,
		}, fmt.Errorf("reverse DNS lookup failed: %w", err)
	}

	lookup := &ipfern.ReverseDetails{
		Ip: ip,
	}

	// Add all PTR records found (not just the first one like in domainasn.go)
	if len(names) > 0 {
		lookup.ReversePtrs = names
	}

	return lookup, nil
}
