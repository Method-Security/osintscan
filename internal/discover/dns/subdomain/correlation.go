package subdomain

import (
	// Standard
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	// Utils
	"github.com/Method-Security/osintscan/utils"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetDomainSubdomainsCorrelation performs FQDN validation and wildcard detection for a list of domains.
// Returns a report containing validation results and any errors encountered.
func GetDomainSubdomainsCorrelation(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	correlationConfig := config.GetCorrelation()
	errors := []string{}

	// Run the FQDN correlation checks
	validatedDomains, err := validateFQDNsWithCorrelation(ctx, correlationConfig.Domains, correlationConfig.Threads, correlationConfig.Timeout, correlationConfig.DnsResolvers)
	if err != nil {
		errors = append(errors, err.Error())
	}

	result := dnsfern.DiscoverDnsSubdomainResult{
		Subdomains: validatedDomains,
	}

	report := dnsfern.DiscoverDnsSubdomainReport{
		Config: &config,
		Result: &result,
		Errors: errors,
	}

	return report, nil
}

// validateFQDNsWithCorrelation performs validation and wildcard detection for a list of FQDNs
func validateFQDNsWithCorrelation(ctx context.Context, fqdns []string, threads int, timeout int, dnsResolvers []string) ([]string, error) {
	log := svc1log.FromContext(ctx)

	// Setup DNS resolvers
	resolvers := []*net.Resolver{}
	if len(dnsResolvers) == 0 {
		// Use default resolver
		resolvers = append(resolvers, &net.Resolver{})
	} else {
		for _, dnsServerAddress := range dnsResolvers {
			resolvers = append(resolvers, utils.GetResolver(dnsServerAddress, log))
		}
	}

	// Process FQDNs concurrently
	validDomains := []string{}
	validDomainsMutex := &sync.Mutex{}
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	var resolverIndex int64 // For round robin resolver selection
	var completedCount int64
	totalDomains := len(fqdns)

	log.Info("Starting FQDN correlation analysis", svc1log.SafeParam("total_fqdns", totalDomains))

	for _, fqdn := range fqdns {
		wg.Add(1)
		go func(fqdn string) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}

			// Round robin resolver selection
			currentIndex := atomic.AddInt64(&resolverIndex, 1) - 1
			resolverIdx := currentIndex % int64(len(resolvers))
			resolver := resolvers[resolverIdx]

			isValid, hasWildcard, err := validateSingleFQDNCorrelation(ctx, fqdn, resolver, timeout, log)
			if err != nil {
				log.Error("Error validating FQDN",
					svc1log.SafeParam("fqdn", fqdn),
					svc1log.SafeParam("error", err.Error()))
			}

			completed := atomic.AddInt64(&completedCount, 1)

			log.Info("FQDN correlation check",
				svc1log.SafeParam("fqdn", fqdn),
				svc1log.SafeParam("valid", isValid),
				svc1log.SafeParam("wildcard", hasWildcard),
				svc1log.SafeParam("completed", completed),
				svc1log.SafeParam("total", totalDomains))

			// Only include valid, non-wildcard domains in results
			if isValid && !hasWildcard {
				validDomainsMutex.Lock()
				validDomains = append(validDomains, fqdn)
				validDomainsMutex.Unlock()
			}
		}(fqdn)
	}

	wg.Wait()

	log.Info("FQDN correlation analysis completed",
		svc1log.SafeParam("total_processed", totalDomains),
		svc1log.SafeParam("valid_domains", len(validDomains)))

	return validDomains, nil
}

// validateSingleFQDNCorrelation validates a single FQDN and checks if it has wildcard DNS
func validateSingleFQDNCorrelation(ctx context.Context, fqdn string, resolver *net.Resolver, timeout int, log svc1log.Logger) (bool, bool, error) {
	// Create timeout context for DNS lookup if specified
	lookupCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		lookupCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	// Try to resolve the FQDN
	_, err := resolver.LookupHost(lookupCtx, fqdn)
	if err != nil {
		return false, false, fmt.Errorf("DNS resolution failed: %v", err)
	}

	// Check for wildcard DNS - test the full FQDN directly
	wildcardDomain, err := detectWildcardForFullDomain(lookupCtx, fqdn, resolver)
	if err != nil {
		log.Warn("Failed to detect wildcard DNS",
			svc1log.SafeParam("fqdn", fqdn),
			svc1log.SafeParam("error", err.Error()))
	} else if wildcardDomain != nil {
		return true, true, nil
	}

	return true, false, nil
}

// detectWildcardForFullDomain tests if the given FQDN has wildcard DNS behavior
// This tests the parent domain of the given FQDN to see if it has wildcard records
func detectWildcardForFullDomain(ctx context.Context, fqdn string, resolver *net.Resolver) (*string, error) {
	// Extract the parent domain to test for wildcards
	// e.g., for "api.example.com", test if "example.com" has wildcard behavior
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid FQDN format for wildcard detection")
	}

	// Get parent domain (remove first subdomain)
	if len(parts) == 2 {
		// This is already a root domain, test it directly
		return detectWildcardDNS(ctx, fqdn, resolver)
	}

	// Get parent domain by removing the first part
	parentDomain := strings.Join(parts[1:], ".")
	return detectWildcardDNS(ctx, parentDomain, resolver)
}
