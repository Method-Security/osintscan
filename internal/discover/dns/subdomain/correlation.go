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

	// Derive new subdomains through correlation
	newlyDiscoveredSubDomains, err := DeriveNewSubDomains(ctx, correlationConfig.Domains, correlationConfig.Threads, correlationConfig.Timeout, correlationConfig.DnsResolvers)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Run the FQDN correlation checks
	validatedDomains, err := validateFQDNsWithCorrelation(ctx, correlationConfig.Domains, correlationConfig.Threads, correlationConfig.Timeout, correlationConfig.DnsResolvers)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Combine original validated domains with newly discovered ones
	allDomains := append(validatedDomains, newlyDiscoveredSubDomains...)

	result := dnsfern.DiscoverDnsSubdomainResult{
		Subdomains: allDomains,
	}

	report := dnsfern.DiscoverDnsSubdomainReport{
		Config: &config,
		Result: &result,
		Errors: errors,
	}

	return report, nil
}

// DeriveNewSubDomains extracts subdomain prefixes from the input domains and tries them
// against all base domains to discover new valid subdomains. This process is recursive:
// newly discovered domains are added back into the set and their prefixes are extracted
// and tried against all domains, continuing until no new subdomains are found.
func DeriveNewSubDomains(ctx context.Context, domains []string, threads int, timeout int, dnsResolvers []string) ([]string, error) {
	log := svc1log.FromContext(ctx)

	if len(domains) == 0 {
		return []string{}, nil
	}

	// Setup DNS resolvers
	resolvers := []*net.Resolver{}
	if len(dnsResolvers) == 0 {
		resolvers = append(resolvers, &net.Resolver{})
	} else {
		for _, dnsServerAddress := range dnsResolvers {
			resolvers = append(resolvers, utils.GetResolver(dnsServerAddress, log))
		}
	}

	log.Info("Starting recursive subdomain correlation discovery",
		svc1log.SafeParam("threads", threads),
		svc1log.SafeParam("initial_domains", len(domains)))

	// Track all known domains (original + discovered)
	knownDomains := make(map[string]bool)
	for _, domain := range domains {
		knownDomains[strings.ToLower(domain)] = true
	}

	// Track newly discovered domains
	allDiscoveredDomains := []string{}

	// Recursive correlation discovery
	iteration := 0
	for {
		iteration++
		log.Info("Starting correlation iteration", svc1log.SafeParam("iteration", iteration))

		// Extract subdomain prefixes and base domains from all known domains
		subdomainPrefixes := make(map[string]bool)
		baseDomains := make(map[string]bool)

		for domain := range knownDomains {
			parts := strings.Split(domain, ".")
			if len(parts) < 2 {
				continue
			}

			// Each known domain is a base domain
			baseDomains[domain] = true

			// Extract subdomain prefixes (all parts except the TLD - the last part)
			for i := 0; i < len(parts)-1; i++ {
				subdomainPrefixes[parts[i]] = true
			}
		}

		log.Info("Extracted correlation data",
			svc1log.SafeParam("iteration", iteration),
			svc1log.SafeParam("subdomain_prefixes", len(subdomainPrefixes)),
			svc1log.SafeParam("base_domains", len(baseDomains)))

		// Generate candidate subdomains
		candidates := make(map[string]bool)
		for baseDomain := range baseDomains {
			for prefix := range subdomainPrefixes {
				candidate := fmt.Sprintf("%s.%s", prefix, baseDomain)
				// Only test candidates we haven't seen before
				if !knownDomains[candidate] {
					candidates[candidate] = true
				}
			}
		}

		if len(candidates) == 0 {
			log.Info("No new candidates to test, correlation discovery complete",
				svc1log.SafeParam("iteration", iteration))
			break
		}

		log.Info("Generated candidate subdomains",
			svc1log.SafeParam("iteration", iteration),
			svc1log.SafeParam("candidates", len(candidates)))

		// Validate candidates concurrently
		newlyDiscoveredThisRound := []string{}
		newlyDiscoveredMutex := &sync.Mutex{}
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, threads)

		var resolverIndex int64
		var completedCount int64
		totalCandidates := len(candidates)

		candidateList := make([]string, 0, len(candidates))
		for candidate := range candidates {
			candidateList = append(candidateList, candidate)
		}

		log.Info("Starting subdomain correlation discovery",
			svc1log.SafeParam("iteration", iteration),
			svc1log.SafeParam("total_candidates", totalCandidates))

		for _, candidate := range candidateList {
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

				log.Debug("Checking potentially new subdomain", svc1log.SafeParam("domain", fqdn))

				isValid, err := validateSingleFQDNCorrelation(ctx, fqdn, resolver, timeout, log)
				if err != nil {
					log.Debug("Candidate domain not valid",
						svc1log.SafeParam("fqdn", fqdn),
						svc1log.SafeParam("error", err.Error()))
				}

				completed := atomic.AddInt64(&completedCount, 1)

				if completed%100 == 0 || completed == int64(totalCandidates) {
					log.Info("Subdomain correlation progress",
						svc1log.SafeParam("iteration", iteration),
						svc1log.SafeParam("completed", completed),
						svc1log.SafeParam("total", totalCandidates))
				}

				if isValid {
					log.Debug("Discovered new subdomain through correlation",
						svc1log.SafeParam("iteration", iteration),
						svc1log.SafeParam("fqdn", fqdn))
					newlyDiscoveredMutex.Lock()
					newlyDiscoveredThisRound = append(newlyDiscoveredThisRound, fqdn)
					newlyDiscoveredMutex.Unlock()
				}
			}(candidate)
		}

		wg.Wait()

		// Add newly discovered domains to our known set
		if len(newlyDiscoveredThisRound) == 0 {
			log.Info("No new subdomains discovered in this iteration, correlation discovery complete",
				svc1log.SafeParam("iteration", iteration))
			break
		}

		for _, domain := range newlyDiscoveredThisRound {
			knownDomains[domain] = true
			allDiscoveredDomains = append(allDiscoveredDomains, domain)
		}

		log.Info("Iteration completed",
			svc1log.SafeParam("iteration", iteration),
			svc1log.SafeParam("newly_discovered_this_round", len(newlyDiscoveredThisRound)),
			svc1log.SafeParam("total_discovered", len(allDiscoveredDomains)))
	}

	log.Info("Subdomain correlation discovery completed",
		svc1log.SafeParam("total_iterations", iteration),
		svc1log.SafeParam("total_newly_discovered", len(allDiscoveredDomains)))

	return allDiscoveredDomains, nil
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

			isValid, err := validateSingleFQDNCorrelation(ctx, fqdn, resolver, timeout, log)
			if err != nil {
				log.Debug("Error validating FQDN",
					svc1log.SafeParam("fqdn", fqdn),
					svc1log.SafeParam("error", err.Error()))
			}

			completed := atomic.AddInt64(&completedCount, 1)

			log.Info("FQDN correlation check",
				svc1log.SafeParam("fqdn", fqdn),
				svc1log.SafeParam("valid", isValid),
				svc1log.SafeParam("completed", completed),
				svc1log.SafeParam("total", totalDomains))

			// Only include valid, non-wildcard domains in results
			if isValid {
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
// Returns:
// - isValid: true if the FQDN is valid
// - hasWildcard: true if the FQDN has wildcard DNS
// - err: error if the FQDN is invalid
func validateSingleFQDNCorrelation(ctx context.Context, fqdn string, resolver *net.Resolver, timeout int, log svc1log.Logger) (bool, error) {
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
		return false, fmt.Errorf("DNS resolution failed: %v", err)
	}

	// Check for wildcard DNS - test the full FQDN directly
	wildcardDomain, err := detectWildcardDNS(lookupCtx, fqdn, resolver)
	if err != nil {
		log.Warn("Failed to detect wildcard DNS",
			svc1log.SafeParam("fqdn", fqdn),
			svc1log.SafeParam("error", err.Error()))
		return false, fmt.Errorf("wildcard detection failed: %v", err)
	} else if wildcardDomain != nil {
		log.Info("Wildcard DNS detected",
			svc1log.SafeParam("fqdn", fqdn),
			svc1log.SafeParam("wildcard_domain", *wildcardDomain))
		return false, nil
	}

	return true, nil
}
