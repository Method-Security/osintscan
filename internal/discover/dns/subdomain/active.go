package subdomain

import (
	"context"
	"fmt"
	"net"
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

// GetDomainSubdomainsActive performs active (bruteforce) subdomain discovery for a given domain.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsActive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	activeConfig := config.GetActive()
	errors := []string{}

	// Run the active subdomain discovery
	subdomains, err := getSubdomainsActive(ctx, activeConfig.Domain, activeConfig.Subdomains, activeConfig.Threads, activeConfig.MaxDepth, activeConfig.Timeout, activeConfig.Sleep, activeConfig.DnsResolvers)
	if err != nil {
		errors = append(errors, err.Error())
	}

	result := dnsfern.DiscoverDnsSubdomainResult{
		Subdomains: subdomains,
	}

	report := dnsfern.DiscoverDnsSubdomainReport{
		Config: &config,
		Result: &result,
		Errors: errors,
	}

	return report, nil
}

// getSubdomainsActive performs recursive bruteforce subdomain enumeration with concurrency and wildcard detection.
func getSubdomainsActive(ctx context.Context, domain string, subdomainList []string, parallelThreads int, recursiveDepth int, timeout int, sleep int, dnsServerAddresses []string) ([]string, error) {
	log := svc1log.FromContext(ctx)
	subdomains := []string{}
	subdomainsSet := make(map[string]struct{}) // To track unique valid subdomains
	subdomainsMutex := &sync.Mutex{}
	semaphore := make(chan struct{}, parallelThreads)
	var wg sync.WaitGroup

	var cancel context.CancelFunc
	if timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
		defer cancel()
	}
	resolvers := []*net.Resolver{}
	for _, dnsServerAddress := range dnsServerAddresses {
		resolvers = append(resolvers, utils.GetResolver(dnsServerAddress, log))
	}

	// First iteration - test all base subdomains for wildcards
	log.Info("Detecting wildcards", svc1log.SafeParam("domain", domain))
	wildcardDNS, err := detectWildcardDNS(ctx, domain, resolvers[0])
	if err != nil {
		return []string{}, err
	}
	if wildcardDNS != nil {
		// Wildcard DNS detected - skip brute forcing to avoid false positives
		log.Info("Wildcard DNS detected, skipping brute force", svc1log.SafeParam("wildcard", *wildcardDNS))
		return subdomains, nil
	}

	log.Info("Generating base permutations", svc1log.SafeParam("domain", domain))
	basePermutations := generatePermutations([]string{domain}, subdomainList)
	validBaseSubdomains := testPermutations(ctx, basePermutations, resolvers, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains, 1, recursiveDepth, sleep)

	// For each subsequent depth, only build on valid subdomains from previous iteration
	log.Info("Starting subdomain discovery", svc1log.SafeParam("base_subdomain count", len(validBaseSubdomains)))
	currentDepthSubdomains := validBaseSubdomains
	for depth := 2; depth <= recursiveDepth; depth++ {
		if len(currentDepthSubdomains) == 0 {
			break // No valid subdomains to build on
		}

		depthPercentage := float64(depth-1) / float64(recursiveDepth-1) * 100
		log.Info("Processing subdomain depth",
			svc1log.SafeParam("depth", depth),
			svc1log.SafeParam("max_depth", recursiveDepth),
			svc1log.SafeParam("depth_progress_pct", fmt.Sprintf("%.1f", depthPercentage)),
			svc1log.SafeParam("subdomain_count", len(currentDepthSubdomains)))

		validSubdomains := []string{}
		for _, subdomain := range currentDepthSubdomains {
			wildcardDNS, err := detectWildcardDNS(ctx, subdomain, resolvers[0]) // Use resolvers[0] for wildcard detection
			if err != nil {
				continue
			}
			if wildcardDNS != nil {
				// Wildcard DNS detected for this subdomain - skip to avoid false positives
				log.Info("Wildcard DNS detected for subdomain, skipping",
					svc1log.SafeParam("subdomain", subdomain),
					svc1log.SafeParam("wildcard", *wildcardDNS))
				continue
			}
			validSubdomains = append(validSubdomains, subdomain)
		}

		newPermutations := generatePermutations(validSubdomains, subdomainList)
		currentDepthSubdomains = testPermutations(ctx, newPermutations, resolvers, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains, depth, recursiveDepth, sleep)
	}

	return subdomains, nil
}

// testPermutations concurrently tests a list of subdomain permutations for DNS resolution.
// Uses a semaphore to limit concurrency and mutexes to protect shared state.
func testPermutations(ctx context.Context, permutations []string, resolvers []*net.Resolver, semaphore chan struct{}, wg *sync.WaitGroup, subdomainsMutex *sync.Mutex, subdomainsSet map[string]struct{}, subdomains *[]string, depth int, maxDepth int, sleep int) []string {
	log := svc1log.FromContext(ctx)
	var validSubdomains []string
	validSubdomainsMutex := &sync.Mutex{}

	totalPermutations := len(permutations)
	var completedCount int64
	var resolverIndex int64 // For round robin resolver selection

	for _, testSubdomain := range permutations {
		wg.Add(1)

		go func(testSubdomain string) {
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
			log.Info("Using resolver", svc1log.SafeParam("resolver_index", resolverIdx))

			// Capture the duration of the lookup
			start := time.Now()
			_, err := resolver.LookupHost(ctx, testSubdomain)
			duration := time.Since(start)

			// Apply sleep delay if configured (in milliseconds)
			if sleep > 0 {
				time.Sleep(time.Duration(sleep) * time.Millisecond)
			}

			completed := atomic.AddInt64(&completedCount, 1)

			if duration.Milliseconds() < 1000 {
				log.Info("Subdomain check",
					svc1log.SafeParam("duration_ms", duration.Milliseconds()),
					svc1log.SafeParam("depth", depth),
					svc1log.SafeParam("completed", completed),
					svc1log.SafeParam("total", totalPermutations))
			} else {
				log.Warn("Subdomain check (Longer than 1 second)",
					svc1log.SafeParam("duration_ms", duration.Milliseconds()),
					svc1log.SafeParam("depth", depth),
					svc1log.SafeParam("completed", completed),
					svc1log.SafeParam("total", totalPermutations))
			}

			// If the subdomain is found, add it to the list
			if err == nil {
				subdomainsMutex.Lock()
				if _, exists := subdomainsSet[testSubdomain]; !exists {
					subdomainsSet[testSubdomain] = struct{}{}
					*subdomains = append(*subdomains, testSubdomain)
				}
				subdomainsMutex.Unlock()

				validSubdomainsMutex.Lock()
				validSubdomains = append(validSubdomains, testSubdomain)
				validSubdomainsMutex.Unlock()
			}
		}(testSubdomain)
	}

	wg.Wait()
	return validSubdomains
}

// generatePermutations creates all possible subdomain permutations for the given base subdomains and subdomain list.
func generatePermutations(validSubdomains []string, subdomainList []string) []string {
	results := make([]string, 0, len(validSubdomains)*len(subdomainList))
	for _, subdomain := range subdomainList {
		for _, validSubdomain := range validSubdomains {
			results = append(results, subdomain+"."+validSubdomain)
		}
	}
	return results
}

// GetDiscoverDNSSubdomainActiveWordlistEmbeddedPath returns the embedded config path for a given wordlist size.
// The returned path is relative to the configs/ directory and should be read via configs.ReadLines().
func GetDiscoverDNSSubdomainActiveWordlistEmbeddedPath(wordlistSize string) string {
	wordlistPaths := map[string]string{
		"TINY":   "discover/dns/subdomain/wordlist-500.txt",
		"SMALL":  "discover/dns/subdomain/wordlist-5000.txt",
		"MEDIUM": "discover/dns/subdomain/wordlist-20000.txt",
		"LARGE":  "discover/dns/subdomain/wordlist-110000.txt",
	}

	return wordlistPaths[wordlistSize]
}
