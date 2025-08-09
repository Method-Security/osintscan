package subdomain

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
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
	subdomains, err := getSubdomainsActive(ctx, activeConfig.Domain, activeConfig.Subdomains, activeConfig.Threads, activeConfig.MaxDepth, activeConfig.Timeout, activeConfig.DnsResolvers)
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

// detectWildcardDNS tests a random high-entropy subdomain to check if a wildcard DNS record is present.
// Returns the wildcard domain if detected, otherwise nil.
func detectWildcardDNS(ctx context.Context, domain string, resolver *net.Resolver) (*string, error) {
	// Generate a high-entropy 16-character random subdomain
	randomSubdomain, err := generateRandomSubdomain(domain)
	if err != nil {
		return nil, err
	}

	// Check if the random subdomain resolves
	_, err = resolver.LookupHost(ctx, randomSubdomain)

	// If no error, it resolved, meaning wildcard is present
	if err == nil {
		wildcardDomain := "*." + domain
		return &wildcardDomain, nil
	}

	// If the error is NXDOMAIN or SERVFAIL, wildcard is NOT present
	return nil, nil
}

// getSubdomainsActive performs recursive bruteforce subdomain enumeration with concurrency and wildcard detection.
func getSubdomainsActive(ctx context.Context, domain string, subdomainList []string, parallelThreads int, recursiveDepth int, timeout int, dnsServerAddresses []string) ([]string, error) {
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
	resolvers := func() []*net.Resolver {
		if len(dnsServerAddresses) == 0 {
			return []*net.Resolver{utils.GetResolver("", log)}
		}

		result := make([]*net.Resolver, 0, len(dnsServerAddresses))
		for _, dnsServerAddress := range dnsServerAddresses {
			result = append(result, utils.GetResolver(dnsServerAddress, log))
		}
		return result
	}()

	// First iteration - test all base subdomains for wildcards
	log.Info("Detecting wildcards", svc1log.SafeParam("domain", domain))
	wildcardDNS, err := detectWildcardDNS(ctx, domain, resolvers[0])
	if err != nil {
		return []string{}, err
	}
	if wildcardDNS != nil {
		domain = *wildcardDNS
		subdomains = append(subdomains, domain)
		return subdomains, nil
	}

	log.Info("Generating base permutations", svc1log.SafeParam("domain", domain))
	basePermutations := generatePermutations([]string{domain}, subdomainList)
	validBaseSubdomains := testPermutations(ctx, basePermutations, resolvers, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains, 1, recursiveDepth)

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
				domain = *wildcardDNS
				subdomains = append(subdomains, domain)
				continue
			}
			validSubdomains = append(validSubdomains, subdomain)
		}

		newPermutations := generatePermutations(validSubdomains, subdomainList)
		currentDepthSubdomains = testPermutations(ctx, newPermutations, resolvers, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains, depth, recursiveDepth)
	}

	return subdomains, nil
}

// testPermutations concurrently tests a list of subdomain permutations for DNS resolution.
// Uses a semaphore to limit concurrency and mutexes to protect shared state.
func testPermutations(ctx context.Context, permutations []string, resolvers []*net.Resolver, semaphore chan struct{}, wg *sync.WaitGroup, subdomainsMutex *sync.Mutex, subdomainsSet map[string]struct{}, subdomains *[]string, depth int, maxDepth int) []string {
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

// generateRandomSubdomain generates a high-entropy subdomain with only letters (16 characters).
func generateRandomSubdomain(domain string) (string, error) {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomString := make([]byte, 16)
	for i := range randomString {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			return "", err
		}
		randomString[i] = letterBytes[n.Int64()]
	}

	return fmt.Sprintf("%s.%s", string(randomString), domain), nil
}

// GetDiscoverDNSSubdomainActiveWordlistPath returns the file path for a given wordlist size
func GetDiscoverDNSSubdomainActiveWordlistPath(wordlistSize string) string {
	wordlistPaths := map[string]string{
		"TINY":   "/opt/method/osintscan/var/conf/discover/dns/subdomain/wordlist-500.txt",
		"SMALL":  "/opt/method/osintscan/var/conf/discover/dns/subdomain/wordlist-5000.txt",
		"MEDIUM": "/opt/method/osintscan/var/conf/discover/dns/subdomain/wordlist-20000.txt",
		"LARGE":  "/opt/method/osintscan/var/conf/discover/dns/subdomain/wordlist-110000.txt",
	}

	return wordlistPaths[wordlistSize]
}
