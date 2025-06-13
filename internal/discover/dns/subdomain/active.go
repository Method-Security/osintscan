package subdomain

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetDomainSubdomainsActive performs active (bruteforce) subdomain discovery for a given domain.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsActive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	activeConfig := config.GetActive()
	errors := []string{}

	// Run the active subdomain discovery
	subdomains, err := getSubdomainsActive(ctx, activeConfig.Domain, activeConfig.Subdomains, *activeConfig.Threads, *activeConfig.MaxDepth, *activeConfig.Timeout, *activeConfig.DnsResolver)
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
func getSubdomainsActive(ctx context.Context, domain string, subdomainList []string, parallelThreads int, recursiveDepth int, timeout int, dnsServerAddress string) ([]string, error) {
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

	resolver := utils.GetResolver(dnsServerAddress, log)

	// First iteration - test all base subdomains for wildcards
	wildcardDNS, err := detectWildcardDNS(ctx, domain, resolver)
	if err != nil {
		return []string{}, err
	}
	if wildcardDNS != nil {
		domain = *wildcardDNS
		subdomains = append(subdomains, domain)
		return subdomains, nil
	}

	basePermutations := generatePermutations([]string{domain}, subdomainList)
	validBaseSubdomains := testPermutations(ctx, basePermutations, resolver, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains)

	// For each subsequent depth, only build on valid subdomains from previous iteration
	currentDepthSubdomains := validBaseSubdomains
	for depth := 2; depth <= recursiveDepth; depth++ {
		if len(currentDepthSubdomains) == 0 {
			break // No valid subdomains to build on
		}

		validSubdomains := []string{}
		for _, subdomain := range currentDepthSubdomains {
			wildcardDNS, err := detectWildcardDNS(ctx, subdomain, resolver)
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
		currentDepthSubdomains = testPermutations(ctx, newPermutations, resolver, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains)
	}

	return subdomains, nil
}

// testPermutations concurrently tests a list of subdomain permutations for DNS resolution.
// Uses a semaphore to limit concurrency and mutexes to protect shared state.
func testPermutations(ctx context.Context, permutations []string, resolver *net.Resolver, semaphore chan struct{}, wg *sync.WaitGroup, subdomainsMutex *sync.Mutex, subdomainsSet map[string]struct{}, subdomains *[]string) []string {
	var validSubdomains []string
	validSubdomainsMutex := &sync.Mutex{}

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

			_, err := resolver.LookupHost(ctx, testSubdomain)
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
