package subdomain

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	// Utils
	"github.com/Method-Security/osintscan/utils"
	// External
	"github.com/miekg/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetDomainSubdomainsActive performs active (bruteforce) subdomain discovery for a given domain.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsActive(ctx context.Context, subdomains []string, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	activeConfig := config.GetActive()
	errors := []string{}

	subdomains, err := getSubdomainsActive(ctx, activeConfig.Domain, subdomains, activeConfig.Threads, activeConfig.MaxDepth, activeConfig.Timeout, activeConfig.Sleep, activeConfig.WildcardChecks, activeConfig.DnsResolvers)
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
func getSubdomainsActive(ctx context.Context, domain string, subdomainList []string, parallelThreads int, recursiveDepth int, timeout int, sleep int, wildcardChecks int, dnsServerAddresses []string) ([]string, error) {
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
	resolvers := utils.GetResolvers(dnsServerAddresses, log)

	rawResolvers := normalizeRawResolvers(dnsServerAddresses)
	wildcardProfileCache := map[string]wildcardDNSProfile{}
	var recursiveWildcardErr error
	recursiveWildcardFailures := 0

	// First iteration - test base domain for wildcards (A/AAAA and CNAME)
	log.Info("Detecting wildcards", svc1log.SafeParam("domain", domain))
	wildcardProfile, err := detectWildcardDNSProfileCached(ctx, domain, wildcardChecks, rawResolvers, wildcardProfileCache)
	if err != nil {
		return []string{}, err
	}
	if wildcardProfile.HasAddresses() || wildcardProfile.HasCNAMETargets() {
		log.Info("Wildcard DNS detected, skipping brute force", svc1log.SafeParam("wildcard", "*."+domain))
		return subdomains, nil
	}
	log.Info("Generating base permutations", svc1log.SafeParam("domain", domain))
	basePermutations := generatePermutations([]string{domain}, subdomainList)
	validBaseSubdomains := testPermutations(ctx, basePermutations, resolvers, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains, 1, recursiveDepth, sleep, rawResolvers)

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
			depthWildcardProfile, err := detectWildcardDNSProfileCached(ctx, subdomain, wildcardChecks, rawResolvers, wildcardProfileCache)
			if err != nil {
				recursiveWildcardFailures++
				if recursiveWildcardErr == nil {
					recursiveWildcardErr = err
				}
				log.Warn("Skipping recursive subdomain after wildcard detection failure",
					svc1log.SafeParam("subdomain", subdomain),
					svc1log.SafeParam("depth", depth),
					svc1log.SafeParam("error", err.Error()))
				continue
			}
			if depthWildcardProfile.HasAddresses() || depthWildcardProfile.HasCNAMETargets() {
				log.Info("Wildcard DNS detected for subdomain, skipping",
					svc1log.SafeParam("subdomain", subdomain),
					svc1log.SafeParam("wildcard", "*."+subdomain))
				continue
			}
			validSubdomains = append(validSubdomains, subdomain)
		}

		newPermutations := generatePermutations(validSubdomains, subdomainList)
		currentDepthSubdomains = testPermutations(ctx, newPermutations, resolvers, semaphore, &wg, subdomainsMutex, subdomainsSet, &subdomains, depth, recursiveDepth, sleep, rawResolvers)
	}

	sort.Strings(subdomains)
	if recursiveWildcardFailures > 0 {
		return subdomains, fmt.Errorf("skipped %d recursive subdomain branches after inconclusive wildcard detection; results may be incomplete: %w", recursiveWildcardFailures, recursiveWildcardErr)
	}
	return subdomains, nil
}

func detectWildcardDNSProfileCached(ctx context.Context, domain string, wildcardChecks int, rawResolvers []string, wildcardProfileCache map[string]wildcardDNSProfile) (wildcardDNSProfile, error) {
	log := svc1log.FromContext(ctx)
	if profile, ok := wildcardProfileCache[domain]; ok {
		log.Info("Using cached wildcard DNS profile",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("has_addresses", profile.HasAddresses()),
			svc1log.SafeParam("has_cname_targets", profile.HasCNAMETargets()))
		return profile, nil
	}

	profile, err := detectWildcardDNSProfileWithResolvers(ctx, domain, wildcardChecks, rawResolvers)
	if err != nil {
		return profile, err
	}
	if profile.HasAddresses() || profile.HasCNAMETargets() {
		wildcardProfileCache[domain] = profile
		log.Info("Cached wildcard DNS profile",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("has_addresses", profile.HasAddresses()),
			svc1log.SafeParam("has_cname_targets", profile.HasCNAMETargets()))
	}
	return profile, nil
}

// testPermutations concurrently tests a list of subdomain permutations for DNS resolution.
// Uses a semaphore to limit concurrency and mutexes to protect shared state.
func testPermutations(ctx context.Context, permutations []string, resolvers []*net.Resolver, semaphore chan struct{}, wg *sync.WaitGroup, subdomainsMutex *sync.Mutex, subdomainsSet map[string]struct{}, subdomains *[]string, depth int, maxDepth int, sleep int, rawResolvers []string) []string {
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

			// Round robin CNAME server selection (may differ in length from resolvers
			// when system defaults are used)
			rawResolverIdx := currentIndex % int64(len(rawResolvers))
			rawResolver := rawResolvers[rawResolverIdx]

			// Capture the duration of the lookup
			start := time.Now()
			_, err := resolver.LookupHost(ctx, testSubdomain)
			// If LookupHost fails (no A/AAAA record), check for CNAME records
			// via a raw DNS query. Go's net.LookupCNAME follows the CNAME chain
			// and fails if the target doesn't resolve, so it can't detect dangling
			// CNAMEs. Dangling CNAMEs are valid discoveries and can indicate
			// subdomain takeover vulnerabilities.
			// Only attempt CNAME detection on a definitive NXDOMAIN — SERVFAIL,
			// timeouts, and other transient errors must not trigger the CNAME path.
			if err != nil && isDNSNotFound(err) {
				cnameTargets := lookupCNAMEs(testSubdomain, rawResolver)
				if len(cnameTargets) > 0 {
					err = nil
				}
			}
			duration := time.Since(start)

			// Apply sleep delay if configured (in milliseconds)
			if sleep > 0 {
				time.Sleep(time.Duration(sleep) * time.Millisecond)
			}

			completed := atomic.AddInt64(&completedCount, 1)

			if duration.Milliseconds() < 1000 {
				shouldLogProgress := completed%500 == 0 || int(completed) == totalPermutations
				if shouldLogProgress {
					log.Info("Subdomain check",
						svc1log.SafeParam("duration_ms", duration.Milliseconds()),
						svc1log.SafeParam("depth", depth),
						svc1log.SafeParam("completed", completed),
						svc1log.SafeParam("total", totalPermutations))
				}
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
				_, exists := subdomainsSet[testSubdomain]
				if !exists {
					subdomainsSet[testSubdomain] = struct{}{}
					*subdomains = append(*subdomains, testSubdomain)
				}
				subdomainsMutex.Unlock()

				if !exists {
					validSubdomainsMutex.Lock()
					validSubdomains = append(validSubdomains, testSubdomain)
					validSubdomainsMutex.Unlock()
				}
			}
		}(testSubdomain)
	}

	wg.Wait()
	return validSubdomains
}

func lookupCNAMEs(subdomain string, server string) []string {
	if server == "" {
		return nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)
	msg.RecursionDesired = true

	resp, err := exchangeDNSWithFallback(msg, server)
	if err != nil || resp == nil {
		return nil
	}

	targets := []string{}
	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			targets = append(targets, normalizeDNSName(cname.Target))
		}
	}
	return targets
}

func exchangeDNSWithFallback(msg *dns.Msg, server string) (*dns.Msg, error) {
	return exchangeDNSWithFallbackContext(context.Background(), msg, server)
}

func exchangeDNSWithFallbackContext(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := udpClient.ExchangeContext(ctx, msg, server)
	if err == nil && resp != nil && !resp.Truncated {
		return resp, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	tcpClient := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
	tcpResp, _, tcpErr := tcpClient.ExchangeContext(ctx, msg, server)
	if tcpErr == nil {
		return tcpResp, nil
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func normalizeRawResolvers(dnsServerAddresses []string) []string {
	if len(dnsServerAddresses) > 0 {
		rawResolvers := make([]string, len(dnsServerAddresses))
		for i, addr := range dnsServerAddresses {
			rawResolvers[i] = utils.NormalizeDNSAddress(addr)
		}
		return rawResolvers
	}

	clientConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return []string{""}
	}
	rawResolvers := make([]string, 0, len(clientConfig.Servers))
	for _, server := range clientConfig.Servers {
		rawResolvers = append(rawResolvers, net.JoinHostPort(server, clientConfig.Port))
	}
	if len(rawResolvers) == 0 {
		return []string{""}
	}
	return rawResolvers
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
