package intelligent

import (
	// Standard
	"context"
	"sync"
	"time"

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func GetSubDomainsIntelligent(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	intelligentConfig := config.GetIntelligent()
	errors := []string{}

	// Handle DNS resolver safely
	dnsResolver := "8.8.8.8:53" // Default value
	if intelligentConfig.DnsResolver != nil {
		dnsResolver = *intelligentConfig.DnsResolver
	}

	// Run the intelligent domain discovery
	domains, err := getDomainsIntelligent(ctx, intelligentConfig.Domains, intelligentConfig.Threads, intelligentConfig.Timeout, dnsResolver)
	if err != nil {
		errors = append(errors, err.Error())
	}

	result := dnsfern.DiscoverDnsSubdomainResult{
		Subdomains: domains,
	}

	report := dnsfern.DiscoverDnsSubdomainReport{
		Config: &config,
		Result: &result,
		Errors: errors,
	}

	return report, nil
}

func getDomainsIntelligent(ctx context.Context, domains []string, threads int, timeout int, dnsResolver string) ([]string, error) {
	// Create a context with timeout (if timeout > 0)
	var timeoutCtx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		timeoutCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
		defer cancel()
	} else {
		// No timeout, use original context
		timeoutCtx = ctx
	}

	log := svc1log.FromContext(timeoutCtx)
	log.Info("Starting intelligent domain analysis",
		svc1log.SafeParam("domains", domains),
		svc1log.SafeParam("threads", threads))

	// Run intelligent analysis
	discoveredDomains, err := RunIntelligentAnalysisForDomains(timeoutCtx, domains, dnsResolver, threads)
	if err != nil {
		return nil, err
	}

	return discoveredDomains, nil
}

// RunIntelligentAnalysisForDomains runs comprehensive intelligent analysis on all domains
// with improved parallelization: processes domains in parallel and runs analysis types concurrently
func RunIntelligentAnalysisForDomains(ctx context.Context, domains []string, dnsServerAddress string, maxThreads int) ([]string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting comprehensive intelligent analysis with enhanced parallelization",
		svc1log.SafeParam("input_domains_count", len(domains)),
		svc1log.SafeParam("max_threads", maxThreads),
		svc1log.SafeParam("tests", "wordlist_substitution, high_entropy, numeric_sequence, advanced_patterns"))

	if maxThreads <= 0 {
		maxThreads = 25
	}

	// Calculate workers: domains can run in parallel, each using some threads for DNS testing
	domainWorkers := min(len(domains), max(1, maxThreads/4))
	dnsWorkers := max(10, maxThreads-domainWorkers)

	log.Info("Thread allocation",
		svc1log.SafeParam("domain_workers", domainWorkers),
		svc1log.SafeParam("dns_workers_per_domain", dnsWorkers))

	// Channel to collect all results
	allResults := make(chan []string, len(domains)*4) // 4 analysis types per domain
	var wg sync.WaitGroup

	// Process domains in parallel
	domainChan := make(chan string, len(domains))

	// Start domain workers
	for i := 0; i < domainWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				processDomainConcurrently(ctx, domain, domains, dnsServerAddress, dnsWorkers, allResults)
			}
		}()
	}

	// Send domains to workers
	go func() {
		defer close(domainChan)
		for _, domain := range domains {
			select {
			case domainChan <- domain:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close results channel when all work is done
	go func() {
		wg.Wait()
		close(allResults)
	}()

	// Collect all discovered domains
	var allDiscoveredDomains []string
	inputSet := make(map[string]bool)
	for _, domain := range domains {
		inputSet[domain] = true
	}

	for results := range allResults {
		for _, domain := range results {
			if !inputSet[domain] {
				allDiscoveredDomains = append(allDiscoveredDomains, domain)
			}
		}
	}

	// Remove duplicates
	uniqueDomains := removeDuplicates(allDiscoveredDomains)

	log.Info("Comprehensive intelligent analysis completed",
		svc1log.SafeParam("total_discovered", len(uniqueDomains)))

	return uniqueDomains, nil
}

// processDomainConcurrently runs all analysis types for a domain concurrently
func processDomainConcurrently(ctx context.Context, domain string, allDomains []string, dnsServerAddress string, dnsWorkers int, allResults chan<- []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Processing domain with concurrent analysis", svc1log.SafeParam("domain", domain))

	// Run all 4 analysis types concurrently
	var analysisWg sync.WaitGroup

	// Wordlist substitution
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		if results, err := TestWordlistSubstitution(ctx, domain, dnsServerAddress, allDomains, dnsWorkers); err == nil {
			select {
			case allResults <- results:
			case <-ctx.Done():
			}
		}
	}()

	// High entropy analysis
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		if results, err := TestHighEntropyDomains(ctx, domain, dnsServerAddress, allDomains); err == nil {
			select {
			case allResults <- results:
			case <-ctx.Done():
			}
		}
	}()

	// Numeric sequence analysis
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		if results, err := TestNumericSequenceDomains(ctx, domain, dnsServerAddress, allDomains); err == nil {
			select {
			case allResults <- results:
			case <-ctx.Done():
			}
		}
	}()

	// Advanced pattern analysis
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		if results, err := TestAdvancedPatternAnalysis(ctx, domain, dnsServerAddress, allDomains); err == nil {
			select {
			case allResults <- results:
			case <-ctx.Done():
			}
		}
	}()

	analysisWg.Wait()
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(domains []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, domain := range domains {
		if !keys[domain] {
			keys[domain] = true
			result = append(result, domain)
		}
	}

	return result
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
