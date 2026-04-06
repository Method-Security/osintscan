package subdomain

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	subutils "github.com/Method-Security/osintscan/internal/discover/dns/subdomain/passive/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// domainResult holds the output of a single domain discovery goroutine.
type domainResult struct {
	domain     string
	subdomains []string
	errors     []string
}

// shouldRunModule checks if a specific module should run based on the selected modules list.
func shouldRunModule(selectedModules []dnsfern.DiscoverDnsSubdomainModule, module dnsfern.DiscoverDnsSubdomainModule) bool {
	return slices.Contains(selectedModules, module) || slices.Contains(selectedModules, dnsfern.DiscoverDnsSubdomainModuleAll)
}

// discoverForDomain runs passive discovery (subfinder and/or amass) for a single domain
// and returns the discovered subdomains and any error strings.
func discoverForDomain(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig, runSubfinder, runAmass bool) ([]string, []string) {
	log := svc1log.FromContext(ctx)
	var subdomains []string
	var errors []string

	if runSubfinder {
		subs, err := subutils.GetSubdomainsPassiveWithSubfinder(ctx, cfg)
		if err != nil {
			errors = append(errors, err.Error())
		}
		subdomains = append(subdomains, subs...)
	}

	if runAmass {
		subs, err := subutils.GetSubdomainsPassiveWithAmass(ctx, cfg)
		if err != nil {
			log.Warn("Passive subdomain discovery (amass v4) encountered errors",
				svc1log.SafeParam("domain", cfg.Domain),
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, err.Error())
		}
		subdomains = append(subdomains, subs...)
	}

	return subdomains, errors
}

// discoverDomainsParallel runs passive discovery across multiple domains concurrently,
// limited to the given number of worker goroutines. Results are collected and returned.
func discoverDomainsParallel(ctx context.Context, domains []string, baseCfg dnsfern.DiscoverDnsSubdomainPassiveConfig, runSubfinder, runAmass bool, workers int) []domainResult {
	results := make([]domainResult, len(domains))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check for context cancellation before starting work
			if ctx.Err() != nil {
				results[idx] = domainResult{
					domain: d,
					errors: []string{ctx.Err().Error()},
				}
				return
			}

			cfg := baseCfg
			cfg.Domain = d

			subs, errs := discoverForDomain(ctx, cfg, runSubfinder, runAmass)
			results[idx] = domainResult{
				domain:     d,
				subdomains: subs,
				errors:     errs,
			}
		}(i, domain)
	}

	wg.Wait()
	return results
}

// extractUniqueDomains returns all unique domain values from the subdomain list
// that have not already been scanned.
func extractUniqueDomains(subdomains []string, scanned map[string]bool) []string {
	unique := map[string]bool{}
	for _, sub := range subdomains {
		sub = strings.TrimSuffix(strings.TrimSpace(sub), ".")
		if sub == "" {
			continue
		}
		if !scanned[sub] && !unique[sub] {
			unique[sub] = true
		}
	}
	result := make([]string, 0, len(unique))
	for d := range unique {
		result = append(result, d)
	}
	sort.Strings(result)
	return result
}

// GetDomainSubdomainsPassive queries passive sources (subfinder and/or amass v4) for subdomains of a given domain.
// When recursiveDepth > 0, discovered subdomains are fed back into the discovery process
// for additional rounds, avoiding rescanning domains that have already been processed.
// Recursive rounds are parallelized using the configured thread count.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting passive subdomain discovery",
		svc1log.SafeParam("domain", config.Passive.Domain),
		svc1log.SafeParam("recursive_depth", config.Passive.RecursiveDepth))

	selectedModules := config.Passive.Modules
	runSubfinder := shouldRunModule(selectedModules, dnsfern.DiscoverDnsSubdomainModuleSubfinder)
	runAmass := shouldRunModule(selectedModules, dnsfern.DiscoverDnsSubdomainModuleAmass)

	// Track all discovered subdomains and which domains we've already scanned
	allSubdomainsSet := map[string]bool{}
	scannedDomains := map[string]bool{}

	// Initial scan of the primary domain
	initialCfg := *config.Passive
	subs, errs := discoverForDomain(ctx, initialCfg, runSubfinder, runAmass)
	errors = append(errors, errs...)
	scannedDomains[config.Passive.Domain] = true

	for _, s := range subs {
		allSubdomainsSet[s] = true
	}

	// Recursive rounds (parallelized)
	recursiveDepth := config.Passive.RecursiveDepth
	workers := config.Passive.Threads

	for depth := 1; depth <= recursiveDepth; depth++ {
		// Get domains we haven't scanned yet from all discovered subdomains
		allSubs := make([]string, 0, len(allSubdomainsSet))
		for s := range allSubdomainsSet {
			allSubs = append(allSubs, s)
		}
		newDomains := extractUniqueDomains(allSubs, scannedDomains)

		if len(newDomains) == 0 {
			log.Info("No new domains to scan, stopping recursion early",
				svc1log.SafeParam("depth", depth))
			break
		}

		log.Info("Starting recursive discovery pass",
			svc1log.SafeParam("depth", depth),
			svc1log.SafeParam("max_depth", recursiveDepth),
			svc1log.SafeParam("domains_to_scan", len(newDomains)),
			svc1log.SafeParam("workers", workers))

		// Mark all domains as scanned before launching workers to prevent
		// duplicate work if the same domain appears in multiple rounds.
		for _, domain := range newDomains {
			scannedDomains[domain] = true
		}

		// Run discovery for all new domains concurrently
		results := discoverDomainsParallel(ctx, newDomains, *config.Passive, runSubfinder, runAmass, workers)

		// Collect results
		for _, r := range results {
			errors = append(errors, r.errors...)

			newFound := 0
			for _, s := range r.subdomains {
				if !allSubdomainsSet[s] {
					allSubdomainsSet[s] = true
					newFound++
				}
			}

			log.Debug("Recursive discovery for domain completed",
				svc1log.SafeParam("domain", r.domain),
				svc1log.SafeParam("depth", depth),
				svc1log.SafeParam("new_subdomains", newFound))
		}
	}

	// Convert set to sorted slice
	allSubdomains := make([]string, 0, len(allSubdomainsSet))
	for s := range allSubdomainsSet {
		allSubdomains = append(allSubdomains, s)
	}
	sort.Strings(allSubdomains)

	result := dnsfern.DiscoverDnsSubdomainResult{
		Subdomains: allSubdomains,
	}

	report := dnsfern.DiscoverDnsSubdomainReport{
		Config: &config,
		Result: &result,
		Errors: errors,
	}

	log.Info("Completed passive subdomain discovery",
		svc1log.SafeParam("domain", config.Passive.Domain),
		svc1log.SafeParam("subdomains_found", len(allSubdomains)),
		svc1log.SafeParam("domains_scanned", len(scannedDomains)),
		svc1log.SafeParam("recursive_depth", recursiveDepth),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}
