package utils

import (
	"bytes"
	"context"
	"io"
	"sort"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// GetSubdomainsPassiveWithSubfinder runs subfinder in passive mode for a single domain and returns discovered subdomains.
func GetSubdomainsPassiveWithSubfinder(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Configuring subfinder for passive discovery",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("threads", cfg.Threads),
		svc1log.SafeParam("rate_limit", cfg.RequestsPerSecond),
		svc1log.SafeParam("all_sources", cfg.AllSources),
	)

	// Set subfinder config
	subfinderOpts := &runner.Options{
		All:                cfg.AllSources,
		Threads:            cfg.Threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
		RateLimit:          cfg.RequestsPerSecond,
	}

	// Initialize subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Warn("Failed to initialize subfinder runner",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	log.Debug("Starting subfinder enumeration", svc1log.SafeParam("domain", cfg.Domain))

	output := &bytes.Buffer{}
	// Run subdomain enumeration for the given domain
	results, err := subfinder.EnumerateSingleDomainWithCtx(ctx, cfg.Domain, []io.Writer{output})
	if err != nil {
		log.Warn("Subfinder enumeration failed",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Collect subdomains from results map keys
	subdomains := make([]string, 0, len(results))
	for sub := range results {
		subdomains = append(subdomains, sub)
	}

	// Sort subdomains for deterministic output
	sort.Strings(subdomains)

	log.Debug("Subfinder enumeration completed",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)))

	return subdomains, nil
}


