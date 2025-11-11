package subdomain

import (
	"bytes"
	"context"
	"io"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// GetDomainSubdomainsPassive queries subfinder for all subdomains for a given domain using passive sources.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting passive subdomain discovery",
		svc1log.SafeParam("domain", config.Passive.Domain))

	// Get all valid subdomains using passive enumeration
	subdomains, err := getSubdomainsPassive(ctx, *config.Passive)
	if err != nil {
		log.Warn("Passive subdomain discovery encountered errors",
			svc1log.SafeParam("domain", config.Passive.Domain),
			svc1log.SafeParam("error", err.Error()))
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

	log.Info("Completed passive subdomain discovery",
		svc1log.SafeParam("domain", config.Passive.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}

// getSubdomainsPassive runs subfinder in passive mode for a single domain and returns the discovered subdomains.
func getSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Configuring subfinder for passive discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("threads", config.Threads),
		svc1log.SafeParam("rate_limit", config.RequestsPerSecond),
		svc1log.SafeParam("all_sources", config.AllSources),
	)

	// Set subfinder config
	subfinderOpts := &runner.Options{
		All:                config.AllSources,
		Threads:            config.Threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
		RateLimit:          config.RequestsPerSecond,
	}

	// Initialize subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Warn("Failed to initialize subfinder runner",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	log.Debug("Starting subfinder enumeration", svc1log.SafeParam("domain", config.Domain))

	output := &bytes.Buffer{}
	// Run subdomain enumeration for the given domain
	results, err := subfinder.EnumerateSingleDomainWithCtx(ctx, config.Domain, []io.Writer{output})
	if err != nil {
		log.Warn("Subfinder enumeration failed",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Collect subdomains from results map keys
	subdomains := make([]string, 0, len(results))
	for sub := range results {
		subdomains = append(subdomains, sub)
	}

	log.Debug("Subfinder enumeration completed",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)))

	return subdomains, err
}
