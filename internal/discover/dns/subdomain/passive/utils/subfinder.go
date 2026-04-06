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

// SubfinderRunner wraps a pre-initialized subfinder runner for reuse across
// multiple domain enumerations, avoiding repeated initialization overhead.
type SubfinderRunner struct {
	runner *runner.Runner
}

// NewSubfinderRunner creates a reusable SubfinderRunner from the given config.
// The returned runner can enumerate many domains without re-loading provider
// config or re-initializing passive sources each time.
func NewSubfinderRunner(cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) (*SubfinderRunner, error) {
	opts := &runner.Options{
		All:                cfg.AllSources,
		Threads:            cfg.Threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
		RateLimit:          cfg.RequestsPerSecond,
	}
	r, err := runner.NewRunner(opts)
	if err != nil {
		return nil, err
	}
	return &SubfinderRunner{runner: r}, nil
}

// EnumerateDomain runs passive subdomain enumeration for a single domain
// using the pre-initialized runner.
func (s *SubfinderRunner) EnumerateDomain(ctx context.Context, domain string) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Starting subfinder enumeration", svc1log.SafeParam("domain", domain))

	output := &bytes.Buffer{}
	results, err := s.runner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output})
	if err != nil {
		log.Warn("Subfinder enumeration failed",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	subdomains := make([]string, 0, len(results))
	for sub := range results {
		subdomains = append(subdomains, sub)
	}
	sort.Strings(subdomains)

	log.Debug("Subfinder enumeration completed",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)))

	return subdomains, nil
}

// GetSubdomainsPassiveWithSubfinder runs subfinder in passive mode for a single domain.
// For batch operations, prefer NewSubfinderRunner + EnumerateDomain to avoid repeated initialization.
func GetSubdomainsPassiveWithSubfinder(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Configuring subfinder for passive discovery",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("threads", cfg.Threads),
		svc1log.SafeParam("rate_limit", cfg.RequestsPerSecond),
		svc1log.SafeParam("all_sources", cfg.AllSources),
	)

	sr, err := NewSubfinderRunner(cfg)
	if err != nil {
		log.Warn("Failed to initialize subfinder runner",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	return sr.EnumerateDomain(ctx, cfg.Domain)
}
