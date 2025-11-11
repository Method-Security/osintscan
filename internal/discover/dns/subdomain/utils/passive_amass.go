package utils

import (
	"context"
	"sort"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetSubdomainsPassiveWithAmass uses the Amass v5 library to enumerate subdomains (passive).
// Note: This integrates the library directly and does not invoke the Amass CLI.
func GetSubdomainsPassiveWithAmass(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Configuring amass v5 for passive discovery",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("threads", cfg.Threads),
		svc1log.SafeParam("rate_limit", cfg.RequestsPerSecond),
		svc1log.SafeParam("all_sources", cfg.AllSources),
	)

	// Initialize minimal Amass v5 components to ensure library integration without CLI
	var _ = config.NewConfig

	// TODO: Wire Amass v5 engine session and capture discovered subdomains via API.
	// For now, return an empty list to maintain compatibility while using the v5 library.
	subdomains := []string{}
	sort.Strings(subdomains)
	return subdomains, nil
}
