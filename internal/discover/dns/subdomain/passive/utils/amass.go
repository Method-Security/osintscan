package utils

import (
	"context"
	"sort"
	"time"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/enum"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// buildAmassConfig creates and configures an Amass v4 config object with optimized performance settings.
func buildAmassConfig(cfg dnsfern.DiscoverDnsSubdomainPassiveConfig, log svc1log.Logger) *config.Config {
	amassCfg := config.NewConfig()
	amassCfg.Passive = true
	amassCfg.AddDomain(cfg.Domain)
	amassCfg.Recursive = false
	amassCfg.Verbose = false
	amassCfg.AddResolvers(cfg.DnsResolvers...)

	// Configure parallelism and performance
	// Increase concurrent DNS queries for faster resolution
	amassCfg.MaxDNSQueries = cfg.MaxDnsQueries // Default is much lower

	// Increase queries per second per resolver for passive mode
	// Passive mode doesn't do active DNS queries, but this helps with validation
	amassCfg.ResolversQPS = cfg.MaxResolversQps // Queries per second per resolver

	log.Info("Amass performance settings",
		svc1log.SafeParam("max_dns_queries", amassCfg.MaxDNSQueries),
		svc1log.SafeParam("resolvers", len(amassCfg.Resolvers)),
		svc1log.SafeParam("qps_per_resolver", amassCfg.ResolversQPS))

	return amassCfg
}

// GetSubdomainsPassiveWithAmass uses the Amass v4 library to enumerate subdomains (passive) via the in-memory graph.
func GetSubdomainsPassiveWithAmass(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Info("Configuring Amass v4 for passive discovery",
		svc1log.SafeParam("domain", cfg.Domain),
	)

	// Build amass v4 config
	amassCfg := buildAmassConfig(cfg, log)

	// Create a local system for Amass v4
	sys, err := systems.NewLocalSystem(amassCfg)
	if err != nil {
		log.Warn("Failed to create Amass v4 system",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Load all available data sources
	allSources := datasrcs.GetAllSources(sys)
	if err := sys.SetDataSources(allSources); err != nil {
		log.Warn("Failed to set data sources",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Log the number of data sources being used
	dataSources := sys.DataSources()
	log.Info("Amass data sources initialized",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("source_count", len(dataSources)))

	// Get the graph database from the system
	graphs := sys.GraphDatabases()
	if len(graphs) == 0 {
		log.Warn("No graph database available",
			svc1log.SafeParam("domain", cfg.Domain))
		return []string{}, nil
	}
	graph := graphs[0]

	// Create and run enumeration
	e := enum.NewEnumeration(amassCfg, sys, graph)

	// Start a goroutine to report progress every minute
	progressCtx, cancelProgress := context.WithCancel(ctx)
	defer cancelProgress()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		previousDomains := make(map[string]struct{})

		for {
			select {
			case <-progressCtx.Done():
				return
			case <-ticker.C:
				// Query the graph database for current count
				if assets, err := graph.DB.FindByType(oam.FQDN, amassCfg.CollectionStartTime); err == nil {
					currentDomains := make(map[string]struct{})
					for _, asset := range assets {
						if fqdn, ok := asset.Asset.(domain.FQDN); ok {
							currentDomains[fqdn.Name] = struct{}{}
						}
					}

					// Find new domains since last check
					var newDomains []string
					for domainName := range currentDomains {
						if _, exists := previousDomains[domainName]; !exists {
							newDomains = append(newDomains, domainName)
						}
					}

					currentCount := len(currentDomains)
					delta := len(newDomains)
					log.Info("Enumeration progress",
						svc1log.SafeParam("domain", cfg.Domain),
						svc1log.SafeParam("subdomains_found_so_far", currentCount),
						svc1log.SafeParam("new_since_last_check", delta))

					// Print each new domain found
					for _, newDomain := range newDomains {
						log.Debug("Domain Found", svc1log.SafeParam("domain.FQDN", newDomain))
					}

					previousDomains = currentDomains
				}
			}
		}
	}()

	if err := e.Start(ctx); err != nil {
		log.Warn("Amass v4 enumeration failed",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	// Query the graph database for all discovered FQDN assets
	// Use the collection start time to get only newly discovered assets
	found := map[string]struct{}{}
	assets, err := graph.DB.FindByType(oam.FQDN, amassCfg.CollectionStartTime)
	if err != nil {
		log.Warn("Failed to query graph database",
			svc1log.SafeParam("domain", cfg.Domain),
			svc1log.SafeParam("error", err.Error()))
		return []string{}, err
	}

	log.Info("Retrieved assets from graph database",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("asset_count", len(assets)))

	for _, asset := range assets {
		if fqdn, ok := asset.Asset.(domain.FQDN); ok {
			if _, exists := found[fqdn.Name]; !exists {
				found[fqdn.Name] = struct{}{}
			}
		}
	}

	var subdomains []string
	for s := range found {
		subdomains = append(subdomains, s)
	}
	sort.Strings(subdomains)

	log.Info("Amass enumeration completed (v4)",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)))

	return subdomains, nil
}
