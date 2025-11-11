package subdomain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	stdlog "log"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/enum"
	"github.com/owasp-amass/amass/v4/systems"
	amasscfg "github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	oamdomain "github.com/owasp-amass/open-asset-model/domain"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// ContextKey is the type for context keys used in the subdomain passive workflow.
type ContextKey string

// ContextKeyAllSources enables using all passive sources in subfinder when set to true in the context.
const ContextKeyAllSources ContextKey = "osintscan:discover:dns:subdomain:passive:all-sources"

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

// SubdomainsEnumReport represents the report of all subdomains for a given domain including all non-fatal errors that occurred.

// getSubdomainsPassive runs subfinder in passive mode for a single domain and returns the discovered subdomains.
func getSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Configuring subfinder for passive discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("threads", config.Threads),
		svc1log.SafeParam("rate_limit", config.RequestsPerSecond))

	// Set subfinder config
	useAllSources, _ := ctx.Value(ContextKeyAllSources).(bool)
	subfinderOpts := &runner.Options{
		All:                useAllSources,
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
	seen := make(map[string]struct{}, len(results))
	subdomains := make([]string, 0, len(results))
	for sub := range results {
		name := strings.TrimSuffix(strings.ToLower(sub), ".")
		if name == "" {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			subdomains = append(subdomains, name)
		}
	}

	// If all-sources is enabled, augment with Amass using the specified sources list
	if useAllSources {
		amassSubs, amassErr := getAmassSubdomains(ctx, config.Domain)
		if amassErr != nil {
			log.Warn("Amass enumeration failed",
				svc1log.SafeParam("domain", config.Domain),
				svc1log.SafeParam("error", amassErr.Error()))
		} else {
			for _, s := range amassSubs {
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					subdomains = append(subdomains, s)
				}
			}
		}
	}

	log.Debug("Subfinder enumeration completed",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)))

	return subdomains, err
}

// getAmassSubdomains runs Amass v4 library in passive mode restricted to a fixed set of sources and returns discovered subdomains.
func getAmassSubdomains(ctx context.Context, domain string) ([]string, error) {
	log := svc1log.FromContext(ctx)
	// The exact sources required when --all-sources is specified. This is a diff
	// so that it only focuses on the scans that subfinder is not able to do.
	requiredSources := []string{
		"360passivedns", "asnlookup", "ahrefs", "bigdatacloud", "binaryedge", "circl",
		"certcentral", "detectify", "gitlab", "ipdata", "ipinfo", "passivetotal",
		"pentesttools", "publicwww", "urlscan", "yandex", "zetalytics", "zoomeye",
	}

	cfg := amasscfg.NewConfig()
	cfg.AddDomain(domain)
	cfg.Passive = true
	cfg.Verbose = true
	// Restrict to only the specified sources
	cfg.SourceFilter.Include = true
	cfg.SourceFilter.Sources = requiredSources
	// Wire Amass logs to our service logger
	r, w := io.Pipe()
	cfg.Log = stdlog.New(w, "", stdlog.Lmicroseconds)
	defer func() { _ = w.Close() }()
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			log.Info("amass", svc1log.SafeParam("message", line))
		}
	}()

	// Create a local Amass system and add all sources so the filter can select the required ones
	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sys.Shutdown() }()
	if err := sys.SetDataSources(datasrcs.GetAllSources(sys)); err != nil {
		return nil, err
	}

	// Setup enumeration
	g := sys.GraphDatabases()[0]
	e := enum.NewEnumeration(cfg, sys, g)
	if e == nil {
		return nil, nil
	}

	// Run enumeration
	results := make([]string, 0, 128)
	seen := make(map[string]struct{}, 256)

	// Execute the enumeration synchronously; respect context cancellation
	if err := e.Start(ctx); err != nil {
		// Even if it errors, attempt to collect what we can
	}

	// After enumeration, read discovered names from the graph within scope
	var fqdns []oam.Asset
	fqdns = append(fqdns, oamdomain.FQDN{Name: domain})
	assets, err := g.DB.FindByScope(fqdns, cfg.CollectionStartTime.UTC())
	if err != nil {
		return results, nil
	}
	for _, a := range assets {
		if fqdn, ok := a.Asset.(oamdomain.FQDN); ok {
			name := strings.TrimSuffix(strings.ToLower(fqdn.Name), ".")
			if name == "" {
				continue
			}
			if name == domain || strings.HasSuffix(name, "."+domain) {
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					// Output Amass-found domain to stdout
					fmt.Println(name)
					results = append(results, name)
				}
			}
		}
	}
	return results, nil
}
