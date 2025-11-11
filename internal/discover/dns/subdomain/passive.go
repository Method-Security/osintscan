package subdomain

import (
	"context"
	"sort"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	subutils "github.com/Method-Security/osintscan/internal/discover/dns/subdomain/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetDomainSubdomainsPassive queries passive sources (subfinder and/or amass v5) for subdomains of a given domain.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting passive subdomain discovery",
		svc1log.SafeParam("domain", config.Passive.Domain))

	// Determine module selection from config (defaults to "subfinder" if not provided)
	selectedModule := "subfinder"
	if config.Passive != nil {
		if extra := config.Passive.GetExtraProperties(); extra != nil {
			if v, ok := extra["module"]; ok {
				if s, ok := v.(string); ok && s != "" {
					selectedModule = strings.ToLower(s)
				}
			}
		}
	}

	// Run requested modules and merge results
	all := map[string]struct{}{}

	runSubfinder := selectedModule == "subfinder" || selectedModule == "all" || selectedModule == ""
	runAmass := selectedModule == "amass" || selectedModule == "all"

	if runSubfinder {
		subfinderSubs, subfinderErr := subutils.GetSubdomainsPassiveWithSubfinder(ctx, *config.Passive)
		if subfinderErr != nil {
			log.Warn("Passive subdomain discovery (subfinder) encountered errors",
				svc1log.SafeParam("domain", config.Passive.Domain),
				svc1log.SafeParam("error", subfinderErr.Error()))
			errors = append(errors, subfinderErr.Error())
		}
		for _, s := range subfinderSubs {
			all[s] = struct{}{}
		}
	}

	if runAmass {
		amassSubs, amassErr := subutils.GetSubdomainsPassiveWithAmass(ctx, *config.Passive)
		if amassErr != nil {
			log.Warn("Passive subdomain discovery (amass v5) encountered errors",
				svc1log.SafeParam("domain", config.Passive.Domain),
				svc1log.SafeParam("error", amassErr.Error()))
			errors = append(errors, amassErr.Error())
		}
		for _, s := range amassSubs {
			all[s] = struct{}{}
		}
	}

	subdomains := make([]string, 0, len(all))
	for s := range all {
		subdomains = append(subdomains, s)
	}
	sort.Strings(subdomains)

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
