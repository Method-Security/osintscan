package subdomain

import (
	"context"
	"slices"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	subutils "github.com/Method-Security/osintscan/internal/discover/dns/subdomain/passive/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// shouldRunModule checks if a specific module should run based on the selected modules list.
func shouldRunModule(selectedModules []dnsfern.DiscoverDnsSubdomainModule, module dnsfern.DiscoverDnsSubdomainModule) bool {
	return slices.Contains(selectedModules, module) || slices.Contains(selectedModules, dnsfern.DiscoverDnsSubdomainModuleAll)
}

// GetDomainSubdomainsPassive queries passive sources (subfinder and/or amass v4) for subdomains of a given domain.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting passive subdomain discovery",
		svc1log.SafeParam("domain", config.Passive.Domain))

	// Determine module selection from config (defaults to "subfinder" if not provided)
	selectedModules := config.Passive.Modules
	runSubfinder := shouldRunModule(selectedModules, dnsfern.DiscoverDnsSubdomainModuleSubfinder)
	runAmass := shouldRunModule(selectedModules, dnsfern.DiscoverDnsSubdomainModuleAmass)

	allSubdomains := []string{}
	if runSubfinder {
		subfinderSubdomains, err := subutils.GetSubdomainsPassiveWithSubfinder(ctx, *config.Passive)
		if err != nil {
			errors = append(errors, err.Error())
		}
		allSubdomains = append(allSubdomains, subfinderSubdomains...)
	}

	if runAmass {
		amassSubdomains, amassErr := subutils.GetSubdomainsPassiveWithAmass(ctx, *config.Passive)
		if amassErr != nil {
			log.Warn("Passive subdomain discovery (amass v4) encountered errors",
				svc1log.SafeParam("domain", config.Passive.Domain),
				svc1log.SafeParam("error", amassErr.Error()))
			errors = append(errors, amassErr.Error())
		}
		allSubdomains = append(allSubdomains, amassSubdomains...)
	}

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
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}
