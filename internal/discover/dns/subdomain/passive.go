package subdomain

import (
	"bytes"
	"context"
	"io"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// GetDomainSubdomainsPassive queries subfinder for all subdomains for a given domain using passive sources.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsPassive(ctx context.Context, config dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	errors := []string{}

	// Get all valid subdomains using passive enumeration
	subdomains, err := getSubdomainsPassive(ctx, config.GetPassive().Domain)
	if err != nil {
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

	return report, nil
}

// SubdomainsEnumReport represents the report of all subdomains for a given domain including all non-fatal errors that occurred.

// getSubdomainsPassive runs subfinder in passive mode for a single domain and returns the discovered subdomains.
func getSubdomainsPassive(ctx context.Context, domain string) ([]string, error) {
	subfinderOpts := &runner.Options{
		Threads:            10, // Number of threads for enumeration
		Timeout:            30, // Timeout in seconds for sources
		MaxEnumerationTime: 10, // Max time in minutes for enumeration
	}

	// Initialize subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return []string{}, err
	}

	output := &bytes.Buffer{}
	// Run subdomain enumeration for the given domain
	if err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output}); err != nil {
		return []string{}, err
	}

	// Convert output buffer to string and split by new line
	subdomains := strings.Split(output.String(), "\n")

	// Remove trailing empty string if present
	if len(subdomains) > 0 && subdomains[len(subdomains)-1] == "" {
		subdomains = subdomains[:len(subdomains)-1]
	}
	return subdomains, err
}
