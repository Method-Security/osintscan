package dns

import (
	"bytes"
	"context"
	"io"
	"strings"

	osintscan "github.com/Method-Security/osintscan/generated/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// GetDomainSubdomainsPassive queries subfinder for all subdomains for a given domain. It returns a SubdomainsEnumReport struct containing
// all subdomains and any errors that occurred.
func GetDomainSubdomainsPassive(ctx context.Context, domain string) (osintscan.DnsSubenumReport, error) {
	report := osintscan.DnsSubenumReport{
		Domain:          domain,
		EnumerationType: osintscan.DnsSubenumTypePassive,
	}
	errors := []string{}

	// Get all valid subdomains
	subdomains, err := getSubdomainsPassive(ctx, domain)
	if err != nil {
		errors = append(errors, err.Error())
	}

	report.Subdomains = subdomains
	report.Errors = errors
	return report, nil

}

// SubdomainsEnumReport represents the report of all subdomains for a given domain including all non-fatal errors that occurred.

func getSubdomainsPassive(ctx context.Context, domain string) ([]string, error) {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return []string{}, err
	}

	output := &bytes.Buffer{}
	// To run subdomain enumeration on a single domain
	if err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{output}); err != nil {
		return []string{}, err
	}

	// Convert buffer to string and split by new line
	subdomains := strings.Split(output.String(), "\n")

	// Trim the last empty string if the output ends with a newline
	if len(subdomains) > 0 && subdomains[len(subdomains)-1] == "" {
		subdomains = subdomains[:len(subdomains)-1]
	}
	return subdomains, err
}
