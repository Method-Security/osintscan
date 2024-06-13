package dns

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type SubdomainsEnumReport struct {
	Domain     string   `json:"domain" yaml:"domain"`
	Subdomains []string `json:"subdomains" yaml:"subdomains"`
	Errors     []string `json:"errors" yaml:"errors"`
}

func getSubdomains(ctx context.Context, domain string) ([]string, error) {
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

func GetDomainSubdomains(ctx context.Context, domain string) (SubdomainsEnumReport, error) {
	errors := []string{}

	// 1. Get all valid subdomains
	subdomains, err := getSubdomains(ctx, domain)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 2. Create report and write to file
	report := SubdomainsEnumReport{
		Domain:     domain,
		Subdomains: subdomains,
		Errors:     errors,
	}
	return report, nil

}
