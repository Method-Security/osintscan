package dns

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

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

// GetDomainSubdomainsBrute queries subfinder for all subdomains for a given domain. It returns a SubdomainsEnumReport struct containing
// all subdomains and any errors that occurred.
func GetDomainSubdomainsBrute(ctx context.Context, domain string, subdomainList []string, parallelThreads int, recursiveDepth int, timeout int) (osintscan.DnsSubenumReport, error) {
	report := osintscan.DnsSubenumReport{
		Domain:          domain,
		EnumerationType: osintscan.DnsSubenumTypeBrute,
	}
	errors := []string{}

	subdomains := getSubdomainsBrute(ctx, domain, subdomainList, parallelThreads, recursiveDepth, timeout)

	report.Subdomains = subdomains
	report.Errors = errors
	return report, nil

}

func getSubdomainsBrute(ctx context.Context, domain string, subdomainList []string, parallelThreads int, recursiveDepth int, timeout int) []string {
	subdomains := []string{}
	subdomainsSet := make(map[string]struct{}) // To track unique valid subdomains
	subdomainsMutex := &sync.Mutex{}
	semaphore := make(chan struct{}, parallelThreads)
	var wg sync.WaitGroup

	var cancel context.CancelFunc
	if timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
		defer cancel()
	}

	resolver := net.Resolver{}

	// Pre-generate all permutations before starting goroutines
	allPermutations := make([]string, 0)
	for depth := 1; depth <= recursiveDepth; depth++ {
		allPermutations = append(allPermutations, generatePermutations(domain, subdomainList, depth)...)
	}

	// Process all permutations in parallel
	for _, testSubdomain := range allPermutations {
		wg.Add(1)

		go func(testSubdomain string) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}

			_, err := resolver.LookupHost(ctx, testSubdomain)
			if err == nil {
				subdomainsMutex.Lock()
				if _, exists := subdomainsSet[testSubdomain]; !exists {
					subdomainsSet[testSubdomain] = struct{}{}
					subdomains = append(subdomains, testSubdomain)
				}
				subdomainsMutex.Unlock()
			}
		}(testSubdomain)
	}

	wg.Wait()

	return subdomains
}

func generatePermutations(domain string, subdomainList []string, depth int) []string {
	if depth == 1 {
		// Pre-allocate results slice for better performance
		results := make([]string, 0, len(subdomainList))
		for _, subdomain := range subdomainList {
			results = append(results, subdomain+"."+domain)
		}
		return results
	}

	basePermutations := generatePermutations(domain, subdomainList, depth-1)
	// Pre-allocate results slice
	results := make([]string, 0, len(basePermutations)*len(subdomainList))

	for _, base := range basePermutations {
		for _, subdomain := range subdomainList {
			results = append(results, subdomain+"."+base)
		}
	}

	return results
}
