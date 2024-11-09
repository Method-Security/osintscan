package dns

import (
	"context"
	"sync"
)

func bruteEnumSubdomains(ctx context.Context, domain string, words []string, threads int) ([]string, []string, error) {
	subdomains := []string{}
	errors := []string{}

	var mu sync.Mutex     // To safely append to shared slices
	var wg sync.WaitGroup // To wait for all goroutines to finish

	sem := make(chan struct{}, threads) // Semaphore channel to limit concurrency

	for _, word := range words {
		wg.Add(1)
		sem <- struct{}{} // Acquire a slot

		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }() // Release the slot

			report, err := GetDomainDNSRecords(ctx, word+"."+domain)
			if err != nil {
				mu.Lock()
				errors = append(errors, err.Error())
				mu.Unlock()
				return
			}

			subdomain := getSubdomainFromRecords(report.DNSRecords)
			if subdomain != "" {
				mu.Lock()
				subdomains = append(subdomains, subdomain)
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()
	return subdomains, errors, nil
}

func BruteEnumDomainSubdomains(ctx context.Context, domain string, words []string, threads int, maxRecursiveDepth int) (SubdomainsEnumReport, error) {
	domains := []string{domain} // Convert the initial domain into a slice to support recursion
	allSubdomains := []string{}
	allErrors := []string{}
	var currentRecursiveDepth = 0
	for currentRecursiveDepth < maxRecursiveDepth {
		for _, domain := range domains {
			subdomains, errors, err := bruteEnumSubdomains(ctx, domain, words, threads)
			if err != nil {
				errors = append(errors, err.Error())
			}
			allSubdomains = append(allSubdomains, subdomains...)
			allErrors = append(allErrors, errors...)
			domains = subdomains // The next recursion cycle will check the wordlist against the domains that we found in this cycle
		}
		currentRecursiveDepth += 1
	}

	report := SubdomainsEnumReport{
		Domain:     domain,
		Subdomains: allSubdomains,
		Errors:     allErrors,
	}

	return report, nil
}

func getSubdomainFromRecords(records Records) string {
	if len(records.A) > 0 {
		return records.A[0].Name
	}
	if len(records.AAAA) > 0 {
		return records.AAAA[0].Name
	}
	if len(records.MX) > 0 {
		return records.MX[0].Name
	}
	if len(records.TXT) > 0 {
		return records.TXT[0].Name
	}
	if len(records.NS) > 0 {
		return records.NS[0].Name
	}
	if len(records.CNAME) > 0 {
		return records.CNAME[0].Name
	}
	return ""
}
