package dns

import (
	"context"
	"github.com/hako/durafmt"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"sync"
	"time"
)

// BruteSubEnumReport represents the report of all subdomains for a given domain along with all DNS records located and
// all non-fatal errors that occurred.
type BruteSubEnumReport struct {
	Domain     string   `json:"domain" yaml:"domain"`
	Subdomains []string `json:"subdomains" yaml:"subdomains"`
	Records    []Record `json:"records" yaml:"records"`
	Errors     []string `json:"errors" yaml:"errors"`
}

func bruteEnumSubdomains(ctx context.Context, domain string, words []string, threads int) ([]string, []Record, []string, error) {
	subdomains := []string{}
	records := []Record{}
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

			report, err := GetDomainDNSRecords(ctx, word+"."+domain, false)
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
				records = append(records, getRecordsFound(report.DNSRecords)...)
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()
	return subdomains, records, errors, nil
}

func BruteEnumDomainSubdomains(ctx context.Context, domain string, words []string, threads int, maxRecursiveDepth int) (BruteSubEnumReport, error) {
	domains := []string{domain} // Convert the initial domain into a slice to support recursion
	allSubdomains := []string{}
	allRecords := []Record{}
	allErrors := []string{}
	var currentRecursiveDepth = 0
	now := time.Now()
	for currentRecursiveDepth < maxRecursiveDepth {
		for _, domain := range domains {
			subdomains, records, errors, err := bruteEnumSubdomains(ctx, domain, words, threads)
			if err != nil {
				errors = append(errors, err.Error())
			}
			allSubdomains = append(allSubdomains, subdomains...)
			allRecords = append(allRecords, records...)
			allErrors = append(allErrors, errors...)
			domains = subdomains // The next recursion cycle will check the wordlist against the domains that we found in this cycle
		}
		currentRecursiveDepth += 1
	}
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(2).String()
	logger := svc1log.FromContext(ctx)
	logger.Info("Finished finding subdomains",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("numSubdomainsFound", len(allSubdomains)),
		svc1log.SafeParam("numRecordsFound", len(allRecords)),
		svc1log.SafeParam("duration", duration))

	report := BruteSubEnumReport{
		Domain:     domain,
		Subdomains: allSubdomains,
		Records:    allRecords,
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
	if len(records.CNAME) > 0 {
		return records.CNAME[0].Name
	}
	return ""
}

func getRecordsFound(records Records) []Record {
	recordsFound := []Record{}
	if len(records.A) > 0 {
		recordsFound = append(recordsFound, records.A...)
	}
	if len(records.AAAA) > 0 {
		recordsFound = append(recordsFound, records.AAAA...)
	}
	if len(records.CNAME) > 0 {
		recordsFound = append(recordsFound, records.CNAME...)
	}
	return recordsFound
}
