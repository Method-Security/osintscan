package dns

import (
	"context"
	"encoding/json"
)

func BruteEnumDomainSubdomains(ctx context.Context, domain string, words []string) (SubdomainsEnumReport, error) {
	errors := []string{}
	subdomains := []string{}

	for _, word := range words {
		report, err := GetDomainDNSRecords(ctx, word+"."+domain)
		if err != nil {
			errors = append(errors, err.Error())
		}
		records, err := json.Marshal(report.DNSRecords)
		if err != nil {
			errors = append(errors, err.Error())
		}
		if string(records) != "{}" {
			subdomains = append(subdomains, string(records))
		}
	}

	report := SubdomainsEnumReport{
		Domain:     domain,
		Subdomains: subdomains,
		Errors:     errors,
	}

	return report, nil
}
