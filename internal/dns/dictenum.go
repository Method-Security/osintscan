package dns

import (
	"context"
	"fmt"
)

func BruteEnumDomainSubdomains(ctx context.Context, domain string, words []string) (SubdomainsEnumReport, error) {
	errors := []string{}
	subdomains := []string{}

	for _, word := range words {
		report, err := GetDomainDNSRecords(ctx, word+"."+domain)
		if err != nil {
			errors = append(errors, err.Error())
		}
		fmt.Println(report.DNSRecords.A)
		fmt.Println(report.DNSRecords.AAAA)
		fmt.Println(report.DNSRecords.CNAME)
		fmt.Println(report.DNSRecords.MX)
		fmt.Println(report.DNSRecords.NS)
		fmt.Println(report.DNSRecords.TXT)
		// subdomains = append(subdomains, report)
	}

	report := SubdomainsEnumReport{
		Domain:     domain,
		Subdomains: subdomains,
		Errors:     errors,
	}

	return report, nil
}
