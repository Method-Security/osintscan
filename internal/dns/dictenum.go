package dns

import (
	"context"
)

func BruteEnumDomainSubdomains(ctx context.Context, domain string, words []string) (SubdomainsEnumReport, error) {
	errors := []string{}
	subdomains := []string{}

	for _, word := range words {
		report, err := GetDomainDNSRecords(ctx, word+"."+domain)
		if err != nil {
			errors = append(errors, err.Error())
		}

		var subdomain = getSubdomainFromRecords(report.DNSRecords)
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	report := SubdomainsEnumReport{
		Domain:     domain,
		Subdomains: subdomains,
		Errors:     errors,
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
