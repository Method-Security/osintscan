package dns

import (
	"context"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"

	osintscan "github.com/Method-Security/osintscan/generated/go"
)

func getDNSRecords(domain string) (osintscan.DnsRecords, error) {
	options := dnsx.DefaultOptions
	var questionTypes []uint16 = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeCNAME}
	options.QuestionTypes = questionTypes
	options.MaxRetries = 5
	client, err := dnsx.New(options)
	if err != nil {
		return osintscan.DnsRecords{}, err
	}

	dnsRecords := osintscan.DnsRecords{}

	results, err := client.QueryMultiple(domain)
	if err != nil {
		return osintscan.DnsRecords{}, err
	}

	populateRecords := func(records []string, recordType string) []*osintscan.DnsRecord {
		var dnsRecordsSlice []*osintscan.DnsRecord
		for _, record := range records {
			dnsRecord := osintscan.DnsRecord{
				Name:  domain,
				Ttl:   int(results.TTL), // This assumes a common TTL for all records; adjust if needed
				Type:  recordType,
				Value: record,
			}
			dnsRecordsSlice = append(dnsRecordsSlice, &dnsRecord)
		}
		return dnsRecordsSlice
	}

	dnsRecords.A = populateRecords(results.A, "A")
	dnsRecords.Aaaa = populateRecords(results.AAAA, "AAAA")
	dnsRecords.Cname = populateRecords(results.CNAME, "CNAME")
	dnsRecords.Mx = populateRecords(results.MX, "MX")
	dnsRecords.Ns = populateRecords(results.NS, "NS")
	dnsRecords.Txt = populateRecords(results.TXT, "TXT")

	return dnsRecords, nil
}

// GetDomainDNSRecords queries DNS for all records for a given domain. It returns a RecordsReport struct containing
// all records that were and any non-fatal errors that occurred.
func GetDomainDNSRecords(ctx context.Context, domain string) (osintscan.DnsRecordsReport, error) {
	errors := []string{}

	// 1. Get all the DNS records
	dnsRecords, err := getDNSRecords(domain)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 2. Create report and write to file
	report := osintscan.DnsRecordsReport{
		Domain:     domain,
		DnsRecords: &dnsRecords,
		Errors:     errors,
	}
	return report, nil

}
