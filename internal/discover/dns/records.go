package dns

import (
	"context"
	"slices"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// getDNSRecords queries DNS for the specified record types for a domain and returns a DnsRecords struct.
func getDNSRecords(domain string, questionTypes []uint16) (dnsfern.DnsRecords, error) {
	options := dnsx.DefaultOptions
	options.QuestionTypes = questionTypes
	client, err := dnsx.New(options)
	if err != nil {
		return dnsfern.DnsRecords{}, err
	}

	dnsRecords := dnsfern.DnsRecords{}

	// Query all requested DNS record types
	results, err := client.QueryMultiple(domain)
	if err != nil {
		return dnsfern.DnsRecords{}, err
	}

	// Helper to convert raw records to DnsRecord structs
	populateRecords := func(records []string, recordType string) []*dnsfern.DnsRecord {
		var dnsRecordsSlice []*dnsfern.DnsRecord
		for _, record := range records {
			dnsRecord := dnsfern.DnsRecord{
				Name:  domain,
				Ttl:   int(results.TTL), // This assumes a common TTL for all records; adjust if needed
				Type:  recordType,
				Value: record,
			}
			dnsRecordsSlice = append(dnsRecordsSlice, &dnsRecord)
		}
		return dnsRecordsSlice
	}

	// Populate each record type if requested
	if slices.Contains(questionTypes, dns.TypeA) {
		dnsRecords.A = populateRecords(results.A, "A")
	}
	if slices.Contains(questionTypes, dns.TypeAAAA) {
		dnsRecords.Aaaa = populateRecords(results.AAAA, "AAAA")
	}
	if slices.Contains(questionTypes, dns.TypeCNAME) {
		dnsRecords.Cname = populateRecords(results.CNAME, "CNAME")
	}
	if slices.Contains(questionTypes, dns.TypeMX) {
		dnsRecords.Mx = populateRecords(results.MX, "MX")
	}
	if slices.Contains(questionTypes, dns.TypeNS) {
		dnsRecords.Ns = populateRecords(results.NS, "NS")
	}
	if slices.Contains(questionTypes, dns.TypeTXT) {
		dnsRecords.Txt = populateRecords(results.TXT, "TXT")
	}

	return dnsRecords, nil
}

// DiscoverDomainDNSRecords queries DNS for all records for a given domain.
// Returns a report containing all records and any non-fatal errors encountered.
func DiscoverDomainDNSRecords(ctx context.Context, domain string) (*dnsfern.DiscoverDnsRecordsReport, error) {
	errors := []string{}

	// Get all the DNS records
	questionTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeCNAME}
	dnsRecords, err := getDNSRecords(domain, questionTypes)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// The DMARC record is always in the _dmarc subdomain (RFC-7489)
	dmarcRecords, err := getDNSRecords("_dmarc."+domain, []uint16{dns.TypeTXT})
	if err != nil {
		errors = append(errors, err.Error())
	}

	// The DKIM record is always in the _domainkey subdomain (RFC-6376),
	// but the selector is not known in advance, so check common selectors.
	dkimRecords := dnsfern.DnsRecords{}
	var selectors []string = []string{"default", "selector1", "selector2", "google", "amazonses", "microsoft"}
	for _, selector := range selectors {
		dkimRecordForSelector, err := getDNSRecords(selector+"._domainkey."+domain, []uint16{dns.TypeTXT})
		if err != nil {
			errors = append(errors, err.Error())
		}
		dkimRecords.Txt = append(dkimRecords.Txt, dkimRecordForSelector.Txt...)
	}

	// Create the report
	report := dnsfern.DiscoverDnsRecordsReport{
		Domain:          domain,
		DnsRecords:      &dnsRecords,
		DmarcDnsRecords: &dmarcRecords,
		DkimDnsRecords:  &dkimRecords,
		Errors:          errors,
	}

	// Set the domain for the DMARC and DKIM records if they exist
	if len(dmarcRecords.Txt) > 0 {
		report.DmarcDomain = &dmarcRecords.Txt[0].Name
	}
	if len(dkimRecords.Txt) > 0 {
		report.DkimDomain = &dkimRecords.Txt[0].Name
	}

	return &report, nil
}
