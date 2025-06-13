package dns

import (
	"context"
	"slices"

	common "github.com/Method-Security/osintscan/generated/go/common"
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// getDNSRecords queries DNS for the specified record types for a domain and returns a DnsRecords struct.
func getDNSRecords(domain string, questionTypes []uint16) ([]*common.DnsRecord, error) {
	options := dnsx.DefaultOptions
	options.QuestionTypes = questionTypes
	client, err := dnsx.New(options)
	if err != nil {
		return []*common.DnsRecord{}, err
	}

	dnsRecords := []*common.DnsRecord{}

	// Query all requested DNS record types
	results, err := client.QueryMultiple(domain)
	if err != nil {
		return []*common.DnsRecord{}, err
	}

	// Helper to convert raw records to DnsRecord structs
	populateRecords := func(records []string, recordType string) []*common.DnsRecord {
		var dnsRecordsSlice []*common.DnsRecord
		for _, record := range records {
			dnsRecord := common.DnsRecord{
				Name:  domain,
				Ttl:   int(results.TTL), // This assumes a common TTL for all records; adjust if needed
				Type:  common.DnsRecordType(recordType),
				Value: record,
			}
			dnsRecordsSlice = append(dnsRecordsSlice, &dnsRecord)
		}
		return dnsRecordsSlice
	}

	// Populate each record type if requested
	if slices.Contains(questionTypes, dns.TypeA) {
		dnsRecords = append(dnsRecords, populateRecords(results.A, "A")...)
	}
	if slices.Contains(questionTypes, dns.TypeAAAA) {
		dnsRecords = append(dnsRecords, populateRecords(results.AAAA, "AAAA")...)
	}
	if slices.Contains(questionTypes, dns.TypeCNAME) {
		dnsRecords = append(dnsRecords, populateRecords(results.CNAME, "CNAME")...)
	}
	if slices.Contains(questionTypes, dns.TypeMX) {
		dnsRecords = append(dnsRecords, populateRecords(results.MX, "MX")...)
	}
	if slices.Contains(questionTypes, dns.TypeNS) {
		dnsRecords = append(dnsRecords, populateRecords(results.NS, "NS")...)
	}
	if slices.Contains(questionTypes, dns.TypeTXT) {
		dnsRecords = append(dnsRecords, populateRecords(results.TXT, "TXT")...)
	}
	if slices.Contains(questionTypes, dns.TypePTR) {
		dnsRecords = append(dnsRecords, populateRecords(results.PTR, "PTR")...)
	}
	if slices.Contains(questionTypes, dns.TypeSRV) {
		dnsRecords = append(dnsRecords, populateRecords(results.SRV, "SRV")...)
	}

	return dnsRecords, nil
}

// DiscoverDomainDNSRecords queries DNS for all records for a given domain.
// Returns a report containing all records and any non-fatal errors encountered.
func DiscoverDomainDNSRecords(ctx context.Context, config dnsfern.DiscoverDnsRecordsConfig) (*dnsfern.DiscoverDnsRecordsReport, error) {
	errors := []string{}

	// Get all the DNS records
	questionTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeCNAME, dns.TypePTR, dns.TypeSRV}
	dnsRecords, err := getDNSRecords(config.Domain, questionTypes)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// The DMARC record is always in the _dmarc subdomain (RFC-7489)
	dmarcRecords, err := getDNSRecords("_dmarc."+config.Domain, []uint16{dns.TypeTXT})
	if err != nil {
		errors = append(errors, err.Error())
	}

	// The DKIM record is always in the _domainkey subdomain (RFC-6376),
	// but the selector is not known in advance, so check common selectors.
	dkimRecords := []*common.DnsRecord{}
	var selectors []string = []string{"default", "selector1", "selector2", "google", "amazonses", "microsoft"}
	for _, selector := range selectors {
		dkimRecordForSelector, err := getDNSRecords(selector+"._domainkey."+config.Domain, []uint16{dns.TypeTXT})
		if err != nil {
			errors = append(errors, err.Error())
		}
		dkimRecords = append(dkimRecords, dkimRecordForSelector...)
	}

	// Create the report
	report := dnsfern.DiscoverDnsRecordsReport{
		Config: &config,
		Result: &dnsfern.DiscoverDnsRecordsResult{
			DnsRecords:   dnsRecords,
			DmarcRecords: dmarcRecords,
			DkimRecords:  dkimRecords,
		},
		Errors: errors,
	}

	return &report, nil
}
