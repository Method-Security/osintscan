package dns

import (
	"context"
	"fmt"
	"slices"

	common "github.com/Method-Security/osintscan/generated/go/common"
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/miekg/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// filterDNSRecordsByType filters DNS records based on the requested record types
func filterDNSRecordsByType(records []*common.DnsRecord, recordTypes []common.DnsRecordType) []*common.DnsRecord {
	// If no specific types requested or ALL is requested, return everything
	for _, recordType := range recordTypes {
		if recordType == common.DnsRecordTypeAll {
			return records
		}
	}

	// If no types specified, return everything
	if len(recordTypes) == 0 {
		return records
	}

	// Create a set of requested types for quick lookup
	requestedTypes := make(map[common.DnsRecordType]bool)
	for _, recordType := range recordTypes {
		requestedTypes[recordType] = true
	}

	// Filter records
	var filteredRecords []*common.DnsRecord
	for _, record := range records {
		if requestedTypes[record.Type] {
			filteredRecords = append(filteredRecords, record)
		}
	}

	return filteredRecords
}

// getDNSRecords queries DNS for the specified record types for a domain and returns a DnsRecords struct.
func getDNSRecords(ctx context.Context, domain string, questionTypes []uint16) ([]*common.DnsRecord, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Querying DNS records",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("record_types_count", len(questionTypes)))

	options := dnsx.DefaultOptions
	options.QuestionTypes = questionTypes
	client, err := dnsx.New(options)
	if err != nil {
		log.Warn("Failed to create DNS client",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("error", err.Error()))
		return []*common.DnsRecord{}, err
	}

	dnsRecords := []*common.DnsRecord{}

	// Query all requested DNS record types
	results, err := client.QueryMultiple(domain)
	if err != nil {
		log.Warn("DNS query failed",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("error", err.Error()))
		return []*common.DnsRecord{}, err
	}

	log.Debug("DNS query successful", svc1log.SafeParam("domain", domain))

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

	// Populate each record type if requested (in alphabetical order)
	if slices.Contains(questionTypes, dns.TypeA) {
		dnsRecords = append(dnsRecords, populateRecords(results.A, "A")...)
	}
	if slices.Contains(questionTypes, dns.TypeAAAA) {
		dnsRecords = append(dnsRecords, populateRecords(results.AAAA, "AAAA")...)
	}
	if slices.Contains(questionTypes, dns.TypeCAA) {
		dnsRecords = append(dnsRecords, populateRecords(results.CAA, "CAA")...)
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
	if slices.Contains(questionTypes, dns.TypePTR) {
		dnsRecords = append(dnsRecords, populateRecords(results.PTR, "PTR")...)
	}
	if slices.Contains(questionTypes, dns.TypeSOA) {
		// SOA records have a different structure, need to convert them to strings
		var soaStrings []string
		for _, soa := range results.SOA {
			soaString := fmt.Sprintf("%s %s %d %d %d %d %d", soa.NS, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
			soaStrings = append(soaStrings, soaString)
		}
		dnsRecords = append(dnsRecords, populateRecords(soaStrings, "SOA")...)
	}
	if slices.Contains(questionTypes, dns.TypeSRV) {
		dnsRecords = append(dnsRecords, populateRecords(results.SRV, "SRV")...)
	}
	if slices.Contains(questionTypes, dns.TypeTXT) {
		dnsRecords = append(dnsRecords, populateRecords(results.TXT, "TXT")...)
	}

	// Note: We don't process unknown record types to avoid noise from DNS protocol overhead
	// and non-existent subdomain responses

	log.Debug("Processed DNS records",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("total_records", len(dnsRecords)))

	return dnsRecords, nil
}

// DiscoverDomainDNSRecords queries DNS for all records for a given domain.
// Returns a report containing all records and any non-fatal errors encountered.
func DiscoverDomainDNSRecords(ctx context.Context, config dnsfern.DiscoverDnsRecordsConfig) *dnsfern.DiscoverDnsRecordsReport {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting DNS records discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("requested_record_types", len(config.RecordTypes)))

	// Get all the DNS records (query all types, then filter)
	questionTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypePTR, dns.TypeSOA, dns.TypeSRV, dns.TypeTXT}
	allDNSRecords, err := getDNSRecords(ctx, config.Domain, questionTypes)
	if err != nil {
		log.Warn("Failed to get DNS records",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}

	// Filter DNS records based on requested types
	dnsRecords := filterDNSRecordsByType(allDNSRecords, config.RecordTypes)
	log.Debug("Filtered DNS records",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("total_records", len(allDNSRecords)),
		svc1log.SafeParam("filtered_records", len(dnsRecords)))

	// The DMARC record is always in the _dmarc subdomain (RFC-7489)
	dmarcDomain := "_dmarc." + config.Domain
	log.Debug("Querying DMARC records", svc1log.SafeParam("dmarc_domain", dmarcDomain))
	dmarcRecords, err := getDNSRecords(ctx, dmarcDomain, []uint16{dns.TypeTXT})
	if err != nil {
		log.Warn("Failed to get DMARC records",
			svc1log.SafeParam("dmarc_domain", dmarcDomain),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	} else {
		log.Debug("Retrieved DMARC records",
			svc1log.SafeParam("dmarc_domain", dmarcDomain),
			svc1log.SafeParam("dmarc_record_count", len(dmarcRecords)))
	}

	// The DKIM record is always in the _domainkey subdomain (RFC-6376),
	// but the selector is not known in advance, so check common selectors.
	dkimRecords := []*common.DnsRecord{}
	var selectors []string = []string{"default", "selector1", "selector2", "google", "amazonses", "microsoft"}
	log.Debug("Querying DKIM records",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("selector_count", len(selectors)))

	for _, selector := range selectors {
		dkimDomain := selector + "._domainkey." + config.Domain
		dkimRecordForSelector, err := getDNSRecords(ctx, dkimDomain, []uint16{dns.TypeTXT})
		if err != nil {
			log.Debug("Failed to get DKIM records for selector",
				svc1log.SafeParam("selector", selector),
				svc1log.SafeParam("dkim_domain", dkimDomain),
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, err.Error())
		} else if len(dkimRecordForSelector) > 0 {
			log.Debug("Retrieved DKIM records for selector",
				svc1log.SafeParam("selector", selector),
				svc1log.SafeParam("dkim_domain", dkimDomain),
				svc1log.SafeParam("dkim_record_count", len(dkimRecordForSelector)))
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

	log.Info("Completed DNS records discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("dns_records", len(dnsRecords)),
		svc1log.SafeParam("dmarc_records", len(dmarcRecords)),
		svc1log.SafeParam("dkim_records", len(dkimRecords)),
		svc1log.SafeParam("error_count", len(errors)))

	return &report
}
