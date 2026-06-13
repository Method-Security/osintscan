package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	common "github.com/Method-Security/osintscan/generated/go/common"
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/miekg/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// defaultTCPResolvers are well-known public resolvers used when TCP is forced but
// no explicit resolvers are supplied (dnsx's defaults are UDP-only).
var defaultTCPResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// normalizeDnsxResolvers converts resolver addresses (e.g. "1.1.1.1:53") to the
// format expected by the dnsx library ("udp:1.1.1.1:53" or "tcp:1.1.1.1:53").
// When useTCP is set and no resolvers are supplied, a TCP-prefixed default set is
// returned so the transport override still takes effect.
func normalizeDnsxResolvers(resolvers []string, useTCP bool) []string {
	proto := "udp:"
	if useTCP {
		proto = "tcp:"
	}
	if len(resolvers) == 0 {
		if !useTCP {
			return nil
		}
		resolvers = defaultTCPResolvers
	}
	normalized := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		hasPrefix := strings.HasPrefix(r, "udp:") || strings.HasPrefix(r, "tcp:")
		// Respect an explicit per-resolver transport only when not globally
		// forcing TCP. When useTCP is set, the override must win even over a
		// resolver already prefixed with udp:.
		if hasPrefix && !useTCP {
			normalized = append(normalized, r)
			continue
		}
		r = strings.TrimPrefix(r, "udp:")
		r = strings.TrimPrefix(r, "tcp:")
		// Add default port if missing
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, "53")
		}
		normalized = append(normalized, proto+r)
	}
	return normalized
}

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
// When timeoutSeconds > 0, the (blocking) resolver query is bounded by that wall-clock deadline.
func getDNSRecords(ctx context.Context, domain string, questionTypes []uint16, dnsResolvers []string, timeoutSeconds int) ([]*common.DnsRecord, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Querying DNS records",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("record_types_count", len(questionTypes)))

	options := dnsx.DefaultOptions
	options.QuestionTypes = questionTypes
	if len(dnsResolvers) > 0 {
		options.BaseResolvers = dnsResolvers
	}
	client, err := dnsx.New(options)
	if err != nil {
		log.Warn("Failed to create DNS client",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("error", err.Error()))
		return []*common.DnsRecord{}, err
	}

	// dnsx exposes no timeout option, so bound the blocking query with a context
	// deadline. The detached goroutine returns once the resolver's own retry budget
	// is exhausted, so it cannot leak indefinitely.
	if timeoutSeconds <= 0 {
		return collectDNSRecords(ctx, client, domain, questionTypes)
	}

	queryCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	type recordsResult struct {
		records []*common.DnsRecord
		err     error
	}
	resultCh := make(chan recordsResult, 1)
	go func() {
		records, queryErr := collectDNSRecords(ctx, client, domain, questionTypes)
		resultCh <- recordsResult{records: records, err: queryErr}
	}()

	select {
	case <-queryCtx.Done():
		// The resolver may have completed in the same scheduling window the
		// context fired; prefer an already-available result over reporting a
		// failure that didn't actually happen.
		select {
		case result := <-resultCh:
			return result.records, result.err
		default:
		}
		// Distinguish a parent-context cancellation (e.g. CLI interrupt) from an
		// actual resolver timeout so the error isn't misattributed.
		if errors.Is(queryCtx.Err(), context.Canceled) {
			return []*common.DnsRecord{}, fmt.Errorf("DNS query for %s canceled: %w", domain, queryCtx.Err())
		}
		log.Warn("DNS query timed out",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("timeoutSeconds", timeoutSeconds))
		return []*common.DnsRecord{}, fmt.Errorf("DNS query for %s timed out after %d seconds", domain, timeoutSeconds)
	case result := <-resultCh:
		return result.records, result.err
	}
}

// collectDNSRecords runs the resolver query and maps the raw response into DnsRecord structs.
func collectDNSRecords(ctx context.Context, client *dnsx.DNSX, domain string, questionTypes []uint16) ([]*common.DnsRecord, error) {
	log := svc1log.FromContext(ctx)

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

	useTCP := config.UseTcp != nil && *config.UseTcp
	timeoutSeconds := 0
	if config.Timeout != nil {
		timeoutSeconds = *config.Timeout
	}

	// Normalize resolver format for dnsx (requires "udp:host:port" / "tcp:host:port" prefix)
	resolvers := normalizeDnsxResolvers(config.DnsResolvers, useTCP)

	// Get all the DNS records (query all types, then filter)
	questionTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS, dns.TypePTR, dns.TypeSOA, dns.TypeSRV, dns.TypeTXT}
	allDNSRecords, err := getDNSRecords(ctx, config.Domain, questionTypes, resolvers, timeoutSeconds)
	if err != nil {
		log.Warn("Failed to get DNS records",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}

	recordTypes := []common.DnsRecordType{}
	for _, recordType := range config.RecordTypes {
		recordTypeEnum, err := common.NewDnsRecordTypeFromString(recordType)
		// SHould never happen since we early exit in cmd file
		if err != nil {
			log.Error("Invalid DNS record type",
				svc1log.SafeParam("domain", config.Domain),
				svc1log.SafeParam("record_type", recordType),
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, err.Error())
			continue
		}
		recordTypes = append(recordTypes, recordTypeEnum)
	}

	// Filter DNS records based on requested types
	dnsRecords := filterDNSRecordsByType(allDNSRecords, recordTypes)
	log.Debug("Filtered DNS records",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("total_records", len(allDNSRecords)),
		svc1log.SafeParam("filtered_records", len(dnsRecords)))

	// DMARC and DKIM are TXT-based records; only query them when TXT or ALL is
	// requested, or when no type filter is applied (meaning return everything).
	wantTXT := len(recordTypes) == 0
	for _, rt := range recordTypes {
		if rt == common.DnsRecordTypeAll || rt == common.DnsRecordTypeTxt {
			wantTXT = true
			break
		}
	}

	// The DMARC record is always in the _dmarc subdomain (RFC-7489)
	dmarcRecords := []*common.DnsRecord{}
	if wantTXT {
		dmarcDomain := "_dmarc." + config.Domain
		log.Debug("Querying DMARC records", svc1log.SafeParam("dmarc_domain", dmarcDomain))
		var dmarcErr error
		dmarcRecords, dmarcErr = getDNSRecords(ctx, dmarcDomain, []uint16{dns.TypeTXT}, resolvers, timeoutSeconds)
		if dmarcErr != nil {
			log.Warn("Failed to get DMARC records",
				svc1log.SafeParam("dmarc_domain", dmarcDomain),
				svc1log.SafeParam("error", dmarcErr.Error()))
			errors = append(errors, dmarcErr.Error())
		} else {
			log.Debug("Retrieved DMARC records",
				svc1log.SafeParam("dmarc_domain", dmarcDomain),
				svc1log.SafeParam("dmarc_record_count", len(dmarcRecords)))
		}
	}

	// The DKIM record is always in the _domainkey subdomain (RFC-6376),
	// but the selector is not known in advance, so check common selectors.
	dkimRecords := []*common.DnsRecord{}
	if wantTXT {
		var selectors []string = []string{"default", "selector1", "selector2", "google", "amazonses", "microsoft"}
		log.Debug("Querying DKIM records",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("selector_count", len(selectors)))

		for _, selector := range selectors {
			dkimDomain := selector + "._domainkey." + config.Domain
			dkimRecordForSelector, dkimErr := getDNSRecords(ctx, dkimDomain, []uint16{dns.TypeTXT}, resolvers, timeoutSeconds)
			if dkimErr != nil {
				log.Debug("Failed to get DKIM records for selector",
					svc1log.SafeParam("selector", selector),
					svc1log.SafeParam("dkim_domain", dkimDomain),
					svc1log.SafeParam("error", dkimErr.Error()))
				errors = append(errors, dkimErr.Error())
			} else if len(dkimRecordForSelector) > 0 {
				log.Debug("Retrieved DKIM records for selector",
					svc1log.SafeParam("selector", selector),
					svc1log.SafeParam("dkim_domain", dkimDomain),
					svc1log.SafeParam("dkim_record_count", len(dkimRecordForSelector)))
			}
			dkimRecords = append(dkimRecords, dkimRecordForSelector...)
		}
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
