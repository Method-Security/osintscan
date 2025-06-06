package zonetransfer

import (
	"context"
	"fmt"
	"net"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	"github.com/Method-Security/osintscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TestZoneTransfer performs DNS zone transfer tests on the specified domains.
// If nameserver is provided, it tests directly against that server.
// Otherwise, it discovers nameservers via NS record lookups.
func TestZoneTransfer(ctx context.Context, domains []string, timeout int, resolver string, nameserver string) (*dnsfern.EnumerateDnsZoneTransferReport, error) {
	log := svc1log.FromContext(ctx)

	// Direct nameserver mode
	if nameserver != "" {
		log.Info("Using direct nameserver mode", svc1log.SafeParam("nameserver", nameserver))
		return testDirectNameserver(ctx, nameserver, domains, timeout, log)
	}

	// NS lookup mode
	log.Info("Using NS lookup mode")
	return testViaNSLookup(ctx, domains, timeout, resolver, log)
}

// testDirectNameserver tests zone transfers directly against a specified nameserver
func testDirectNameserver(ctx context.Context, nameserver string, domains []string, timeout int, log svc1log.Logger) (*dnsfern.EnumerateDnsZoneTransferReport, error) {
	report := &dnsfern.EnumerateDnsZoneTransferReport{Domains: domains}
	errors := []string{}
	zoneTransferDetails := []*dnsfern.DnsZoneTransferDetails{}

	// Normalize nameserver address
	ns := normalizeNameserver(nameserver)

	for _, domain := range domains {
		log.Info("Testing zone transfer",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("nameserver", ns))

		// Attempt zone transfer
		records, success, errs := sendAXFRRequest(ns, domain, timeout, log)

		if len(errs) > 0 {
			for _, err := range errs {
				errors = append(errors, fmt.Sprintf("%s@%s: %s", domain, ns, err))
			}
		}

		zoneTransferDetails = append(zoneTransferDetails, &dnsfern.DnsZoneTransferDetails{
			Domain:     domain,
			DnsRecords: records,
			Success:    &success,
		})

		if success {
			log.Info("Zone transfer successful",
				svc1log.SafeParam("domain", domain),
				svc1log.SafeParam("records", len(records)))
		}
	}

	report.ZoneTransfer = zoneTransferDetails
	report.Errors = errors
	return report, nil
}

// testViaNSLookup discovers nameservers and tests zone transfers on each
func testViaNSLookup(ctx context.Context, domains []string, timeout int, resolver string, log svc1log.Logger) (*dnsfern.EnumerateDnsZoneTransferReport, error) {
	report := &dnsfern.EnumerateDnsZoneTransferReport{Domains: domains}
	errors := []string{}
	zoneTransferDetails := []*dnsfern.DnsZoneTransferDetails{}

	// Get custom resolver if specified
	customResolver := utils.GetResolver(resolver, log)

	for _, domain := range domains {
		details := testDomainViaLookup(ctx, domain, timeout, customResolver, log, &errors)
		zoneTransferDetails = append(zoneTransferDetails, details)
	}

	report.ZoneTransfer = zoneTransferDetails
	report.Errors = errors
	return report, nil
}

// testDomainViaLookup tests a single domain by looking up its NS records
func testDomainViaLookup(ctx context.Context, domain string, timeout int, resolver *net.Resolver, log svc1log.Logger, errors *[]string) *dnsfern.DnsZoneTransferDetails {
	axfrSuccessful := false
	dnsRecords := []*dnsfern.DnsZoneTransferRecord{}

	log.Info("Looking up NS records", svc1log.SafeParam("domain", domain))

	// Lookup NS records
	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		log.Error("NS lookup failed",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("error", err))
		*errors = append(*errors, fmt.Sprintf("NS lookup failed for %s: %v", domain, err))

		return &dnsfern.DnsZoneTransferDetails{
			Domain:     domain,
			DnsRecords: dnsRecords,
			Success:    &axfrSuccessful,
		}
	}

	log.Info("Found NS records",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("count", len(nsRecords)))

	// Track which nameservers we've successfully tested
	testedServers := make(map[string]bool)

	// Try zone transfer on each unique nameserver
	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")

		// Skip if we've already tested this server
		if testedServers[nsHost] {
			continue
		}
		testedServers[nsHost] = true

		log.Info("Testing nameserver",
			svc1log.SafeParam("nameserver", nsHost),
			svc1log.SafeParam("domain", domain))

		// Attempt zone transfer
		records, success, errs := sendAXFRRequest(nsHost, domain, timeout, log)

		if len(errs) > 0 {
			for _, err := range errs {
				*errors = append(*errors, fmt.Sprintf("%s@%s: %s", domain, nsHost, err))
			}
		}

		if success {
			log.Info("Zone transfer successful",
				svc1log.SafeParam("nameserver", nsHost),
				svc1log.SafeParam("records", len(records)))
			axfrSuccessful = true
			dnsRecords = append(dnsRecords, records...)
			// Continue testing other nameservers to find all vulnerable ones
		}
	}

	return &dnsfern.DnsZoneTransferDetails{
		Domain:     domain,
		DnsRecords: dnsRecords,
		Success:    &axfrSuccessful,
	}
}

// normalizeNameserver ensures the nameserver address is properly formatted
func normalizeNameserver(nameserver string) string {
	// Remove any trailing dots
	ns := strings.TrimSuffix(nameserver, ".")

	// If it's an IP address, return as-is
	if net.ParseIP(ns) != nil {
		return ns
	}

	// If it already has a port, return as-is
	if strings.Contains(ns, ":") {
		return ns
	}

	// Otherwise, it's a hostname without port
	return ns
}
