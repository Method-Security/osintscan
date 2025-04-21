package dns

import (
	"context"
	"fmt"
	"net"

	dnsfern "github.com/Method-Security/osintscan/generated/go/dns"
)

// TestZoneTransfer checks if a domain is vulnerable to a DNS zone transfer attack
func TestZoneTransfer(ctx context.Context, domains []string, timeout int) (*dnsfern.DnsZoneTransferReport, error) {
	report := &dnsfern.DnsZoneTransferReport{Domains: domains}
	errors := []string{}

	zoneTransferDetails := []*dnsfern.DnsZoneTransferDetails{}
	for _, domain := range domains {
		axfrSuccessful := false

		fmt.Printf("[Debug] Retrieving NS records for %s\n", domain)
		nsRecords, err := net.LookupNS(domain)
		if err != nil {
			fmt.Printf("[Error] Failed to retrieve NS records for %s: %v\n", domain, err)
			errors = append(errors, fmt.Sprintf("failed to retrieve NS records for %s: %v", domain, err))
			continue
		}

		dnsRecords := []*dnsfern.DnsZoneTransferRecord{}
		for _, ns := range nsRecords {
			dnsRecords = append(dnsRecords, &dnsfern.DnsZoneTransferRecord{
				Name:  domain,
				Type:  dnsfern.DnsRecordEnumNs,
				Value: ns.Host,
			})
			fmt.Printf("[Debug] Testing zone transfer on NS: %s\n", ns.Host)
			records, success, err := sendAXFRRequest(ns.Host, domain, timeout)
			if len(err) > 0 {
				errors = append(errors, err...)
			}
			if success {
				fmt.Printf("[Debug] Zone transfer successful on %s\n", ns.Host)
				axfrSuccessful = true
				dnsRecords = append(dnsRecords, records...)
			}
		}

		zoneTransferDetails = append(zoneTransferDetails, &dnsfern.DnsZoneTransferDetails{
			Domain:     domain,
			DnsRecords: dnsRecords,
			Success:    &axfrSuccessful,
		})
	}
	report.ZoneTransfer = zoneTransferDetails
	report.Errors = errors
	return report, nil
}
