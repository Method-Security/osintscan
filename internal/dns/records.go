package dns

import (
	"context"
	"slices"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"

	osintscan "github.com/Method-Security/osintscan/generated/go"
)

func populateRecords(domain string, ttl int, records []string, recordType string) []*osintscan.DnsRecord {
	var dnsRecordsSlice []*osintscan.DnsRecord
	for _, record := range records {
		dnsRecord := osintscan.DnsRecord{
			Name:  domain,
			Ttl:   ttl, // This assumes a common TTL for all records; adjust if needed
			Type:  recordType,
			Value: record,
		}
		dnsRecordsSlice = append(dnsRecordsSlice, &dnsRecord)
	}
	return dnsRecordsSlice
}

func getDNSRecords(domain string, questionTypes []uint16) (osintscan.DnsRecords, error) {
	options := dnsx.DefaultOptions
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

	if slices.Contains(questionTypes, dns.TypeA) {
		dnsRecords.A = populateRecords(domain, int(results.TTL), results.A, "A")
	}
	if slices.Contains(questionTypes, dns.TypeAAAA) {
		dnsRecords.Aaaa = populateRecords(domain, int(results.TTL), results.AAAA, "AAAA")
	}
	if slices.Contains(questionTypes, dns.TypeCNAME) {
		dnsRecords.Cname = populateRecords(domain, int(results.TTL), results.CNAME, "CNAME")
	}
	if slices.Contains(questionTypes, dns.TypeMX) {
		dnsRecords.Mx = populateRecords(domain, int(results.TTL), results.MX, "MX")
	}
	if slices.Contains(questionTypes, dns.TypeNS) {
		dnsRecords.Ns = populateRecords(domain, int(results.TTL), results.NS, "NS")
	}
	if slices.Contains(questionTypes, dns.TypeTXT) {
		dnsRecords.Txt = populateRecords(domain, int(results.TTL), results.TXT, "TXT")
	}

	return dnsRecords, nil
}

// GetDomainDNSRecords queries DNS for all records for a given domain. It returns a RecordsReport struct containing
// all records that were and any non-fatal errors that occurred.
func GetDomainDNSRecords(ctx context.Context, domain string) (osintscan.DnsRecordsReport, error) {
	errors := []string{}

	// Get all the DNS records
	var questionTypes []uint16 = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeCNAME}
	dnsRecords, err := getDNSRecords(domain, questionTypes)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// The DMARC record is always in the _dmarc subdomain (RFC-7489) and therefore must be fetched separately
	dmarcRecords, err := getDNSRecords("_dmarc."+domain, []uint16{dns.TypeTXT})
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Create report and write to file
	report := osintscan.DnsRecordsReport{
		Domain:          domain,
		DnsRecords:      &dnsRecords,
		DmarcDnsRecords: &dmarcRecords,
		Errors:          errors,
	}
	return report, nil

}
