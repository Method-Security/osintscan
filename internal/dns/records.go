package dns

import (
	"context"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Record represents a single DNS record.
type Record struct {
	Name  string `json:"name" yaml:"name"`
	TTL   uint32 `json:"ttl" yaml:"ttl"`
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
}

// Records represents all of the DNS records for a given domain.
type Records struct {
	A     []Record `json:"a,omitempty" yaml:"a"`
	AAAA  []Record `json:"aaaa,omitempty" yaml:"aaaa"`
	MX    []Record `json:"mx,omitempty" yaml:"mx"`
	TXT   []Record `json:"txt,omitempty" yaml:"txt"`
	NS    []Record `json:"ns,omitempty" yaml:"ns"`
	CNAME []Record `json:"cname,omitempty" yaml:"cname"`
}

// RecordsReport represents the report of all DNS records for a given domain including all non-fatal errors that occurred.
type RecordsReport struct {
	Domain     string   `json:"domain" yaml:"domain"`
	DNSRecords Records  `json:"dns_records" yaml:"dns_records"`
	Errors     []string `json:"errors" yaml:"errors"`
}

func getDNSRecords(domain string) (Records, error) {
	options := dnsx.DefaultOptions
	var questionTypes []uint16 = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeCNAME}
	options.QuestionTypes = questionTypes
	options.MaxRetries = 5
	client, err := dnsx.New(options)
	if err != nil {
		return Records{}, err
	}

	dnsRecords := Records{}

	results, err := client.QueryMultiple(domain)
	if err != nil {
		return Records{}, err
	}

	populateRecords := func(records []string, recordType string) []Record {
		var dnsRecordsSlice []Record
		for _, record := range records {
			dnsRecord := Record{
				Name:  domain,
				TTL:   results.TTL, // This assumes a common TTL for all records; adjust if needed
				Type:  recordType,
				Value: record,
			}
			dnsRecordsSlice = append(dnsRecordsSlice, dnsRecord)
		}
		return dnsRecordsSlice
	}

	dnsRecords.A = populateRecords(results.A, "A")
	dnsRecords.AAAA = populateRecords(results.AAAA, "AAAA")
	dnsRecords.CNAME = populateRecords(results.CNAME, "CNAME")
	dnsRecords.MX = populateRecords(results.MX, "MX")
	dnsRecords.NS = populateRecords(results.NS, "NS")
	dnsRecords.TXT = populateRecords(results.TXT, "TXT")

	return dnsRecords, nil
}

// GetDomainDNSRecords queries DNS for all records for a given domain. It returns a RecordsReport struct containing
// all records that were and any non-fatal errors that occurred.
func GetDomainDNSRecords(ctx context.Context, domain string) (RecordsReport, error) {
	errors := []string{}

	// 1. Get all the DNS records
	dnsRecords, err := getDNSRecords(domain)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 2. Create report and write to file
	report := RecordsReport{
		Domain:     domain,
		DNSRecords: dnsRecords,
		Errors:     errors,
	}
	return report, nil

}
