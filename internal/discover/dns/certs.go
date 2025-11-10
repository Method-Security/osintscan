// Package dns handles all of the data structures and logic required to interact with DNS data.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// DiscoverDomainCerts queries crt.sh for all certificates for a given domain.
// Returns a report containing all certificates and any errors encountered.
func DiscoverDomainCerts(ctx context.Context, config dnsfern.DiscoverDnsCertsConfig) (*dnsfern.DiscoverDnsCertsReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting certificate discovery", svc1log.SafeParam("domain", config.Domain))

	baseURL := "https://crt.sh/?q=%s&output=json"
	escapedDomain := url.QueryEscape(config.Domain) // Properly escape the domain in the URL
	apiURL := fmt.Sprintf(baseURL, escapedDomain)

	// Make the HTTP request to crt.sh API
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Warn("Failed to query crt.sh API",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}
	defer func() {
		// Capture and log any error from Close
		if cerr := resp.Body.Close(); cerr != nil {
			errors = append(errors, cerr.Error())
		}
	}()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Parse the JSON response manually
	var rawRecords []map[string]interface{}
	if err := json.Unmarshal(body, &rawRecords); err != nil {
		errors = append(errors, err.Error())
	}

	// Convert raw records to CertificateRecord structs
	records := make([]*dnsfern.CertificateRecord, 0, len(rawRecords))
	for _, raw := range rawRecords {
		record := &dnsfern.CertificateRecord{
			IssuerCaid:     int(raw["issuer_ca_id"].(float64)),
			IssuerName:     raw["issuer_name"].(string),
			CommonName:     raw["common_name"].(string),
			NameValue:      raw["name_value"].(string),
			Id:             int(raw["id"].(float64)),
			EntryTimestamp: raw["entry_timestamp"].(string),
			NotBefore:      raw["not_before"].(string),
			NotAfter:       raw["not_after"].(string),
			SerialNumber:   raw["serial_number"].(string),
			ResultCount:    int(raw["result_count"].(float64)),
		}
		records = append(records, record)
	}

	// Create the CertReport struct
	report := &dnsfern.DiscoverDnsCertsReport{
		Config: &config,
		Result: &dnsfern.DiscoverDnsCertsResult{
			Certificates: records,
		},
		Errors: errors,
	}

	log.Info("Completed certificate discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("certificates_found", len(records)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}
