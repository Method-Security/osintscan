// Package dns handles all of the data structures and logic required to interact with DNS data.
package dns

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// extractFQDNs parses the nameValue field to extract valid FQDNs
// The nameValue field typically contains DNS names separated by newlines
func extractFQDNs(nameValue string) []string {
	if nameValue == "" {
		return []string{}
	}

	// Split by newlines and clean up each domain
	lines := strings.Split(nameValue, "\n")
	var fqdns []string

	// Regular expression to validate FQDN format
	// This matches valid domain names including wildcards
	fqdnRegex := regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

	for _, line := range lines {
		domain := strings.TrimSpace(line)
		if domain != "" && fqdnRegex.MatchString(domain) {
			fqdns = append(fqdns, domain)
		}
	}

	// Note: We can't log here directly since we don't have a context
	// The logging will happen at the caller level

	return fqdns
}

// DiscoverDomainCerts queries crt.sh for all certificates for a given domain.
// Returns a report containing all certificates and any errors encountered.
// Each certificate record now includes an Fqdns field containing extracted FQDNs
// from the certificate's Subject Alternative Name (SAN) field.
//
// Example usage:
//
//	config := dnsfern.DiscoverDnsCertsConfig{Domain: "example.com"}
//	report, err := DiscoverDomainCerts(ctx, config)
//	if err != nil {
//	    // handle error
//	}
//
//	// Get all unique FQDNs from all certificates
//	allFQDNs := GetUniqueFQDNsFromReport(report)
//
//	// Or access FQDNs from individual certificates
//	for _, cert := range report.Result.Certificates {
//	    fmt.Printf("Certificate %d FQDNs: %v\n", cert.Id, cert.Fqdns)
//	}
func DiscoverDomainCerts(ctx context.Context, config dnsfern.DiscoverDnsCertsConfig) (*dnsfern.DiscoverDnsCertsReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting certificate discovery", svc1log.SafeParam("domain", config.Domain))

	baseURL := "https://crt.sh/?q=%s&output=json"
	escapedDomain := url.QueryEscape(config.Domain) // Properly escape the domain in the URL
	apiURL := fmt.Sprintf(baseURL, escapedDomain)

	log.Debug("Making HTTP request to crt.sh", svc1log.SafeParam("url", apiURL))

	// Make the HTTP request to crt.sh API
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error("Failed to make HTTP request to crt.sh", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}
	defer func() {
		// Capture and log any error from Close
		if cerr := resp.Body.Close(); cerr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", cerr.Error()))
			errors = append(errors, cerr.Error())
		}
	}()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read response body", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}

	// Parse the JSON response manually
	var rawRecords []map[string]interface{}
	if err := json.Unmarshal(body, &rawRecords); err != nil {
		log.Error("Failed to parse JSON response from crt.sh", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}

	log.Info("Successfully retrieved certificates from crt.sh", svc1log.SafeParam("certificate_count", len(rawRecords)))

	// Convert raw records to CertificateRecord structs
	log.Debug("Starting certificate processing and FQDN extraction")
	records := make([]*dnsfern.CertificateRecord, 0, len(rawRecords))

	for _, raw := range rawRecords {
		// Safely extract nameValue with type assertion
		nameValue, ok := raw["name_value"].(string)
		if !ok {
			nameValue = ""
		}
		fqdns := extractFQDNs(nameValue)

		// Helper function to safely convert interface{} to int
		safeInt := func(val interface{}) (int, error) {
			if f, ok := val.(float64); ok {
				return int(f), nil
			}
			if i, ok := val.(int); ok {
				return i, nil
			}
			return 0, fmt.Errorf("cannot convert %T to int", val)
		}

		// Helper function to safely convert interface{} to string
		safeString := func(val interface{}) string {
			if s, ok := val.(string); ok {
				return s
			}
			return ""
		}

		issuerCaid, err := safeInt(raw["issuer_ca_id"])
		if err != nil {
			log.Warn("Failed to convert issuer_ca_id to int", svc1log.SafeParam("error", err.Error()))
			return nil, err
		}

		id, err := safeInt(raw["id"])
		if err != nil {
			log.Warn("Failed to convert id to int", svc1log.SafeParam("error", err.Error()))
			return nil, err
		}

		resultCount, err := safeInt(raw["result_count"])
		if err != nil {
			log.Warn("Failed to convert result_count to int", svc1log.SafeParam("error", err.Error()))
			return nil, err
		}

		record := &dnsfern.CertificateRecord{
			IssuerCaid:     issuerCaid,
			IssuerName:     safeString(raw["issuer_name"]),
			CommonName:     safeString(raw["common_name"]),
			NameValue:      fqdns,
			Id:             id,
			EntryTimestamp: safeString(raw["entry_timestamp"]),
			NotBefore:      safeString(raw["not_before"]),
			NotAfter:       safeString(raw["not_after"]),
			SerialNumber:   safeString(raw["serial_number"]),
			ResultCount:    resultCount,
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

	if len(errors) > 0 {
		log.Error("Certificate discovery failed with errors",
			svc1log.SafeParam("error_count", len(errors)),
			svc1log.SafeParam("domain", config.Domain))
		return nil, fmt.Errorf("certificate discovery failed with %d error(s): %s", len(errors), strings.Join(errors, "; "))
	}
	log.Info("Certificate discovery completed successfully",
		svc1log.SafeParam("domain", config.Domain))

	return report, nil
}
