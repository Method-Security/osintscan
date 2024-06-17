// Package dns handles all of the data structures and logic required to interact with DNS data.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// CertificateRecord represents all of the information for a single x509 certificate record.
type CertificateRecord struct {
	IssuerCAID     int    `json:"issuer_ca_id" yaml:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name" yaml:"issuer_name"`
	CommonName     string `json:"common_name" yaml:"common_name"`
	NameValue      string `json:"name_value" yaml:"name_value"`
	ID             int64  `json:"id" yaml:"id"`
	EntryTimestamp string `json:"entry_timestamp" yaml:"entry_timestamp"`
	NotBefore      string `json:"not_before" yaml:"not_before"`
	NotAfter       string `json:"not_after" yaml:"not_after"`
	SerialNumber   string `json:"serial_number" yaml:"serial_number"`
	ResultCount    int    `json:"result_count" yaml:"result_count"`
}

// CertsReport represents the report of all certificates for a given domain including all non-fatal errors that occurred.
type CertsReport struct {
	Domain       string              `json:"domain" yaml:"domain"`
	Certificates []CertificateRecord `json:"certificates" yaml:"certificates"`
	Errors       []string            `json:"errors" yaml:"errors"`
}

// GetDomainCerts queries crt.sh for all certificates for a given domain. It returns a CertsReport struct containing
// all certificates and any errors that occurred.
func GetDomainCerts(ctx context.Context, domain string) (CertsReport, error) {
	errors := []string{}

	baseURL := "https://crt.sh/?q=%s&output=json"
	escapedDomain := url.QueryEscape(domain) // Properly escape the domain in the URL
	apiURL := fmt.Sprintf(baseURL, escapedDomain)

	// 1. Make the HTTP request to crt.sh API
	resp, err := http.Get(apiURL)
	if err != nil {
		errors = append(errors, err.Error())
	}
	defer func() {
		// Capture and log any error from Close
		if cerr := resp.Body.Close(); cerr != nil {
			errors = append(errors, cerr.Error())
		}
	}()

	// 2. Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 3. Decode the JSON response into the slice of CertificateRecord
	var records []CertificateRecord
	err = json.Unmarshal(body, &records)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 4. Create the CertReport struct
	report := CertsReport{
		Domain:       domain,
		Certificates: records,
		Errors:       errors,
	}

	return report, nil
}
