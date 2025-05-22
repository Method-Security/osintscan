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
)

// DiscoverDomainCerts queries crt.sh for all certificates for a given domain.
// Returns a report containing all certificates and any errors encountered.
func DiscoverDomainCerts(ctx context.Context, domain string) (*dnsfern.DiscoverDnsCertsReport, error) {
	errors := []string{}

	baseURL := "https://crt.sh/?q=%s&output=json"
	escapedDomain := url.QueryEscape(domain) // Properly escape the domain in the URL
	apiURL := fmt.Sprintf(baseURL, escapedDomain)

	// Make the HTTP request to crt.sh API
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

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Decode the JSON response into the slice of CertificateRecord
	var records []*dnsfern.CertificateRecord
	err = json.Unmarshal(body, &records)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Create the CertReport struct
	report := &dnsfern.DiscoverDnsCertsReport{
		Domain:       domain,
		Certificates: records,
		Errors:       errors,
	}

	return report, nil
}
