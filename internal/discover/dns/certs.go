// Package dns handles all of the data structures and logic required to interact with DNS data.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	dnsFern "github.com/Method-Security/osintscan/generated/go/discover/dns"
)

// DiscoverDomainCerts queries crt.sh for all certificates for a given domain. It returns a CertsReport struct containing
// all certificates and any errors that occurred.
func DiscoverDomainCerts(ctx context.Context, domain string) (*dnsFern.DiscoverDnsCertsReport, error) {
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
	var records []*dnsFern.CertificateRecord
	err = json.Unmarshal(body, &records)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 4. Create the CertReport struct
	report := &dnsFern.DiscoverDnsCertsReport{
		Domain:       domain,
		Certificates: records,
		Errors:       errors,
	}

	return report, nil
}
