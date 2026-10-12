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
	osintConfig "github.com/Method-Security/osintscan/internal/config"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type crtShCertificateRecord struct {
	IssuerCaid     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	Id             int    `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
	ResultCount    int    `json:"result_count"`
}

func parseCrtShCertificateRecords(body []byte) ([]*dnsfern.CertificateRecord, error) {
	var rawRecords []crtShCertificateRecord
	if err := json.Unmarshal(body, &rawRecords); err != nil {
		return nil, err
	}

	records := make([]*dnsfern.CertificateRecord, 0, len(rawRecords))
	for _, raw := range rawRecords {
		records = append(records, &dnsfern.CertificateRecord{
			IssuerCaid:     raw.IssuerCaid,
			IssuerName:     raw.IssuerName,
			CommonName:     raw.CommonName,
			NameValue:      raw.NameValue,
			Id:             raw.Id,
			EntryTimestamp: raw.EntryTimestamp,
			NotBefore:      raw.NotBefore,
			NotAfter:       raw.NotAfter,
			SerialNumber:   raw.SerialNumber,
			ResultCount:    raw.ResultCount,
		})
	}
	return records, nil
}

// DiscoverDomainCerts queries crt.sh for all certificates for a given domain.
// Returns a report containing all certificates and any errors encountered.
func DiscoverDomainCerts(ctx context.Context, config dnsfern.DiscoverDnsCertsConfig) (*dnsfern.DiscoverDnsCertsReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting certificate discovery", svc1log.SafeParam("domain", config.Domain))

	proxyConfig := osintConfig.ProxyConfigFromContext(ctx)
	if proxyConfig.HttpProxy != "" {
		config.HttpProxy = &proxyConfig.HttpProxy
	}
	if proxyConfig.SocksProxy != "" {
		config.SocksProxy = &proxyConfig.SocksProxy
	}

	baseURL := "https://crt.sh/?q=%s&output=json"
	escapedDomain := url.QueryEscape(config.Domain) // Properly escape the domain in the URL
	apiURL := fmt.Sprintf(baseURL, escapedDomain)

	// Make the HTTP request to crt.sh API
	client, err := osintConfig.NewHTTPClientFromContext(ctx, true, 0)
	if err != nil {
		errors = append(errors, err.Error())
		return &dnsfern.DiscoverDnsCertsReport{
			Config: &config,
			Result: &dnsfern.DiscoverDnsCertsResult{},
			Errors: errors,
		}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		errors = append(errors, err.Error())
		return &dnsfern.DiscoverDnsCertsReport{
			Config: &config,
			Result: &dnsfern.DiscoverDnsCertsResult{},
			Errors: errors,
		}, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn("Failed to query crt.sh API",
			svc1log.SafeParam("domain", config.Domain),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
		return &dnsfern.DiscoverDnsCertsReport{
			Config: &config,
			Result: &dnsfern.DiscoverDnsCertsResult{},
			Errors: errors,
		}, nil
	}
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil {
		errors = append(errors, cerr.Error())
	}
	if err != nil {
		errors = append(errors, err.Error())
	}

	records, err := parseCrtShCertificateRecords(body)
	if err != nil {
		errors = append(errors, err.Error())
		records = []*dnsfern.CertificateRecord{}
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
