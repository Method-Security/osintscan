package saas

import (
	"encoding/json"
	"fmt"
	"os"

	saasFern "github.com/Method-Security/osintscan/generated/go/saas"
)

// selectFingerprints enables the user to only look for specific SaaS companies or SSO login pages
func selectFingerprints(fingerprints saasFern.SaasFingerprintFile, companies []string) (saasFern.SaasFingerprintFile, []string) {
	if len(companies) == 0 {
		return fingerprints, nil
	}
	errs := []string{}
	filteredFingerprints := make(map[string]*saasFern.SaasFingerprintEntry)
	for _, company := range companies {
		if entry, exists := fingerprints.Fingerprints[company]; exists {
			filteredFingerprints[company] = entry
		} else {
			errs = append(errs, fmt.Sprintf("company %s not found in fingerprints", company))
		}
	}
	return saasFern.SaasFingerprintFile{Fingerprints: filteredFingerprints}, errs
}

// shouldAddRequest determines if a request should be included in results based on its findings and the successfulOnly flag
func shouldAddRequest(request *saasFern.SaasDiscoveryRequest, successfulOnly bool) bool {
	if request == nil {
		return false
	}

	if request.Findings == nil {
		return !successfulOnly
	}

	hasCompanyPage := request.Findings.CompanyPage != nil && *request.Findings.CompanyPage
	hasSsoPage := request.Findings.SsoPage != nil

	return hasCompanyPage || hasSsoPage || !successfulOnly
}

// UnmarshalFingerprints unmarshals the fingerprint files into a SaasFingerprintFile
func UnmarshalFingerprints(fingerprintFiles []string) saasFern.SaasFingerprintFile {
	result := saasFern.SaasFingerprintFile{
		Fingerprints: make(map[string]*saasFern.SaasFingerprintEntry),
	}
	// Read and unmarshal each fingerprint file
	for _, file := range fingerprintFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var fingerprints saasFern.SaasFingerprintFile
		if err := json.Unmarshal(data, &fingerprints); err != nil {
			continue
		}
		// Merge fingerprints from this file into result
		for k, v := range fingerprints.Fingerprints {
			result.Fingerprints[k] = v
		}
	}

	return result
}
