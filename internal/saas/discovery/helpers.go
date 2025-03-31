package saas

import (
	"github.com/Method-Security/osintscan/generated/go/saas"
)

// selectFingerprints enables the user to only look for specific SaaS companies or SSO login pages
func selectFingerprints(fingerprints saas.SaasFingerprintFile, saasCompanies []string) saas.SaasFingerprintFile {
	if saasCompanies == nil {
		return fingerprints
	}
	filteredFingerprints := make(map[string]*saas.SaasFingerprintEntry)
	for _, company := range saasCompanies {
		if entry, exists := fingerprints.Fingerprints[company]; exists {
			filteredFingerprints[company] = entry
		}
	}
	return saas.SaasFingerprintFile{Fingerprints: filteredFingerprints}
}

// shouldAddRequest determines if a request should be included in results based on its findings and the successfulOnly flag
func shouldAddRequest(request *saas.SaasDiscoveryRequest, successfulOnly bool) bool {
	if request.Findings == nil {
		return !successfulOnly
	}

	hasCompanyPage := request.Findings.CompanyPage != nil && *request.Findings.CompanyPage
	hasSsoPage := request.Findings.SsoPage != nil

	return hasCompanyPage || hasSsoPage || !successfulOnly
}
