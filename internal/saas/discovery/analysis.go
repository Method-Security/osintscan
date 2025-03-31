package saas

import (
	"log"
	"strings"

	"github.com/Method-Security/osintscan/generated/go/saas"
)

func analyzeSaasRequest(request *saas.SaasDiscoveryRequest, saasFingerprint *saas.SaasFingerprintEntry, selectedSsoFingerprints saas.SaasFingerprintFile, redirectedPage bool) *saas.SaaSDiscoveryFinding {
	// Initial validation
	// Note: If no response body or headers, or status code is not 200, return false
	if (request.ResponseBody == nil && request.ResponseHeaders == nil) ||
		(request.StatusCode == nil || *request.StatusCode != 200) {
		return nil
	}

	if saasFingerprint.FingerprintProfile == nil {
		log.Printf("[WARNING] No fingerprint profile found for %s", request.Url)
		return nil
	}

	// Initialize values
	companyPage := false
	finding := &saas.SaaSDiscoveryFinding{CompanyPage: &companyPage}

	// Check for indicators that the webpage is not actually a valid SaaS page
	// Note: Sometimes it will appear as a SaaS page but strings such as 'Not found' or '404' will be present
	if isFalsePositive(request.ResponseBody, &saasFingerprint.FingerprintProfile.PageNotFound) {
		return finding
	}

	// Check for SSO Page first
	// Note: SSO pages are only found if we have redirected to a new page from the intial SaaS page request
	if redirectedPage {
		for ssoCompany, ssoFingerprint := range selectedSsoFingerprints.Fingerprints {
			if ssoFingerprint.FingerprintProfile == nil {
				continue
			}

			if checkHeaders(request.ResponseHeaders, ssoFingerprint.FingerprintProfile.Headers) {
				finding.SsoPage = &ssoCompany
				break
			}
			// Check body if no header match
			if checkBody(request.ResponseBody, ssoFingerprint.FingerprintProfile.Body) {
				finding.SsoPage = &ssoCompany
				break
			}
		}
	}

	// Check for Company Page
	if finding.SsoPage == nil {
		if checkHeaders(request.ResponseHeaders, saasFingerprint.FingerprintProfile.Headers) {
			companyPage = true
			finding.CompanyPage = &companyPage
		}
		// Check for company match in body if not already found
		if !companyPage && checkBody(request.ResponseBody, saasFingerprint.FingerprintProfile.Body) {
			companyPage = true
			finding.CompanyPage = &companyPage
		}
	}

	return finding
}

// isFalsePositive is a helper function to check for false positives
func isFalsePositive(responseBody *string, notFoundPatterns *[]string) bool {
	if responseBody == nil {
		return false
	}

	if notFoundPatterns == nil {
		log.Printf("[WARNING] No 'not found patterns' found for %s", *responseBody)
		return false
	}

	bodyLower := strings.ToLower(*responseBody)
	for _, pattern := range *notFoundPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// checkHeaders is a helper function to check headers for matches
func checkHeaders(headers map[string]string, fingerprintHeaders map[string][]string) bool {
	if headers == nil || fingerprintHeaders == nil {
		return false
	}

	for fingerprintHeader, fingerprintValue := range fingerprintHeaders {
		// Normalize header key to lowercase for case-insensitive comparison
		for headerKey, headerValue := range headers {
			if strings.EqualFold(fingerprintHeader, headerKey) {
				// If the fingerprint value is empty or matches (case insensitive)
				if len(fingerprintValue) == 0 {
					return true
				}
				for _, fingerprintValue := range fingerprintValue {
					if strings.EqualFold(fingerprintValue, headerValue) {
						log.Printf("[DEBUG] Header match found for %s: %s", fingerprintHeader, headerValue)
						return true
					}
				}
			}
		}
	}
	return false
}

// checkBody is a helper function to check body for matches
func checkBody(responseBody *string, fingerprintBody []string) bool {
	if responseBody == nil {
		return false
	}

	bodyLower := strings.ToLower(*responseBody)
	for _, bodyEntry := range fingerprintBody {
		if strings.Contains(bodyLower, strings.ToLower(bodyEntry)) {
			log.Printf("[DEBUG] Body match found for %s: %s", bodyEntry, *responseBody)
			return true
		}
	}
	return false
}
