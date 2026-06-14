package cctld

import (
	"strings"
)

// parkingNameservers is a best-effort list of known parking NS patterns.
var parkingNameservers = []string{
	"sedo.com",
	"sedoparking.com",
	"domaincontrol.com", // GoDaddy parking
	"parkingcrew.net",
	"namebrightdns.com",
	"namecheaphosting.com",
	"registrar-servers.com", // Namecheap parking
	"hugedomains.com",
	"afternic.com",
	"bodis.com",
	"parking.hitfarm.com",
	"above.com",
}

// parkingTitleMarkers are substrings indicating a parked/for-sale domain.
var parkingTitleMarkers = []string{
	"for sale",
	"domain for sale",
	"parked",
	"buy this domain",
	"this domain",
	"domain parking",
	"under construction",
}

// ClassificationInput holds the per-candidate data used for classification.
type ClassificationInput struct {
	// RegistrableLabel is the SLD of the input domain (e.g. "acme" from "acme.com").
	RegistrableLabel string
	// CertSubject is the TLS cert subject DN, may be empty.
	CertSubject string
	// CertSANs is the list of TLS cert SANs, may be nil.
	CertSANs []string
	// SimilarityToBaseline is 0.0–1.0; negative means no baseline.
	SimilarityToBaseline float64
	// HasBaseline indicates whether a baseline was fetched.
	HasBaseline bool
	// Title is the page <title>, may be empty.
	Title string
	// HTTPStatus is the HTTP status code, 0 if no response.
	HTTPStatus int
	// BodyLen is the byte length of the response body.
	BodyLen int
	// NSRecords is the list of NS records for the candidate.
	NSRecords []string
}

// Classify returns a classification string for a candidate.
// The returned string matches one of the DiscoverDnsCctldClassification enum values.
func Classify(in ClassificationInput) string {
	label := strings.ToLower(in.RegistrableLabel)

	certMatchesInput := certContainsLabel(in.CertSubject, in.CertSANs, label)

	// Check for PARKED first — it is the weakest signal and should win over
	// UNRELATED but lose to explicit alt-region / impersonation signals.
	if isParked(in) {
		return "PARKED"
	}

	if in.HasBaseline {
		// With a baseline we can use content similarity.
		if certMatchesInput && in.SimilarityToBaseline >= 0.7 {
			return "LIKELY_LEGIT_ALT_REGION"
		}
		if !certMatchesInput && in.SimilarityToBaseline >= 0.5 {
			return "LIKELY_IMPERSONATION"
		}
	} else {
		// Without a baseline, rely on cert and title.
		if certMatchesInput {
			return "LIKELY_LEGIT_ALT_REGION"
		}
		// Title contains brand label but cert doesn't match
		if strings.Contains(strings.ToLower(in.Title), label) && !certMatchesInput {
			return "LIKELY_IMPERSONATION"
		}
	}

	return "UNRELATED"
}

// certContainsLabel returns true if the subject DN or any SAN contains label.
func certContainsLabel(subject string, sans []string, label string) bool {
	if strings.Contains(strings.ToLower(subject), label) {
		return true
	}
	for _, san := range sans {
		if strings.Contains(strings.ToLower(san), label) {
			return true
		}
	}
	return false
}

// isParked returns true if the candidate looks like a parked domain.
func isParked(in ClassificationInput) bool {
	// Tiny body with 200 OK is a parking indicator
	if in.HTTPStatus == 200 && in.BodyLen > 0 && in.BodyLen < 2048 {
		return true
	}

	// Check title for parking markers
	titleLower := strings.ToLower(in.Title)
	for _, marker := range parkingTitleMarkers {
		if strings.Contains(titleLower, marker) {
			return true
		}
	}

	// Check NS records for known parking providers
	for _, ns := range in.NSRecords {
		nsLower := strings.ToLower(ns)
		for _, parking := range parkingNameservers {
			if strings.Contains(nsLower, parking) {
				return true
			}
		}
	}

	return false
}
