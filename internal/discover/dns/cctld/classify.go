package cctld

import (
	"strings"
)

// parkingNameservers is a best-effort list of dedicated parking / for-sale
// service NS patterns.
//
// Important: this list deliberately EXCLUDES default-registrar nameservers
// like `domaincontrol.com` (GoDaddy default) and `registrar-servers.com`
// (Namecheap default). Those NS hosts serve BOTH parked and fully-active
// sites — using them as a parking signal produces false PARKED
// classifications on legitimate small businesses that just happen to run
// on GoDaddy / Namecheap default DNS. Same for `namecheaphosting.com`,
// which is the actual hosting NS, not a parking NS.
var parkingNameservers = []string{
	"sedo.com",
	"sedoparking.com",
	"parkingcrew.net",
	"namebrightdns.com",
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
//
// Order of precedence: a matching cert (subject or SAN contains the input's
// registrable label) is the strongest single signal — a TLS cert binding
// requires registry / CA participation in a way that title text and body
// content do not. We short-circuit on that signal so that a low-similarity
// regional subsidiary (e.g. acme.de runs an entirely localized site whose
// vocabulary barely overlaps the global English baseline) is still
// classified as LIKELY_LEGIT_ALT_REGION rather than UNRELATED. Then we
// check the parked heuristics, which intentionally lose to an explicit
// cert match so a legitimate brand site that happens to be short is not
// mis-flagged. Finally we fall through to baseline similarity for
// impersonation detection.
func Classify(in ClassificationInput) string {
	label := strings.ToLower(in.RegistrableLabel)

	certMatchesInput := certContainsLabel(in.CertSubject, in.CertSANs, label)

	// 1. Cert match → strong LIKELY_LEGIT_ALT_REGION signal regardless of
	//    baseline / similarity. This also prevents the parked heuristic
	//    below from misclassifying a short legitimate page as PARKED.
	if certMatchesInput {
		return "LIKELY_LEGIT_ALT_REGION"
	}

	// 2. Parked / for-sale heuristics. Only meaningful when the cert did
	//    NOT match the input (the cert-match branch above already returned).
	if isParked(in) {
		return "PARKED"
	}

	// 3. Without a cert match, lean on baseline similarity (when available)
	//    or title containment (no baseline) to flag impersonation.
	if in.HasBaseline {
		if in.SimilarityToBaseline >= 0.5 {
			return "LIKELY_IMPERSONATION"
		}
	} else if containsAsLabel(strings.ToLower(in.Title), label) {
		// Title contains the brand label as a bounded token (not a
		// substring inside an unrelated word). Same rationale as cert
		// matching: a short brand like "go" would otherwise match inside
		// "going", "logo", etc. and produce false IMPERSONATION classifications.
		return "LIKELY_IMPERSONATION"
	}

	return "UNRELATED"
}

// certContainsLabel returns true if the subject DN or any SAN contains the
// input's registrable label as a *standalone DNS label* — i.e. bounded by
// the start of the string or by a non-label character (anything other than
// ASCII letter, digit, or hyphen).
//
// We need this stricter check because short brand labels (3-letter brands
// are common — "ibm", "ups", "ge") would otherwise substring-match inside
// unrelated names: a cert for `mygoshop.com` should NOT count as
// containing the brand `go`, and `acmegrid.io` should NOT count as
// containing the brand `acme` (the label there is `acmegrid`, not
// `acme`). The label-boundary check eliminates the highest-volume class
// of LIKELY_LEGIT_ALT_REGION false positives.
func certContainsLabel(subject string, sans []string, label string) bool {
	if label == "" {
		return false
	}
	if containsAsLabel(strings.ToLower(subject), label) {
		return true
	}
	for _, san := range sans {
		if containsAsLabel(strings.ToLower(san), label) {
			return true
		}
	}
	return false
}

// containsAsLabel reports whether label appears in s bounded by non-label
// characters on both sides. Label chars are ASCII letters / digits /
// hyphens (the same character class DNS uses for hostname labels). The
// search is byte-wise (callers lowercase the input), so this only works
// correctly for ASCII labels; punycode-normalized input is the supported
// case for this codepath.
func containsAsLabel(s, label string) bool {
	if label == "" || len(s) < len(label) {
		return false
	}
	for i := 0; i+len(label) <= len(s); i++ {
		if s[i:i+len(label)] != label {
			continue
		}
		if i > 0 && isLabelByte(s[i-1]) {
			continue
		}
		end := i + len(label)
		if end < len(s) && isLabelByte(s[end]) {
			continue
		}
		return true
	}
	return false
}

func isLabelByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '-':
		return true
	}
	return false
}

// isParked returns true if the candidate looks like a parked / for-sale
// domain. Each independent signal below either fires conclusively (title
// marker, dedicated parking NS) or contributes to the tiny-body heuristic.
//
// Note: tiny body alone is intentionally NOT enough — many legitimate
// small landing pages return a short body with status 200 (e.g. "Coming
// soon" pages for real future products, region-specific stub pages
// pointing back to the global site). We require tiny body AND a missing
// title to avoid those false positives. The cert-match short-circuit in
// Classify also prevents this from firing on real subsidiary pages.
func isParked(in ClassificationInput) bool {
	// Check title for parking markers
	titleLower := strings.ToLower(in.Title)
	for _, marker := range parkingTitleMarkers {
		if strings.Contains(titleLower, marker) {
			return true
		}
	}

	// Tiny body + no title combination — weaker but reasonable parking
	// signal in the absence of a positive title marker.
	if in.HTTPStatus == 200 && in.BodyLen > 0 && in.BodyLen < 2048 && titleLower == "" {
		return true
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
