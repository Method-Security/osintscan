// Package cctld implements ccTLD pivot discovery: given a base FQDN, it
// tests whether the same registrable label resolves under a set of
// country-code TLDs. It is invoked from the active subdomain discovery
// flow and contributes any resolved FQDNs to that flow's output, so the
// downstream processor handles ccTLD-discovered FQDNs the same way it
// handles wordlist-discovered subdomains.
package cctld

// DefaultCcTlds is the curated default list of country-code TLD labels
// the active subdomain discovery tests for ccTLD pivots when the caller
// does not provide an explicit list.
//
// The set blends two operator concerns from the parent OSINT content pack:
//
//  1. Nation-state-relevant zones (RU, CN, IR, KP, BY, SU) plus the
//     IDN siblings most commonly cited for impersonation infrastructure
//     (.рф / .中国 / .中國 / .ايران, expressed here in punycode so the
//     source file is plain ASCII; idna normalization is performed at
//     lookup time on each candidate).
//
//  2. The major economic ccTLDs where regional subsidiaries and
//     lookalike registrations most often appear — Europe, Asia, Middle
//     East, Americas, Oceania, Africa.
//
// Callers can override the entire list via the `cctlds` Fern config
// field (which maps to the `--cctlds` CLI flag and the `cctlds`
// Ontology parameter). Passing an empty list reverts to this default.
var DefaultCcTlds = []string{
	// APT-relevant ASCII ccTLDs
	"ru", "cn", "ir", "kp", "by", "su",
	// APT-relevant IDN ccTLDs (punycode)
	"xn--p1ai",        // .рф (Russia)
	"xn--fiqs8s",      // .中国 (China, simplified)
	"xn--fiqz9s",      // .中國 (China, traditional)
	"xn--mgba3a4f16a", // .ایران (Iran)
	// Europe
	"uk", "de", "fr", "it", "es", "nl", "be", "ch", "se", "no",
	"dk", "fi", "pl", "cz", "ie", "at", "pt", "gr", "ro", "hu",
	// Asia
	"jp", "kr", "in", "sg", "hk", "tw", "my", "th", "vn", "id", "ph",
	// Middle East
	"ae", "sa", "il", "tr",
	// Americas
	"ca", "br", "mx", "ar", "cl", "co", "us",
	// Oceania & Africa
	"au", "nz", "za", "ng", "ke", "eg",
}
