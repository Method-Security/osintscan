package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utilsfern "github.com/Method-Security/osintscan/generated/go/utils"
	"github.com/miekg/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Cymru offers quality WHOIS and DNS based ASN services particularly for IP to ASN lookups

// IPASNLookup performs an ASN lookup using the Cymru DNS service
// Returns ASN information for the given IP address using raw DNS queries
func IPASNLookup(ctx context.Context, ip string) (string, error) {
	result, err := IPASNLookupDetailed(ctx, ip)
	if err != nil {
		return "", err
	}
	return result.Asn, nil
}

// IPASNLookupDetailed performs an ASN lookup using the Cymru DNS service
// Returns detailed ASN information for the given IP address using raw DNS queries
func IPASNLookupDetailed(ctx context.Context, ip string) (*utilsfern.CymruAsnResult, error) {
	log := svc1log.FromContext(ctx)

	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Determine if IPv4 or IPv6 and construct the query domain
	reversed, err := reverseIPBare(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to reverse IP: %w", err)
	}
	queryDomain := reversed + ".origin.asn.cymru.com"

	log.Debug("Performing Cymru ASN lookup", svc1log.SafeParam("ip", ip), svc1log.SafeParam("query_domain", queryDomain))

	// Create a resolver with reasonable timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	// Perform TXT record lookup
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	records, err := resolver.LookupTXT(ctx, queryDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup TXT record for %s: %w", queryDomain, err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no TXT records found for %s", queryDomain)
	}

	// Parse the first TXT record (Cymru typically returns one record)
	txtRecord := records[0]
	log.Debug("Cymru TXT record", svc1log.SafeParam("record", txtRecord))

	result, err := parseCymruTXTRecord(txtRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cymru TXT record '%s': %w", txtRecord, err)
	}

	return result, nil
}

// ReverseIPBare returns the reversed form used in PTR construction,
// but without the zone suffixes (".in-addr.arpa" / ".ip6.arpa") and trailing dot.
// Examples:
//
//	"216.90.108.31"        -> "31.108.90.216"
//	"2001:db8::1"          -> "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
func reverseIPBare(ip string) (string, error) {
	ptr, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	}

	// Normalize and strip the trailing dot and known reverse zones.
	s := strings.ToLower(ptr)
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, ".in-addr.arpa")
	s = strings.TrimSuffix(s, ".ip6.arpa")
	return s, nil
}

// parseCymruTXTRecord parses a Cymru TXT record response
// Format: "ASN | BGP Prefix | Country Code | Registry | Allocation Date"
// Example: "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
func parseCymruTXTRecord(record string) (*utilsfern.CymruAsnResult, error) {
	// Remove surrounding quotes if present
	record = strings.Trim(record, "\"")

	// Split by pipe character
	parts := strings.Split(record, "|")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid Cymru record format: expected at least 2 pipe-separated fields, got %d", len(parts))
	}

	// Parse ASN (first field)
	asnStr := strings.TrimSpace(parts[0])
	if asnStr == "" {
		return nil, fmt.Errorf("empty ASN field in Cymru record")
	}

	// Validate ASN is numeric and convert to standard ASN format
	if _, err := strconv.Atoi(asnStr); err != nil {
		return nil, fmt.Errorf("invalid ASN format '%s': %w", asnStr, err)
	}

	// Ensure ASN has AS prefix
	asn := asnStr
	if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
		asn = "AS" + asn
	}

	result := &utilsfern.CymruAsnResult{
		Asn: asn,
	}

	// Parse optional fields
	if len(parts) >= 2 {
		result.BgpPrefix = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		result.CountryCode = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		result.Registry = strings.TrimSpace(parts[3])
	}
	if len(parts) >= 5 {
		result.AllocDate = strings.TrimSpace(parts[4])
	}

	return result, nil
}

// GetASNDescription looks up the description for a given ASN using Cymru's asn.cymru.com zone
// Example query: dig +short AS23028.asn.cymru.com TXT
func GetASNDescription(ctx context.Context, asn string, timeout ...time.Duration) (string, error) {
	log := svc1log.FromContext(ctx)

	// Set default timeout to 5 if not provided
	actualTimeout := 5 * time.Second
	if len(timeout) > 0 && timeout[0] > 0 {
		actualTimeout = timeout[0]
	}

	// Normalize ASN format - ensure it starts with AS and is numeric
	normalizedASN, err := normalizeASN(asn)
	if err != nil {
		return "", fmt.Errorf("invalid ASN format '%s': %w", asn, err)
	}

	queryDomain := normalizedASN + ".asn.cymru.com"
	log.Debug("Looking up ASN description", svc1log.SafeParam("asn", normalizedASN), svc1log.SafeParam("query_domain", queryDomain))

	// Create a resolver with reasonable timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: actualTimeout * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	// Perform TXT record lookup
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	records, err := resolver.LookupTXT(ctx, queryDomain)
	if err != nil {
		return "", fmt.Errorf("failed to lookup TXT record for %s: %w", queryDomain, err)
	}

	if len(records) == 0 {
		return "", fmt.Errorf("no TXT records found for %s", queryDomain)
	}

	// Parse the description from the TXT record
	description := strings.Trim(records[0], "\"")
	// Cymru ASN description format is typically: "ASN | Country | Registry | Description"
	parts := strings.Split(description, "|")
	if len(parts) >= 4 {
		return strings.TrimSpace(parts[3]), nil
	}

	// If format is different, return the whole record
	return description, nil
}

// normalizeASN ensures ASN is in the correct format for Cymru queries
func normalizeASN(asn string) (string, error) {
	// Remove AS prefix and whitespace
	asnNum := strings.TrimSpace(strings.ToUpper(asn))
	asnNum = strings.TrimPrefix(asnNum, "AS")

	// Validate it's numeric
	if _, err := strconv.Atoi(asnNum); err != nil {
		return "", fmt.Errorf("ASN must be numeric, got '%s'", asnNum)
	}

	return "AS" + asnNum, nil
}

// IPASNLookupWithFallback tries Cymru DNS first, then falls back to whois if needed
func IPASNLookupWithFallback(ctx context.Context, ip string) (string, error) {
	// Try Cymru first
	asn, err := IPASNLookup(ctx, ip)
	if err == nil && asn != "" {
		return asn, nil
	}

	// Fall back to whois
	return WhoisASNWithContext(ctx, ip)
}
