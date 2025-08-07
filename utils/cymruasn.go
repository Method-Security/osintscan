package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Cymru offers quality WHOIS and DNS based ASN services particularly for IP to ASN lookups

// CymruASNResult represents the parsed result from a Cymru ASN lookup
type CymruASNResult struct {
	ASN         string
	BGPPrefix   string
	CountryCode string
	Registry    string
	AllocDate   string
}

// IPASNLookup performs an ASN lookup using the Cymru DNS service
// Returns ASN information for the given IP address using raw DNS queries
func IPASNLookup(ctx context.Context, ip string) (string, error) {
	result, err := IPASNLookupDetailed(ctx, ip)
	if err != nil {
		return "", err
	}
	return result.ASN, nil
}

// IPASNLookupDetailed performs an ASN lookup using the Cymru DNS service
// Returns detailed ASN information for the given IP address using raw DNS queries
func IPASNLookupDetailed(ctx context.Context, ip string) (*CymruASNResult, error) {
	log := svc1log.FromContext(ctx)

	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Determine if IPv4 or IPv6 and construct the query domain
	var queryDomain string
	if parsedIP.To4() != nil {
		// IPv4 - reverse the octets
		queryDomain = reverseIPv4(ip) + ".origin.asn.cymru.com"
	} else {
		// IPv6 - reverse the nibbles
		queryDomain = reverseIPv6(ip) + ".origin6.asn.cymru.com"
	}

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

// reverseIPv4 reverses the octets of an IPv4 address
// Example: 216.90.108.31 becomes 31.108.90.216
func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip // Return original if not valid IPv4 format
	}

	// Reverse the order
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

// reverseIPv6 reverses the nibbles of an IPv6 address for PTR-style DNS queries
// Example: 2001:db8::1 becomes 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
func reverseIPv6(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip
	}

	// Get the 16-byte representation of IPv6
	ipv6Bytes := parsedIP.To16()
	if ipv6Bytes == nil {
		return ip
	}

	// Convert each byte to two hex digits and reverse the nibbles
	var nibbles []string
	for i := len(ipv6Bytes) - 1; i >= 0; i-- {
		b := ipv6Bytes[i]
		// Add the lower nibble first (reverse nibble order within byte)
		nibbles = append(nibbles, fmt.Sprintf("%x", b&0x0f))
		// Add the upper nibble
		nibbles = append(nibbles, fmt.Sprintf("%x", (b&0xf0)>>4))
	}

	return strings.Join(nibbles, ".")
}

// parseCymruTXTRecord parses a Cymru TXT record response
// Format: "ASN | BGP Prefix | Country Code | Registry | Allocation Date"
// Example: "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
func parseCymruTXTRecord(record string) (*CymruASNResult, error) {
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

	result := &CymruASNResult{
		ASN: asn,
	}

	// Parse optional fields
	if len(parts) >= 2 {
		result.BGPPrefix = strings.TrimSpace(parts[1])
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
func GetASNDescription(ctx context.Context, asn string) (string, error) {
	log := svc1log.FromContext(ctx)

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
