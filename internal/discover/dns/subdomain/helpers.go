package subdomain

import (
	// standard
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
)

// detectWildcardDNS tests multiple random high-entropy subdomains to check if a wildcard DNS record is present.
// Returns a non-nil slice if wildcard is detected, nil if no wildcard.
// Using multiple probes reduces the chance of a single false result.
func detectWildcardDNS(ctx context.Context, domain string, resolver *net.Resolver, wildcardChecks int) ([]string, error) {
	for i := 0; i < wildcardChecks; i++ {
		randomSubdomain, err := generateRandomSubdomain(domain)
		if err != nil {
			return nil, err
		}

		ips, err := resolver.LookupHost(ctx, randomSubdomain)
		if err == nil {
			// Random subdomain resolved - wildcard is present
			return ips, nil
		}

		if !isDNSNotFound(err) {
			// Non-NXDOMAIN error (timeout, SERVFAIL, etc.) - DNS is unreliable
			return nil, fmt.Errorf("DNS resolution failed during wildcard detection for %s: %v", randomSubdomain, err)
		}
		// NXDOMAIN - this probe says no wildcard, try next probe
	}

	// All probes returned NXDOMAIN - no wildcard
	return nil, nil
}

// generateRandomSubdomain generates a high-entropy subdomain with only letters (16 characters).
func generateRandomSubdomain(domain string) (string, error) {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomString := make([]byte, 16)
	for i := range randomString {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			return "", err
		}
		randomString[i] = letterBytes[n.Int64()]
	}

	return fmt.Sprintf("%s.%s", string(randomString), domain), nil
}

// isDNSNotFound checks if the error is specifically an NXDOMAIN (domain not found) error
// using proper DNS error type checking instead of fragile string matching
func isDNSNotFound(err error) bool {
	if err == nil {
		return false
	}

	// Check for DNS-specific error types
	if dnsError, ok := err.(*net.DNSError); ok {
		// NXDOMAIN: domain doesn't exist (safe to continue)
		// IsNotFound indicates the name does not exist
		return dnsError.IsNotFound
	}

	// For non-DNS errors, treat as failure (not NXDOMAIN)
	return false
}
