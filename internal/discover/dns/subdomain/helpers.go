package subdomain

import (
	// standard
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
)

// detectWildcardDNS tests a random high-entropy subdomain to check if a wildcard DNS record is present.
// Returns the wildcard domain if detected, otherwise nil.
func detectWildcardDNS(ctx context.Context, domain string, resolver *net.Resolver) (*string, error) {
	// Generate a high-entropy 16-character random subdomain
	randomSubdomain, err := generateRandomSubdomain(domain)
	if err != nil {
		return nil, err
	}

	// Check if the random subdomain resolves
	_, err = resolver.LookupHost(ctx, randomSubdomain)

	// If no error, it resolved, meaning wildcard is present
	if err == nil {
		wildcardDomain := "*." + domain
		return &wildcardDomain, nil
	}

	// Check if it's specifically NXDOMAIN (domain doesn't exist)
	if isDNSNotFound(err) {
		// NXDOMAIN = no wildcard, safe to continue
		return nil, nil
	}

	// Any other DNS error = fail fast, don't continue with potentially unreliable results
	return nil, fmt.Errorf("DNS resolution failed during wildcard detection for %s: %v", randomSubdomain, err)
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
