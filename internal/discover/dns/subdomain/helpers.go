package subdomain

import (
	// standard
	"context"
	"fmt"
	"net"
	"strings"
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

	// If the error is NXDOMAIN or SERVFAIL, wildcard is NOT present
	return nil, nil
}

// detectWildcardForFullDomain tests if the given FQDN has wildcard DNS behavior
// This tests all parent domains of the given FQDN to see if any have wildcard records
func detectWildcardForFullDomain(ctx context.Context, fqdn string, resolver *net.Resolver) (*string, error) {
	// Extract all parent domains to test for wildcards
	// e.g., for "api.staging.app.example.com", test:
	// - "staging.app.example.com"
	// - "app.example.com"
	// - "example.com"
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid FQDN format for wildcard detection")
	}

	// If this is already a root domain, test it directly
	if len(parts) == 2 {
		return detectWildcardDNS(ctx, fqdn, resolver)
	}

	// Check each parent domain level for wildcards
	// Start from the immediate parent and work up to the root domain
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")

		// Skip if we've reached a single-part domain (invalid)
		if len(strings.Split(parentDomain, ".")) < 2 {
			continue
		}

		wildcardDomain, err := detectWildcardDNS(ctx, parentDomain, resolver)
		if err != nil {
			// Log the error but continue checking other parent domains
			continue
		}

		// If we found a wildcard, return it immediately
		if wildcardDomain != nil {
			return wildcardDomain, nil
		}
	}

	// No wildcards found in any parent domain
	return nil, nil
}
