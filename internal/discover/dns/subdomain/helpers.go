package subdomain

import (
	// standard
	"context"
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

	// If the error is NXDOMAIN or SERVFAIL, wildcard is NOT present
	return nil, nil
}
