package subdomain

import (
	// standard
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"
)

const wildcardProbeDelay = 5 * time.Second

type wildcardDNSProfile struct {
	Addresses    map[string]struct{}
	CNAMETargets map[string]struct{}
}

func newWildcardDNSProfile() wildcardDNSProfile {
	return wildcardDNSProfile{
		Addresses:    map[string]struct{}{},
		CNAMETargets: map[string]struct{}{},
	}
}

func (p wildcardDNSProfile) HasAddresses() bool {
	return len(p.Addresses) > 0
}

func (p wildcardDNSProfile) HasCNAMETargets() bool {
	return len(p.CNAMETargets) > 0
}

// detectWildcardDNS tests multiple random high-entropy subdomains to check if a wildcard DNS record is present.
// Checks both A/AAAA records (via LookupHost) and CNAME records (via raw query) since a dangling
// wildcard CNAME won't resolve via LookupHost but still produces false positives in brute-force.
// Returns (true, true) for A/AAAA wildcard, (true, false) for CNAME-only wildcard, (false, false) for no wildcard.
func detectWildcardDNS(ctx context.Context, domain string, resolver *net.Resolver, wildcardChecks int, rawResolver string) (wildcardFound bool, wildcardA bool, err error) {
	profile, err := detectWildcardDNSProfile(ctx, domain, resolver, wildcardChecks, rawResolver)
	if err != nil {
		return false, false, err
	}
	return profile.HasAddresses() || profile.HasCNAMETargets(), profile.HasAddresses(), nil
}

func detectWildcardDNSProfile(ctx context.Context, domain string, resolver *net.Resolver, wildcardChecks int, rawResolver string) (wildcardDNSProfile, error) {
	return detectWildcardDNSProfileWithResolvers(ctx, domain, []*net.Resolver{resolver}, wildcardChecks, []string{rawResolver})
}

func detectWildcardDNSProfileWithResolvers(ctx context.Context, domain string, resolvers []*net.Resolver, wildcardChecks int, rawResolvers []string) (wildcardDNSProfile, error) {
	profile := newWildcardDNSProfile()
	if wildcardChecks <= 0 || len(resolvers) == 0 {
		return profile, nil
	}

	var firstTransientErr error
	nxdomainCount := 0

	for i := 0; i < wildcardChecks; i++ {
		randomSubdomain, err := generateRandomSubdomain(domain)
		if err != nil {
			return profile, err
		}

		resolver := resolvers[i%len(resolvers)]
		rawResolver := ""
		if len(rawResolvers) > 0 {
			rawResolver = rawResolvers[i%len(rawResolvers)]
		}

		addresses, err := resolver.LookupHost(ctx, randomSubdomain)
		if err == nil {
			// Random subdomain resolved via A/AAAA - wildcard is present
			for _, address := range addresses {
				profile.Addresses[address] = struct{}{}
			}
			for _, target := range lookupCNAMEs(randomSubdomain, rawResolver) {
				profile.CNAMETargets[target] = struct{}{}
			}
			return profile, nil
		}

		if !isDNSNotFound(err) {
			// Non-NXDOMAIN errors (timeouts, SERVFAIL, etc.) are common when
			// resolvers are under load. Keep probing so one bad packet does not
			// disable wildcard detection.
			if firstTransientErr == nil {
				firstTransientErr = fmt.Errorf("DNS resolution failed during wildcard detection for %s: %v", randomSubdomain, err)
			}
			if i < wildcardChecks-1 {
				select {
				case <-time.After(wildcardProbeDelay):
				case <-ctx.Done():
					return profile, ctx.Err()
				}
			}
			continue
		}

		nxdomainCount++

		// NXDOMAIN for A/AAAA - check if a wildcard CNAME exists (only when a raw resolver is provided)
		for _, target := range lookupCNAMEs(randomSubdomain, rawResolver) {
			profile.CNAMETargets[target] = struct{}{}
		}
		if profile.HasCNAMETargets() {
			return profile, nil
		}

		if i < wildcardChecks-1 {
			select {
			case <-time.After(wildcardProbeDelay):
			case <-ctx.Done():
				return profile, ctx.Err()
			}
		}
	}

	if nxdomainCount > 0 {
		return profile, nil
	}
	if firstTransientErr != nil {
		return profile, firstTransientErr
	}
	return profile, nil
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
