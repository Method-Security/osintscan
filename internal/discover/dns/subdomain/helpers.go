package subdomain

import (
	// standard
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sort"
	"time"

	// External
	"github.com/miekg/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
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

type wildcardProbeStatus string

const (
	wildcardProbePositive wildcardProbeStatus = "positive"
	wildcardProbeNegative wildcardProbeStatus = "negative"
	wildcardProbeUnknown  wildcardProbeStatus = "unknown"
)

type wildcardProbeOutcome struct {
	status                          wildcardProbeStatus
	unknownDueOnlyToResolverFailure bool
	degradedByResolverFailures      bool
}

type wildcardDetectionStats struct {
	positiveResponses         int
	negativeResponses         int
	unknownResponses          int
	resolverFailures          int
	resolverDisagreements     int
	unprovenNegatives         int
	negativeProbes            int
	unknownProbes             int
	failureOnlyUnknownProbes  int
	degradedNegativeConsensus bool
}

func (s wildcardDetectionStats) log(log svc1log.Logger, domain string, status string) {
	log.Info("Wildcard DNS detection summary",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("status", status),
		svc1log.SafeParam("wildcard_positive_responses", s.positiveResponses),
		svc1log.SafeParam("wildcard_negative_responses", s.negativeResponses),
		svc1log.SafeParam("wildcard_unknown_responses", s.unknownResponses),
		svc1log.SafeParam("resolver_failures", s.resolverFailures),
		svc1log.SafeParam("resolver_disagreements", s.resolverDisagreements),
		svc1log.SafeParam("unproven_negative_responses", s.unprovenNegatives),
		svc1log.SafeParam("wildcard_negative_probes", s.negativeProbes),
		svc1log.SafeParam("wildcard_unknown_probes", s.unknownProbes),
		svc1log.SafeParam("failure_only_unknown_probes", s.failureOnlyUnknownProbes),
		svc1log.SafeParam("degraded_negative_consensus", s.degradedNegativeConsensus))
}

func detectWildcardDNSProfileWithResolvers(ctx context.Context, domain string, wildcardChecks int, rawResolvers []string) (wildcardDNSProfile, error) {
	log := svc1log.FromContext(ctx)
	profile := newWildcardDNSProfile()
	rawResolvers = nonEmptyRawResolvers(rawResolvers)
	if wildcardChecks <= 0 {
		log.Info("Skipping wildcard DNS detection",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("wildcard_checks", wildcardChecks),
			svc1log.SafeParam("resolver_count", len(rawResolvers)))
		return profile, nil
	}
	if len(rawResolvers) == 0 {
		return profile, fmt.Errorf("wildcard DNS detection requires at least one raw DNS resolver")
	}

	log.Info("Starting wildcard DNS detection",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("wildcard_checks", wildcardChecks),
		svc1log.SafeParam("resolver_count", len(rawResolvers)))

	stats := wildcardDetectionStats{}
	var firstUnknownErr error

	for i := 0; i < wildcardChecks; i++ {
		randomSubdomain, err := generateRandomSubdomain(domain)
		if err != nil {
			return profile, err
		}

		log.Info("Running wildcard DNS probe",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("probe", i+1),
			svc1log.SafeParam("wildcard_checks", wildcardChecks),
			svc1log.SafeParam("random_subdomain", randomSubdomain),
			svc1log.SafeParam("resolver_count", len(rawResolvers)))

		resolverOutcomes := make([]wildcardProbeOutcome, 0, len(rawResolvers))
		for resolverIndex, rawResolver := range rawResolvers {
			outcome, resolverProfile, probeErr := probeWildcardDNSResolver(ctx, randomSubdomain, rawResolver, &stats)
			resolverOutcomes = append(resolverOutcomes, outcome)
			mergeWildcardDNSProfile(&profile, resolverProfile)
			if probeErr != nil && firstUnknownErr == nil {
				firstUnknownErr = probeErr
			}

			log.Info("Wildcard DNS resolver probe completed",
				svc1log.SafeParam("domain", domain),
				svc1log.SafeParam("random_subdomain", randomSubdomain),
				svc1log.SafeParam("probe", i+1),
				svc1log.SafeParam("resolver_index", resolverIndex),
				svc1log.SafeParam("resolver", rawResolver),
				svc1log.SafeParam("status", outcome.status),
				svc1log.SafeParam("unknown_due_only_to_resolver_failure", outcome.unknownDueOnlyToResolverFailure),
				svc1log.SafeParam("degraded_by_resolver_failures", outcome.degradedByResolverFailures),
				svc1log.SafeParam("addresses", setKeys(resolverProfile.Addresses)),
				svc1log.SafeParam("cname_targets", setKeys(resolverProfile.CNAMETargets)),
				svc1log.SafeParam("error", errorString(probeErr)))

			if outcome.status == wildcardProbePositive {
				if hasWildcardResolverDisagreement(resolverOutcomes) {
					stats.resolverDisagreements++
				}
				stats.log(log, domain, "present")
				return profile, nil
			}
		}

		if hasWildcardResolverDisagreement(resolverOutcomes) {
			stats.resolverDisagreements++
		}

		probeOutcome := aggregateWildcardProbeOutcomes(resolverOutcomes)
		switch probeOutcome.status {
		case wildcardProbeNegative:
			stats.negativeProbes++
			if probeOutcome.degradedByResolverFailures {
				stats.degradedNegativeConsensus = true
			}
		case wildcardProbeUnknown:
			stats.unknownProbes++
			if probeOutcome.unknownDueOnlyToResolverFailure {
				stats.failureOnlyUnknownProbes++
			}
		}

		log.Info("Wildcard DNS probe completed",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("random_subdomain", randomSubdomain),
			svc1log.SafeParam("probe", i+1),
			svc1log.SafeParam("wildcard_checks", wildcardChecks),
			svc1log.SafeParam("status", probeOutcome.status),
			svc1log.SafeParam("unknown_due_only_to_resolver_failure", probeOutcome.unknownDueOnlyToResolverFailure),
			svc1log.SafeParam("degraded_by_resolver_failures", probeOutcome.degradedByResolverFailures))

		if i < wildcardChecks-1 {
			if err := waitForNextWildcardProbe(ctx); err != nil {
				return profile, err
			}
		}
	}

	if stats.negativeProbes > 0 && stats.unknownProbes == stats.failureOnlyUnknownProbes {
		stats.degradedNegativeConsensus = stats.degradedNegativeConsensus || stats.unknownProbes > 0
		stats.log(log, domain, "absent")
		return profile, nil
	}
	if stats.unknownProbes > 0 {
		stats.log(log, domain, "unknown")
		return profile, fmt.Errorf(
			"wildcard DNS detection inconclusive for %s: %d/%d probes were unknown; positive_responses=%d negative_responses=%d unknown_responses=%d resolver_failures=%d resolver_disagreements=%d unproven_negative_responses=%d; first unknown: %v",
			domain,
			stats.unknownProbes,
			wildcardChecks,
			stats.positiveResponses,
			stats.negativeResponses,
			stats.unknownResponses,
			stats.resolverFailures,
			stats.resolverDisagreements,
			stats.unprovenNegatives,
			firstUnknownErr,
		)
	}

	stats.log(log, domain, "unknown")
	return profile, fmt.Errorf("wildcard DNS detection inconclusive for %s: no definitive wildcard or NXDOMAIN consensus", domain)
}

func probeWildcardDNSResolver(ctx context.Context, host string, rawResolver string, stats *wildcardDetectionStats) (wildcardProbeOutcome, wildcardDNSProfile, error) {
	profile := newWildcardDNSProfile()
	negativeResponseCount := 0
	unknownResponseCount := 0
	unknownDueOnlyToResolverFailure := true
	var firstUnknownErr error

	for _, questionType := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		status, responseProfile, resolverFailure, unprovenNegative, err := queryWildcardDNSRecord(ctx, host, rawResolver, questionType)
		mergeWildcardDNSProfile(&profile, responseProfile)

		switch status {
		case wildcardProbePositive:
			stats.positiveResponses++
			return wildcardProbeOutcome{status: wildcardProbePositive}, profile, nil
		case wildcardProbeNegative:
			stats.negativeResponses++
			negativeResponseCount++
		case wildcardProbeUnknown:
			stats.unknownResponses++
			unknownResponseCount++
			if resolverFailure {
				stats.resolverFailures++
			} else {
				unknownDueOnlyToResolverFailure = false
			}
			if unprovenNegative {
				stats.unprovenNegatives++
			}
			if firstUnknownErr == nil {
				firstUnknownErr = err
			}
		}
	}

	if negativeResponseCount > 0 && unknownDueOnlyToResolverFailure {
		return wildcardProbeOutcome{
			status:                     wildcardProbeNegative,
			degradedByResolverFailures: unknownResponseCount > 0,
		}, profile, nil
	}
	return wildcardProbeOutcome{
		status:                          wildcardProbeUnknown,
		unknownDueOnlyToResolverFailure: unknownResponseCount > 0 && unknownDueOnlyToResolverFailure,
	}, profile, firstUnknownErr
}

func queryWildcardDNSRecord(ctx context.Context, host string, rawResolver string, questionType uint16) (wildcardProbeStatus, wildcardDNSProfile, bool, bool, error) {
	profile := newWildcardDNSProfile()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), questionType)
	msg.RecursionDesired = true

	resp, err := exchangeDNSWithFallbackContext(ctx, msg, rawResolver)
	if err != nil {
		return wildcardProbeUnknown, profile, true, false, fmt.Errorf("DNS %s query to %s failed: %w", dns.TypeToString[questionType], rawResolver, err)
	}
	if resp == nil {
		return wildcardProbeUnknown, profile, true, false, fmt.Errorf("DNS %s query to %s returned no response", dns.TypeToString[questionType], rawResolver)
	}
	if resp.Truncated {
		return wildcardProbeUnknown, profile, true, false, fmt.Errorf("DNS %s query to %s remained truncated after TCP fallback", dns.TypeToString[questionType], rawResolver)
	}

	for _, answer := range resp.Answer {
		switch typedAnswer := answer.(type) {
		case *dns.A:
			profile.Addresses[typedAnswer.A.String()] = struct{}{}
		case *dns.AAAA:
			profile.Addresses[typedAnswer.AAAA.String()] = struct{}{}
		case *dns.CNAME:
			profile.CNAMETargets[normalizeDNSName(typedAnswer.Target)] = struct{}{}
		}
	}
	if profile.HasAddresses() || profile.HasCNAMETargets() {
		return wildcardProbePositive, profile, false, false, nil
	}

	switch resp.Rcode {
	case dns.RcodeNameError:
		if hasSOAAuthority(resp, host) {
			return wildcardProbeNegative, profile, false, false, nil
		}
		return wildcardProbeUnknown, profile, false, true, fmt.Errorf("DNS %s query to %s returned NXDOMAIN without SOA authority proof", dns.TypeToString[questionType], rawResolver)
	case dns.RcodeSuccess:
		return wildcardProbeUnknown, profile, false, false, fmt.Errorf("DNS %s query to %s returned NOERROR with no A, AAAA, or CNAME answers", dns.TypeToString[questionType], rawResolver)
	default:
		return wildcardProbeUnknown, profile, true, false, fmt.Errorf("DNS %s query to %s returned %s", dns.TypeToString[questionType], rawResolver, dns.RcodeToString[resp.Rcode])
	}
}

func hasSOAAuthority(resp *dns.Msg, host string) bool {
	queryName := dns.Fqdn(host)
	for _, authority := range resp.Ns {
		soa, ok := authority.(*dns.SOA)
		if ok && dns.IsSubDomain(soa.Hdr.Name, queryName) {
			return true
		}
	}
	return false
}

func mergeWildcardDNSProfile(dst *wildcardDNSProfile, src wildcardDNSProfile) {
	for address := range src.Addresses {
		dst.Addresses[address] = struct{}{}
	}
	for target := range src.CNAMETargets {
		dst.CNAMETargets[target] = struct{}{}
	}
}

func aggregateWildcardProbeOutcomes(outcomes []wildcardProbeOutcome) wildcardProbeOutcome {
	if len(outcomes) == 0 {
		return wildcardProbeOutcome{status: wildcardProbeUnknown}
	}

	hasNegative := false
	unknownDueOnlyToResolverFailure := true
	unknownCount := 0
	degradedByResolverFailures := false
	for _, outcome := range outcomes {
		if outcome.degradedByResolverFailures {
			degradedByResolverFailures = true
		}
		switch outcome.status {
		case wildcardProbePositive:
			return wildcardProbeOutcome{status: wildcardProbePositive}
		case wildcardProbeNegative:
			hasNegative = true
		case wildcardProbeUnknown:
			unknownCount++
			if !outcome.unknownDueOnlyToResolverFailure {
				unknownDueOnlyToResolverFailure = false
			}
		}
	}

	if hasNegative && unknownDueOnlyToResolverFailure {
		return wildcardProbeOutcome{
			status:                     wildcardProbeNegative,
			degradedByResolverFailures: degradedByResolverFailures || unknownCount > 0,
		}
	}
	return wildcardProbeOutcome{
		status:                          wildcardProbeUnknown,
		unknownDueOnlyToResolverFailure: unknownCount > 0 && unknownDueOnlyToResolverFailure,
	}
}

func hasWildcardResolverDisagreement(outcomes []wildcardProbeOutcome) bool {
	if len(outcomes) < 2 {
		return false
	}
	firstStatus := outcomes[0].status
	for _, outcome := range outcomes[1:] {
		if outcome.status != firstStatus {
			return true
		}
	}
	return false
}

func waitForNextWildcardProbe(ctx context.Context) error {
	select {
	case <-time.After(wildcardProbeDelay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func nonEmptyRawResolvers(rawResolvers []string) []string {
	resolvers := make([]string, 0, len(rawResolvers))
	for _, resolver := range rawResolvers {
		if resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}
	return resolvers
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func setKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
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
