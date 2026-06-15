// Package cctld implements ccTLD pivot discovery: given an input domain it
// constructs <base>.<tld> apex candidates for each ccTLD in the supplied list
// or preset, resolves DNS records, and returns structured per-candidate results.
package cctld

import (
	"context"
	"crypto/rand"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	// Internal
	"github.com/Method-Security/osintscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/idna"
)

// dnsCallTimeout derives the per-DNS-call deadline from config.Timeout
// (which the CLI documents as the per-request timeout in milliseconds
// for DNS calls). Returns 0 if the caller passed a nonpositive value,
// in which case callers should fall through to the parent context with
// no extra deadline.
func dnsCallTimeout(timeoutMs int) time.Duration {
	if timeoutMs <= 0 {
		return 0
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

// withDNSDeadline returns a child context bounded by the per-call
// timeout, or the parent context unchanged if no timeout is configured.
// The caller MUST defer the returned cancel func — when no deadline was
// applied we still return a no-op cancel so call sites stay simple.
func withDNSDeadline(parent context.Context, timeoutMs int) (context.Context, context.CancelFunc) {
	d := dnsCallTimeout(timeoutMs)
	if d == 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}

// PivotCcTLD is the main entry point.  It orchestrates the full ccTLD pivot
// workflow and returns a structured report.
func PivotCcTLD(ctx context.Context, config dnsfern.DiscoverDnsCctldConfig) dnsfern.DiscoverDnsCctldReport {
	log := svc1log.FromContext(ctx)
	errs := []string{}

	// Normalize the input domain: trim leading/trailing whitespace and a
	// trailing dot so that "acme.com." and " acme.com " both parse correctly.
	domain := strings.TrimSuffix(strings.TrimSpace(config.Domain), ".")
	if domain == "" {
		return buildReport(config, nil, []string{"domain is required and must not be empty"})
	}

	// Resolve the registrable label (SLD) from the input domain.
	// publicsuffix.Parse returns a *DomainName with .SLD == "acme" for "acme.com"
	// and also handles multi-label TLDs like "acme.co.uk" → SLD="acme".
	dn, err := publicsuffix.Parse(domain)
	if err != nil {
		// Fall back to splitting on the first dot. We must populate TLD
		// from the remainder too — otherwise inputApex collapses to just
		// the base label, and the later EqualFold-against-inputApex skip
		// can't recognize the input domain itself and the sweep ends up
		// re-discovering it as a ccTLD candidate.
		parts := strings.SplitN(domain, ".", 2)
		fallback := &publicsuffix.DomainName{SLD: parts[0]}
		if len(parts) == 2 {
			fallback.TLD = parts[1]
		}
		dn = fallback
	}
	// IDN-normalize the base label so a Unicode-spelled input (e.g.
	// "акмe.com" with a Cyrillic "a") becomes punycode before we build
	// candidate FQDNs. Without this, only the ccTLD labels get normalized
	// and "акмe.ru" never resolves because the base half is still Unicode.
	rawBase := strings.ToLower(dn.SLD)
	baseLabel, baseErr := idna.Lookup.ToASCII(rawBase)
	if baseErr != nil || baseLabel == "" {
		// Fall back to the raw lowercase label; lookups will likely fail
		// for non-ASCII inputs but the operator still sees the attempt.
		baseLabel = rawBase
	}
	if baseLabel == "" {
		return buildReport(config, nil, []string{"could not derive base label from domain: " + domain})
	}
	inputApex := baseLabel
	if dn.TLD != "" {
		tldNorm, _ := idna.Lookup.ToASCII(strings.ToLower(dn.TLD))
		if tldNorm == "" {
			tldNorm = strings.ToLower(dn.TLD)
		}
		inputApex = baseLabel + "." + tldNorm
	}

	log.Info("Starting ccTLD pivot",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("base_label", baseLabel),
		svc1log.SafeParam("input_apex", inputApex))

	// Gather TLD list.
	tlds, tldErrs := resolveTLDs(config)
	errs = append(errs, tldErrs...)
	if len(tlds) == 0 {
		errs = append(errs, "no TLDs to probe")
		return buildReport(config, nil, errs)
	}

	// IDN-normalize all TLDs.
	profile := idna.Lookup
	normalizedTLDs := make([]string, 0, len(tlds))
	for _, tld := range tlds {
		ascii, err := profile.ToASCII(tld)
		if err != nil {
			// Keep the raw label; the DNS stack will reject it gracefully.
			ascii = tld
		}
		normalizedTLDs = append(normalizedTLDs, strings.ToLower(ascii))
	}

	// Build resolver pool.
	resolvers := utils.GetResolvers(config.DnsResolvers, log)

	// Fan-out over TLDs.
	type result struct {
		candidate *dnsfern.DiscoverDnsCctldCandidate
		err       string
	}

	threads := config.Threads
	if threads <= 0 {
		threads = 1
	}
	semaphore := make(chan struct{}, threads)
	resultCh := make(chan result, len(normalizedTLDs))
	var wg sync.WaitGroup
	var resolverIndex int64

	for _, tld := range normalizedTLDs {
		// Respect context cancellation before queuing new work.
		if ctx.Err() != nil {
			break
		}
		tld := tld // capture
		wg.Add(1)
		semaphore <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Round-robin a resolver per candidate so a slow resolver
			// can't sequentially block the whole sweep.
			var resolver *net.Resolver
			if len(resolvers) > 0 {
				idx := atomic.AddInt64(&resolverIndex, 1) - 1
				resolver = resolvers[idx%int64(len(resolvers))]
			}
			candidate, candidateErr := processCandidateTLD(ctx, baseLabel, tld, inputApex, config, resolver)
			r := result{}
			if candidateErr != "" {
				r.err = candidateErr
			}
			if candidate != nil {
				r.candidate = candidate
			}
			resultCh <- r
		}()
	}

	// Wait for all goroutines then close channel.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var candidates []*dnsfern.DiscoverDnsCctldCandidate
	for r := range resultCh {
		if r.err != "" {
			errs = append(errs, r.err)
		}
		if r.candidate != nil {
			candidates = append(candidates, r.candidate)
		}
	}

	log.Info("Completed ccTLD pivot",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("tld_count", len(normalizedTLDs)),
		svc1log.SafeParam("resolved_count", len(candidates)),
		svc1log.SafeParam("error_count", len(errs)))

	return buildReport(config, candidates, errs)
}

// resolveTLDs gathers the final TLD list from config (explicit list and/or preset).
func resolveTLDs(config dnsfern.DiscoverDnsCctldConfig) ([]string, []string) {
	errs := []string{}
	seen := map[string]struct{}{}
	var tlds []string

	addUnique := func(list []string) {
		for _, t := range list {
			// Accept both ".ru" and "ru" from --cctlds; otherwise the
			// candidate FQDN ends up as "acme..ru" and never resolves.
			t = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(t)), ".")
			if t == "" {
				continue
			}
			if _, ok := seen[t]; !ok {
				seen[t] = struct{}{}
				tlds = append(tlds, t)
			}
		}
	}

	if len(config.Cctlds) > 0 {
		addUnique(config.Cctlds)
	}

	if config.CctldsPreset != nil {
		presetName := string(*config.CctldsPreset)
		presetTLDs, err := TLDsForPreset(presetName)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			addUnique(presetTLDs)
		}
	}

	return tlds, errs
}

// processCandidateTLD resolves a single <base>.<tld> candidate.
// Returns nil candidate (and possibly an error string) if the candidate does not resolve.
func processCandidateTLD(
	ctx context.Context,
	baseLabel string,
	tld string,
	inputApex string,
	config dnsfern.DiscoverDnsCctldConfig,
	resolver *net.Resolver,
) (*dnsfern.DiscoverDnsCctldCandidate, string) {
	fqdn := baseLabel + "." + tld

	// Skip the candidate that IS the input's own apex.
	if strings.EqualFold(fqdn, inputApex) {
		return nil, ""
	}

	if resolver == nil {
		return nil, "no DNS resolver available for " + fqdn
	}

	log := svc1log.FromContext(ctx)

	// Main A/AAAA lookup.  We pass resolved IPs into detectCandidateWildcard
	// so it can reuse them without a redundant apex call.
	// If the name has no A/AAAA records but does publish NS or MX (e.g. a
	// mail-only apex domain), we still want to surface it — so we only
	// skip immediately on a true NXDOMAIN; other errors cause a fallthrough
	// to the NS/MX lookups below.
	dnsCtx, cancel := withDNSDeadline(ctx, config.Timeout)
	defer cancel()
	ips, lookupErr := resolver.LookupHost(dnsCtx, fqdn)
	if lookupErr != nil && isDNSNotFound(lookupErr) {
		// True NXDOMAIN: the name does not exist in DNS at all — skip.
		return nil, ""
	}
	// For any other LookupHost error ips will be nil; we continue to
	// attempt NS/MX lookups and skip only if those also return nothing.

	// Wildcard detection is only meaningful when we have IPs to compare
	// against. detectCandidateWildcard already guards len(baseIPs)==0.
	wildcardDetected := detectCandidateWildcard(ctx, fqdn, ips, resolver, config.Timeout)

	// Separate A and AAAA.
	var aRecords, aaaaRecords []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			aRecords = append(aRecords, ip)
		} else {
			aaaaRecords = append(aaaaRecords, ip)
		}
	}

	log.Info("Resolved ccTLD candidate",
		svc1log.SafeParam("fqdn", fqdn),
		svc1log.SafeParam("a_count", len(aRecords)),
		svc1log.SafeParam("aaaa_count", len(aaaaRecords)))

	// Resolve NS records (with the same per-call deadline).
	nsRecords := lookupNS(ctx, fqdn, resolver, config.Timeout)
	// Resolve MX records (with the same per-call deadline).
	mxRecords := lookupMX(ctx, fqdn, resolver, config.Timeout)

	// If the initial A/AAAA lookup failed (non-NXDOMAIN) and NS/MX also
	// returned nothing, there is no evidence this apex domain is active —
	// report the DNS error and skip.
	if lookupErr != nil && len(nsRecords) == 0 && len(mxRecords) == 0 {
		return nil, "DNS resolution error for " + fqdn + ": " + lookupErr.Error()
	}

	candidate := &dnsfern.DiscoverDnsCctldCandidate{
		Tld:      tld,
		Fqdn:     fqdn,
		Wildcard: wildcardDetected,
	}

	if len(aRecords) > 0 {
		candidate.Ips = aRecords
	}
	if len(aaaaRecords) > 0 {
		candidate.Aaaa = aaaaRecords
	}
	if len(nsRecords) > 0 {
		candidate.Ns = nsRecords
	}
	if len(mxRecords) > 0 {
		candidate.Mx = mxRecords
	}

	return candidate, ""
}

// detectCandidateWildcard checks whether the registry zone for this candidate
// exhibits wildcard behavior. baseIPs is the already-resolved IP set for fqdn,
// passed in to avoid a redundant apex lookup.
func detectCandidateWildcard(ctx context.Context, fqdn string, baseIPs []string, resolver *net.Resolver, timeoutMs int) bool {
	if resolver == nil || len(baseIPs) == 0 {
		return false
	}

	baseSet := map[string]struct{}{}
	for _, ip := range baseIPs {
		baseSet[ip] = struct{}{}
	}

	// Probe a random label under the FQDN.
	randomFQDN, err := generateRandomLabel(fqdn)
	if err != nil {
		return false
	}
	randCtx, randCancel := withDNSDeadline(ctx, timeoutMs)
	defer randCancel()
	randomIPs, err := resolver.LookupHost(randCtx, randomFQDN)
	if err != nil || len(randomIPs) == 0 {
		return false
	}

	// If the random label resolves to the same addresses, it's a wildcard zone.
	for _, ip := range randomIPs {
		if _, ok := baseSet[ip]; ok {
			return true
		}
	}
	return false
}

// generateRandomLabel creates a random 16-character alphabetic label prepended to domain.
func generateRandomLabel(domain string) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 16)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[n.Int64()]
	}
	return string(b) + "." + domain, nil
}

// lookupNS returns the NS records for the given FQDN using the resolver,
// bounded by the per-call DNS deadline.
func lookupNS(ctx context.Context, fqdn string, resolver *net.Resolver, timeoutMs int) []string {
	c, cancel := withDNSDeadline(ctx, timeoutMs)
	defer cancel()
	nsList, err := resolver.LookupNS(c, fqdn)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(nsList))
	for _, ns := range nsList {
		result = append(result, strings.TrimSuffix(ns.Host, "."))
	}
	return result
}

// lookupMX returns the MX records for the given FQDN using the resolver,
// bounded by the per-call DNS deadline.
func lookupMX(ctx context.Context, fqdn string, resolver *net.Resolver, timeoutMs int) []string {
	c, cancel := withDNSDeadline(ctx, timeoutMs)
	defer cancel()
	mxList, err := resolver.LookupMX(c, fqdn)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(mxList))
	for _, mx := range mxList {
		result = append(result, strings.TrimSuffix(mx.Host, "."))
	}
	return result
}

// isDNSNotFound checks if the error is a DNS NXDOMAIN error.
func isDNSNotFound(err error) bool {
	if err == nil {
		return false
	}
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
}

// buildReport constructs the final Fern report.
func buildReport(config dnsfern.DiscoverDnsCctldConfig, candidates []*dnsfern.DiscoverDnsCctldCandidate, errs []string) dnsfern.DiscoverDnsCctldReport {
	report := dnsfern.DiscoverDnsCctldReport{
		Config: &config,
		Result: &dnsfern.DiscoverDnsCctldResult{
			Candidates: candidates,
		},
	}
	if len(errs) > 0 {
		report.Errors = errs
	}
	return report
}
