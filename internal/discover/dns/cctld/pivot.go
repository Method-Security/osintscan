// Package cctld implements ccTLD pivot discovery: given an input domain it
// constructs <base>.<tld> apex candidates for each ccTLD in the supplied list
// or preset, resolves DNS records, optionally probes HTTP/HTTPS, and classifies
// each resolved candidate.
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
// for DNS and HTTP probes). Returns 0 if the caller passed a
// nonpositive value, in which case callers should fall through to the
// parent context with no extra deadline.
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

	// Resolve the registrable label (SLD) from the input domain.
	// publicsuffix.Parse returns a *DomainName with .SLD == "acme" for "acme.com"
	// and also handles multi-label TLDs like "acme.co.uk" → SLD="acme".
	dn, err := publicsuffix.Parse(config.Domain)
	if err != nil {
		// Fall back to splitting on the first dot. We must populate TLD
		// from the remainder too — otherwise inputApex collapses to just
		// the base label, and the later EqualFold-against-inputApex skip
		// can't recognize the input domain itself and the sweep ends up
		// re-discovering it as a ccTLD candidate.
		parts := strings.SplitN(config.Domain, ".", 2)
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
	inputApex := baseLabel
	if dn.TLD != "" {
		tldNorm, _ := idna.Lookup.ToASCII(strings.ToLower(dn.TLD))
		if tldNorm == "" {
			tldNorm = strings.ToLower(dn.TLD)
		}
		inputApex = baseLabel + "." + tldNorm
	}

	log.Info("Starting ccTLD pivot",
		svc1log.SafeParam("domain", config.Domain),
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

	// Optionally fetch baseline body. Only set `hasBaseline` when we actually
	// retrieved a non-empty body — if FetchBody fails (DNS, connect refused,
	// 5xx, empty 200) we want classification to fall through to the
	// no-baseline cert/title heuristic rather than score every candidate
	// against an empty token set (which produces similarity=0 across the
	// board and misclassifies legitimate matches as UNRELATED).
	baselineBody := ""
	hasBaseline := false
	if config.BaselineUrl != nil && *config.BaselineUrl != "" {
		log.Info("Fetching baseline URL", svc1log.SafeParam("url", *config.BaselineUrl))
		baselineBody = FetchBody(ctx, *config.BaselineUrl, config.Timeout)
		if baselineBody != "" {
			hasBaseline = true
		} else {
			log.Warn("Baseline fetch returned empty body; falling back to no-baseline classification",
				svc1log.SafeParam("baseline_url", *config.BaselineUrl))
		}
	}

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
			candidate, candidateErr := processCandidateTLD(ctx, baseLabel, tld, inputApex, config, resolver, baselineBody, hasBaseline)
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
		svc1log.SafeParam("domain", config.Domain),
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

// processCandidateTLD resolves and classifies a single <base>.<tld> candidate.
// Returns nil candidate (and possibly an error string) if the candidate does not resolve.
func processCandidateTLD(
	ctx context.Context,
	baseLabel string,
	tld string,
	inputApex string,
	config dnsfern.DiscoverDnsCctldConfig,
	resolver *net.Resolver,
	baselineBody string,
	hasBaseline bool,
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

	// Wildcard detection: probe the candidate FQDN itself, then probe a random label.
	wildcardDetected := detectCandidateWildcard(ctx, fqdn, resolver, config.Timeout)

	// Per-call DNS deadline derived from config.Timeout so a slow registry
	// resolver does not stall the whole sweep beyond what the operator
	// expects. The CLI's --timeout flag documents these semantics.
	dnsCtx, cancel := withDNSDeadline(ctx, config.Timeout)
	defer cancel()
	ips, err := resolver.LookupHost(dnsCtx, fqdn)
	if err != nil {
		// NXDOMAIN or resolution failure — candidate does not exist, skip.
		if isDNSNotFound(err) {
			return nil, ""
		}
		// Transient error — record but skip.
		return nil, "DNS resolution error for " + fqdn + ": " + err.Error()
	}

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

	// Web probe.
	var probeResult ProbeResult
	if config.ProbeWeb {
		probeResult = ProbeWeb(ctx, fqdn, config.Timeout)
	}

	// Similarity to baseline. Skip when the probe followed redirects to a
	// different host — the body / title we tokenized belongs to the
	// redirect target, not the candidate. A regional subsidiary that
	// redirects to the global site would otherwise score 1.0 against the
	// baseline and look like impersonation.
	var similarityPtr *float64
	if hasBaseline && probeResult.Body != "" && !probeResult.RedirectedOffCandidate {
		score := SimilarityScore(baselineBody, probeResult.Body)
		similarityPtr = &score
	}

	// Determine the effective HTTP-ish status for classification. HTTPS is
	// preferred — many candidates redirect bare HTTP to HTTPS or only ever
	// serve TLS, and the body/title we tokenized lives on whichever probe
	// actually responded. Falling back to plain HTTPStatus here previously
	// caused HTTPS-only candidates to look like "no response" to the
	// classifier and never trigger the parked / tiny-body heuristics.
	httpStatus := 0
	switch {
	case probeResult.HTTPSStatus != nil:
		httpStatus = *probeResult.HTTPSStatus
	case probeResult.HTTPStatus != nil:
		httpStatus = *probeResult.HTTPStatus
	}

	// Classification.
	certSubjectStr := ""
	if probeResult.CertSubject != nil {
		certSubjectStr = *probeResult.CertSubject
	}
	// When the web probe followed redirects to a different host, the
	// title and body we captured belong to the redirect target — NOT to
	// the candidate. Zero them out before classifying so the title-based
	// impersonation heuristic and the tiny-body parking heuristic don't
	// fire on content that isn't the candidate's. The cert dial happens
	// against the original candidate host, so CertSubject / CertSANs
	// remain usable.
	titleStr := ""
	bodyLen := 0
	if !probeResult.RedirectedOffCandidate {
		if probeResult.Title != nil {
			titleStr = *probeResult.Title
		}
		bodyLen = len(probeResult.Body)
	}
	similarityVal := -1.0
	if similarityPtr != nil {
		similarityVal = *similarityPtr
	}
	classIn := ClassificationInput{
		RegistrableLabel:     baseLabel,
		CertSubject:          certSubjectStr,
		CertSANs:             probeResult.CertSANs,
		SimilarityToBaseline: similarityVal,
		HasBaseline:          hasBaseline && similarityPtr != nil,
		Title:                titleStr,
		HTTPStatus:           httpStatus,
		BodyLen:              bodyLen,
		NSRecords:            nsRecords,
	}
	classificationStr := Classify(classIn)
	classification, _ := dnsfern.NewDiscoverDnsCctldClassificationFromString(classificationStr)

	candidate := &dnsfern.DiscoverDnsCctldCandidate{
		Tld:                  tld,
		Fqdn:                 fqdn,
		Wildcard:             wildcardDetected,
		Classification:       classification,
		SimilarityToBaseline: similarityPtr,
		CertSubject:          probeResult.CertSubject,
		CertSans:             probeResult.CertSANs,
		FinalUrl:             probeResult.FinalURL,
		Title:                probeResult.Title,
		ServerHeader:         probeResult.ServerHeader,
		HttpStatus:           probeResult.HTTPStatus,
		HttpsStatus:          probeResult.HTTPSStatus,
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
// exhibits wildcard behavior by probing a random label under the candidate FQDN.
func detectCandidateWildcard(ctx context.Context, fqdn string, resolver *net.Resolver, timeoutMs int) bool {
	if resolver == nil {
		return false
	}

	// First confirm the FQDN itself resolves (per-call deadline).
	baseCtx, baseCancel := withDNSDeadline(ctx, timeoutMs)
	defer baseCancel()
	baseIPs, err := resolver.LookupHost(baseCtx, fqdn)
	if err != nil || len(baseIPs) == 0 {
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
