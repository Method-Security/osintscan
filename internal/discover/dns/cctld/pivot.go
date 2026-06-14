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

	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	// Internal
	"github.com/Method-Security/osintscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/idna"
)

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
		// Fall back to splitting on the first dot.
		parts := strings.SplitN(config.Domain, ".", 2)
		dn = &publicsuffix.DomainName{SLD: parts[0]}
	}
	baseLabel := strings.ToLower(dn.SLD)
	inputApex := strings.ToLower(dn.SLD)
	if dn.TLD != "" {
		inputApex = baseLabel + "." + strings.ToLower(dn.TLD)
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

	// Optionally fetch baseline body.
	baselineBody := ""
	hasBaseline := false
	if config.BaselineUrl != nil && *config.BaselineUrl != "" {
		log.Info("Fetching baseline URL", svc1log.SafeParam("url", *config.BaselineUrl))
		baselineBody = FetchBody(ctx, *config.BaselineUrl, config.Timeout)
		hasBaseline = true
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
			t = strings.ToLower(strings.TrimSpace(t))
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
	wildcardDetected := detectCandidateWildcard(ctx, fqdn, resolver)

	ips, err := resolver.LookupHost(ctx, fqdn)
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

	// Resolve NS records.
	nsRecords := lookupNS(ctx, fqdn, resolver)
	// Resolve MX records.
	mxRecords := lookupMX(ctx, fqdn, resolver)

	// Web probe.
	var probeResult ProbeResult
	if config.ProbeWeb {
		probeResult = ProbeWeb(ctx, fqdn, config.Timeout)
	}

	// Similarity to baseline.
	var similarityPtr *float64
	if hasBaseline && probeResult.Body != "" {
		score := SimilarityScore(baselineBody, probeResult.Body)
		similarityPtr = &score
	}

	// Determine HTTP/HTTPS status for classification.
	httpStatus := 0
	if probeResult.HTTPStatus != nil {
		httpStatus = *probeResult.HTTPStatus
	}

	// Classification.
	certSubjectStr := ""
	if probeResult.CertSubject != nil {
		certSubjectStr = *probeResult.CertSubject
	}
	titleStr := ""
	if probeResult.Title != nil {
		titleStr = *probeResult.Title
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
		BodyLen:              len(probeResult.Body),
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
func detectCandidateWildcard(ctx context.Context, fqdn string, resolver *net.Resolver) bool {
	if resolver == nil {
		return false
	}

	// First confirm the FQDN itself resolves.
	baseIPs, err := resolver.LookupHost(ctx, fqdn)
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
	randomIPs, err := resolver.LookupHost(ctx, randomFQDN)
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

// lookupNS returns the NS records for the given FQDN using the resolver.
func lookupNS(ctx context.Context, fqdn string, resolver *net.Resolver) []string {
	nsList, err := resolver.LookupNS(ctx, fqdn)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(nsList))
	for _, ns := range nsList {
		result = append(result, strings.TrimSuffix(ns.Host, "."))
	}
	return result
}

// lookupMX returns the MX records for the given FQDN using the resolver.
func lookupMX(ctx context.Context, fqdn string, resolver *net.Resolver) []string {
	mxList, err := resolver.LookupMX(ctx, fqdn)
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
