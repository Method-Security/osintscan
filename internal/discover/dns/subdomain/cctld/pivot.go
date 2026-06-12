package cctld

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/idna"
)

// GetCctldPivots tests whether the registrable label of `domain` resolves
// under each of the supplied country-code TLDs. If `cctlds` is nil or
// empty, DefaultCcTlds is used.
//
// Each candidate FQDN is IDN-normalized via the IDNA Lookup profile
// before resolution, so callers can mix ASCII and Unicode ccTLDs freely
// (e.g. both "ru" and "рф"). Resolution failures are not propagated as
// errors — a candidate that does not resolve is simply omitted from the
// output. The function only returns an error when ccTLD pivot cannot run
// at all (e.g. no resolvers, undecodable base label).
//
// The returned FQDN list is intended to be appended to the active
// subdomain discovery output so the downstream processor creates one
// Fqdn object per resolved ccTLD candidate.
func GetCctldPivots(
	ctx context.Context,
	domain string,
	cctlds []string,
	threads int,
	timeoutMinutes int,
	dnsServerAddresses []string,
) ([]string, error) {
	log := svc1log.FromContext(ctx)

	label, inputRegistrable, err := registrableLabelAndApex(domain)
	if err != nil {
		return nil, fmt.Errorf("ccTLD pivot: cannot derive registrable label from %q: %w", domain, err)
	}

	candidates := normalizeCctldList(cctlds)
	if len(candidates) == 0 {
		log.Info("ccTLD pivot disabled: empty ccTLD list and empty defaults",
			svc1log.SafeParam("domain", domain))
		return nil, nil
	}

	log.Info("Starting ccTLD pivot",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("label", label),
		svc1log.SafeParam("cctld_count", len(candidates)))

	if timeoutMinutes > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMinutes)*time.Minute)
		defer cancel()
	}

	resolvers := utils.GetResolvers(dnsServerAddresses, log)
	if len(resolvers) == 0 {
		return nil, errors.New("ccTLD pivot: no DNS resolvers available")
	}

	if threads <= 0 {
		threads = 20
	}

	semaphore := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var resolverIndex int64

	var foundMutex sync.Mutex
	foundSet := map[string]struct{}{}
	found := make([]string, 0, len(candidates))

	for _, cc := range candidates {
		wg.Add(1)
		go func(cc string) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}

			rawCandidate := label + "." + cc
			candidate, err := idna.Lookup.ToASCII(rawCandidate)
			if err != nil {
				log.Info("ccTLD candidate failed IDN normalization, skipping",
					svc1log.SafeParam("candidate", rawCandidate),
					svc1log.SafeParam("error", err.Error()))
				return
			}
			candidate = strings.ToLower(candidate)

			// Skip candidates that resolve back to the input's own registrable
			// apex — e.g. input "acme.ru" or "mail.acme.ru" with cc="ru" would
			// otherwise emit "acme.ru" as a discovered cross-zone pivot of
			// itself. The ccTLD pivot is only meaningful for cross-zone hits.
			if inputRegistrable != "" && candidate == inputRegistrable {
				return
			}

			idx := atomic.AddInt64(&resolverIndex, 1) - 1
			resolver := resolvers[idx%int64(len(resolvers))]

			addresses, lookupErr := resolver.LookupHost(ctx, candidate)
			if lookupErr != nil || len(addresses) == 0 {
				return
			}

			log.Info("ccTLD pivot match",
				svc1log.SafeParam("candidate", candidate),
				svc1log.SafeParam("addresses", addresses))

			foundMutex.Lock()
			defer foundMutex.Unlock()
			if _, exists := foundSet[candidate]; !exists {
				foundSet[candidate] = struct{}{}
				found = append(found, candidate)
			}
		}(cc)
	}

	wg.Wait()

	log.Info("ccTLD pivot complete",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("candidates_tested", len(candidates)),
		svc1log.SafeParam("matches", len(found)))

	return found, nil
}

// registrableLabelAndApex returns the second-level domain label (SLD) of
// the input plus the input's registrable apex (SLD + public suffix) — e.g.
// ("acme", "acme.com") from "acme.com" or "mail.acme.com"; ("acme",
// "acme.co.uk") from "shop.acme.co.uk". Uses the public-suffix list so
// multi-label suffixes (.co.uk, .com.au, .net.cn) are handled correctly.
//
// The apex is used to filter ccTLD candidates that resolve back to the
// input itself (e.g. input "acme.ru" against the default ccTLD "ru"). An
// input without a dot is treated as a bare label with empty apex; in that
// case no apex-self-match filter is applied.
func registrableLabelAndApex(domain string) (string, string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", "", errors.New("empty domain")
	}
	if !strings.Contains(domain, ".") {
		return domain, "", nil
	}
	parsed, err := publicsuffix.Parse(domain)
	if err != nil {
		return "", "", err
	}
	if parsed.SLD == "" {
		return "", "", fmt.Errorf("could not extract registrable label from %q", domain)
	}
	apex := parsed.SLD
	if parsed.TLD != "" {
		apex = parsed.SLD + "." + parsed.TLD
	}
	return parsed.SLD, apex, nil
}

// normalizeCctldList trims, lowercases, and deduplicates the input list.
// Strips a leading dot if present so callers may pass either ".ru" or
// "ru". If the result is empty, falls back to DefaultCcTlds.
func normalizeCctldList(cctlds []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(cctlds))
	for _, cc := range cctlds {
		normalized := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(cc)), ".")
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		// Fall back to defaults — also deduped/normalized so a curated
		// default with stray whitespace cannot break the contract.
		for _, cc := range DefaultCcTlds {
			normalized := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(cc)), ".")
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
	}
	return out
}
