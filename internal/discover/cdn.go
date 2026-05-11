package discover

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/cdncheck"

	// Configs
	"github.com/Method-Security/osintscan/configs"
	// Generated
	cdnfern "github.com/Method-Security/osintscan/generated/go/discover/cdn"
	// Utils
	"github.com/Method-Security/osintscan/utils"
)

// cdncheckProviderMap maps the lowercase provider name strings returned by cdncheck
// to their corresponding Fern CdnProvider enum key strings.
// Note: "amazon" is the CNAME-based name cdncheck uses for Amazon CloudFront.
// Note: "imperva" is the parent company of Incapsula and maps to INCAPSULA.
var cdncheckProviderMap = map[string]string{
	"akamai":     "AKAMAI",
	"amazon":     "CLOUDFRONT",
	"aws":        "AWS",
	"cloudflare": "CLOUDFLARE",
	"cloudfront": "CLOUDFRONT",
	"edgecast":   "EDGECAST",
	"fastly":     "FASTLY",
	"gocache":    "GOCACHE",
	"google":     "GOOGLE",
	"imperva":    "INCAPSULA",
	"incapsula":  "INCAPSULA",
	"oracle":     "ORACLE",
}

// supplementalProviderEntry holds IPv4 and IPv6 CIDR ranges for a single provider.
type supplementalProviderEntry struct {
	IPv4Ranges []string `json:"ipv4Ranges"`
	IPv6Ranges []string `json:"ipv6Ranges"`
}

// supplementalProviders is the shape of providers.json.
// It ships with AKAMAI, AZURE_FRONTDOOR, CLOUDFLARE, CLOUDFRONT, INCAPSULA, and VERCEL
// and can be overridden via --fingerprints-file.
type supplementalProviders struct {
	CdnProviders map[string]supplementalProviderEntry `json:"cdnProviders"`
}

// RunDiscoverCdns resolves a domain to IP addresses and checks them against CDN/WAF/cloud
// providers using two independent sources:
//  1. projectdiscovery/cdncheck — broad, regularly updated provider ranges.
//  2. providers.json — supplemental CIDR file shipped with the binary (overridable via
//     --fingerprints-file) covering AKAMAI, AZURE_FRONTDOOR, CLOUDFLARE, CLOUDFRONT,
//     INCAPSULA, and VERCEL.
//
// Results from both sources are merged; duplicates (same IP + same provider) are dropped.
// ipAddresses may contain individual IPs or CIDR notation (e.g. 1.2.3.0/24).
func RunDiscoverCdns(ctx context.Context, config cdnfern.DiscoverCdnConfig) *cdnfern.DiscoverCdnReport {
	log := svc1log.FromContext(ctx)

	result := &cdnfern.DiscoverCdnResult{}
	report := &cdnfern.DiscoverCdnReport{}
	report.SetConfig(&config)
	report.SetResult(result)

	// Build cdncheck client, forwarding any custom DNS resolvers.
	var (
		client *cdncheck.Client
		err    error
	)
	if len(config.DnsResolvers) > 0 {
		normalized := make([]string, 0, len(config.DnsResolvers))
		for _, r := range config.DnsResolvers {
			normalized = append(normalized, utils.NormalizeDNSAddress(r))
		}
		client, err = cdncheck.NewWithOpts(3, normalized)
		if err != nil {
			report.SetErrors([]string{err.Error()})
			return report
		}
	} else {
		client = cdncheck.New()
	}

	// Load supplemental providers file.
	var fingerprintsFile string
	if config.FingerprintsFile != nil {
		fingerprintsFile = *config.FingerprintsFile
	}
	supplemental, err := loadSupplementalProviders(fingerprintsFile)
	if err != nil {
		report.SetErrors([]string{err.Error()})
		return report
	}

	// Determine IP addresses to check.
	var rawInputs []string
	if config.IpAddresses != nil {
		rawInputs = config.IpAddresses
	} else {
		log.Info("Resolving domain", svc1log.SafeParam("domain", config.Domain))
		dnsData, resolveErr := client.GetDnsData(config.Domain)
		if resolveErr != nil {
			report.SetErrors([]string{fmt.Sprintf("failed to resolve domain %s: %v", config.Domain, resolveErr)})
			return report
		}
		rawInputs = append(rawInputs, dnsData.A...)
		rawInputs = append(rawInputs, dnsData.AAAA...)
		log.Info("Resolved domain", svc1log.SafeParam("domain", config.Domain), svc1log.SafeParam("ip_count", len(rawInputs)))
	}

	// Expand any CIDRs into individual IPs.
	ipAddresses, expandErrors := expandIPs(rawInputs)
	var errors []string
	errors = append(errors, expandErrors...)

	// Check each IP against both sources and collect unique (ip, provider) pairs.
	matches := []*cdnfern.IpCdnResult{}

	for _, ipStr := range ipAddresses {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			log.Error("Invalid IP address", svc1log.SafeParam("ipAddress", ipStr))
			errors = append(errors, fmt.Sprintf("invalid IP address: %s", ipStr))
			continue
		}

		log.Info("Checking IP address", svc1log.SafeParam("ipAddress", ipStr))

		providers, checkErrors := collectProviders(ip, client, supplemental, log)
		errors = append(errors, checkErrors...)

		for _, provider := range providers {
			ipResult := &cdnfern.IpCdnResult{}
			ipResult.SetDomain(config.Domain)
			ipResult.SetIpAddress(ipStr)
			ipResult.SetProvider(provider)
			matches = append(matches, ipResult)
		}
	}

	if len(errors) > 0 {
		report.SetErrors(errors)
	}
	result.SetMatches(matches)
	report.SetResult(result)
	return report
}

// collectProviders runs both cdncheck and the supplemental file against a single IP
// and returns the deduplicated set of matched CdnProvider values.
func collectProviders(ip net.IP, client *cdncheck.Client, supplemental *supplementalProviders, log svc1log.Logger) ([]cdnfern.CdnProvider, []string) {
	seen := map[cdnfern.CdnProvider]struct{}{}
	var providers []cdnfern.CdnProvider
	var errors []string

	// --- source 1: cdncheck ---
	matched, providerStr, _, err := client.Check(ip)
	if err != nil {
		errors = append(errors, fmt.Sprintf("cdncheck error for %s: %v", ip, err))
	} else if matched {
		enumKey, ok := cdncheckProviderMap[providerStr]
		if !ok {
			log.Warn("unrecognised cdncheck provider", svc1log.SafeParam("provider", providerStr))
		} else {
			provider, parseErr := cdnfern.NewCdnProviderFromString(enumKey)
			if parseErr != nil {
				errors = append(errors, fmt.Sprintf("failed to map cdncheck provider %q: %v", providerStr, parseErr))
			} else if _, dup := seen[provider]; !dup {
				seen[provider] = struct{}{}
				providers = append(providers, provider)
			}
		}
	}

	// --- source 2: supplemental providers.json ---
	supplementalProvider, ok := checkSupplemental(ip, supplemental)
	if ok {
		if _, dup := seen[supplementalProvider]; !dup {
			seen[supplementalProvider] = struct{}{}
			providers = append(providers, supplementalProvider)
		}
	}

	return providers, errors
}

// checkSupplemental checks an IP against the supplemental provider CIDR ranges.
func checkSupplemental(ip net.IP, providers *supplementalProviders) (cdnfern.CdnProvider, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}
	addr = addr.Unmap()
	isIPv4 := addr.Is4()

	for providerKey, entry := range providers.CdnProviders {
		var ranges []string
		if isIPv4 {
			ranges = entry.IPv4Ranges
		} else {
			ranges = entry.IPv6Ranges
		}
		for _, raw := range ranges {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			if prefix.Contains(addr) {
				provider, err := cdnfern.NewCdnProviderFromString(providerKey)
				if err != nil {
					continue
				}
				return provider, true
			}
		}
	}
	return "", false
}

// loadSupplementalProviders reads the supplemental CDN provider CIDR file.
// When fingerprintsFile is empty the embedded default is used.
func loadSupplementalProviders(fingerprintsFile string) (*supplementalProviders, error) {
	var data []byte
	var err error
	if fingerprintsFile != "" {
		data, err = os.ReadFile(fingerprintsFile)
	} else {
		data, err = configs.ReadFile("discover/cdn/providers.json")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read supplemental CDN providers: %w", err)
	}
	var providers supplementalProviders
	if err := json.Unmarshal(data, &providers); err != nil {
		return nil, fmt.Errorf("failed to parse supplemental CDN providers: %w", err)
	}
	return &providers, nil
}

// expandIPs takes a slice of individual IPs and/or CIDR strings and returns
// the full flat list of IP address strings, plus any parse errors.
func expandIPs(inputs []string) ([]string, []string) {
	var ips []string
	var errors []string

	for _, input := range inputs {
		trimmed := strings.TrimSpace(input)
		if strings.Contains(trimmed, "/") {
			expanded, err := expandCIDR(trimmed)
			if err != nil {
				errors = append(errors, fmt.Sprintf("invalid CIDR %s: %v", trimmed, err))
				continue
			}
			ips = append(ips, expanded...)
		} else {
			ips = append(ips, trimmed)
		}
	}
	return ips, errors
}

// expandCIDR returns all host addresses within the given CIDR block.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip = ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// incrementIP advances an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
