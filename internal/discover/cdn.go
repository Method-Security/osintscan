package discover

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"

	// Configs
	"github.com/Method-Security/osintscan/configs"
	// Generated
	cdnfern "github.com/Method-Security/osintscan/generated/go/discover/cdn"
	// Utils
	"github.com/Method-Security/osintscan/utils"
)

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

// RunDiscoverCdns resolves a domain to IP addresses and checks them against the
// supplemental providers.json CIDR file (overridable via --fingerprints-file),
// which ships with AKAMAI, AZURE_FRONTDOOR, CLOUDFLARE, CLOUDFRONT, INCAPSULA,
// and VERCEL ranges.
//
// ipAddresses may contain individual IPs or CIDR notation (e.g. 1.2.3.0/24).
func RunDiscoverCdns(ctx context.Context, config cdnfern.DiscoverCdnConfig) *cdnfern.DiscoverCdnReport {
	log := svc1log.FromContext(ctx)

	result := &cdnfern.DiscoverCdnResult{}
	report := &cdnfern.DiscoverCdnReport{}
	report.SetConfig(&config)
	report.SetResult(result)

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
		resolved, resolveErr := resolveDomain(ctx, config.Domain, config.DnsResolvers)
		if resolveErr != nil {
			report.SetErrors([]string{fmt.Sprintf("failed to resolve domain %s: %v", config.Domain, resolveErr)})
			return report
		}
		rawInputs = resolved
		log.Info("Resolved domain", svc1log.SafeParam("domain", config.Domain), svc1log.SafeParam("ip_count", len(rawInputs)))
	}

	// Expand any CIDRs into individual IPs.
	ipAddresses, expandErrors := expandIPs(rawInputs)
	var errors []string
	errors = append(errors, expandErrors...)

	// Check each IP against the supplemental providers and collect unique (ip, provider) pairs.
	matches := []*cdnfern.IpCdnResult{}

	for _, ipStr := range ipAddresses {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			log.Error("Invalid IP address", svc1log.SafeParam("ipAddress", ipStr))
			errors = append(errors, fmt.Sprintf("invalid IP address: %s", ipStr))
			continue
		}

		log.Info("Checking IP address", svc1log.SafeParam("ipAddress", ipStr))

		provider, ok := checkSupplemental(ip, supplemental)
		if !ok {
			continue
		}

		ipResult := &cdnfern.IpCdnResult{}
		ipResult.SetDomain(config.Domain)
		ipResult.SetIpAddress(ipStr)
		ipResult.SetProvider(provider)
		matches = append(matches, ipResult)
	}

	if len(errors) > 0 {
		report.SetErrors(errors)
	}
	result.SetMatches(matches)
	report.SetResult(result)
	return report
}

// resolveDomain returns the A/AAAA records for a domain using the configured
// DNS resolvers, or the system default resolver when none are provided.
func resolveDomain(ctx context.Context, domain string, dnsResolvers []string) ([]string, error) {
	log := svc1log.FromContext(ctx)
	resolvers := utils.GetResolvers(dnsResolvers, log)
	resolver := resolvers[rand.Intn(len(resolvers))]
	return resolver.LookupHost(ctx, domain)
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
				upperCaseProviderKey := strings.ToUpper(providerKey)
				provider, err := cdnfern.NewCdnProviderFromString(upperCaseProviderKey)
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
