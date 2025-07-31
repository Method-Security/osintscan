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
	"sync/atomic"

	// Generated
	cdnfern "github.com/Method-Security/osintscan/generated/go/discover"
	// Utils
	"github.com/Method-Security/osintscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// RunDiscoverCdns resolves domains to IP addresses and checks them against known CDN provider ranges
// and returns a report with any matches found
func RunDiscoverCdns(ctx context.Context, config cdnfern.DiscoverCdnConfig) *cdnfern.DiscoverCdnReport {
	log := svc1log.FromContext(ctx)

	// Initialize empty result structure to hold all IP check results
	result := &cdnfern.DiscoverCdnResult{
		Results: []*cdnfern.IpCdnResult{},
	}

	// Initialize report structure with config and result
	report := &cdnfern.DiscoverCdnReport{
		Config: &config,
		Result: result,
	}

	// Load CDN provider configuration from specified file path
	cdnFingerprints, err := loadCdnDictFromPath(config.FingerprintsFile)
	if err != nil {
		report.Errors = []string{err.Error()}
		return report
	}

	// Create resolvers for each provided DNS server
	resolvers := []*net.Resolver{}
	for _, dnsServerAddress := range config.DnsResolvers {
		resolvers = append(resolvers, utils.GetResolver(dnsServerAddress, log))
	}

	// Iterate through each domain provided in the config
	for _, domain := range config.Domains {
		log.Info("Resolving domain", svc1log.SafeParam("domain", domain))

		// Resolve domain to IP addresses using round-robin resolvers
		ipAddresses, resolveErrors := resolvedomainToIPs(ctx, domain, resolvers, log)

		// Add any resolution errors to the report
		report.Errors = append(report.Errors, resolveErrors...)

		// Check each resolved IP address against CDN ranges
		for _, ipAddress := range ipAddresses {
			log.Info("Checking resolved IP address", svc1log.SafeParam("domain", domain), svc1log.SafeParam("ipAddress", ipAddress))

			// Initialize result structure for this specific IP

			// Parse and validate the IP address string
			ip := net.ParseIP(strings.TrimSpace(ipAddress))
			if ip == nil {
				log.Error("Invalid IP address from resolution", svc1log.SafeParam("domain", domain), svc1log.SafeParam("ipAddress", ipAddress))
				continue
			}

			// Check if this IP falls within any CDN provider ranges
			match, errors := checkIPAgainstCdnRanges(ctx, ip, cdnFingerprints)
			if match != nil {
				ipResult := &cdnfern.IpCdnResult{
					Domain:    domain,
					IpAddress: ipAddress,
					Match:     match,
				}
				result.Results = append(result.Results, ipResult)
			}

			// Accumulate any errors encountered during checking
			report.Errors = append(report.Errors, errors...)
		}
	}

	// Set final result and return complete report
	report.Result = result
	return report
}

// loadCdnDictFromPath reads and parses the CDN configuration file
// Returns parsed CDN provider data structure or error if file cannot be read/parsed
func loadCdnDictFromPath(fingerprintsFile string) (*cdnfern.CdnProviders, error) {
	// Read the entire configuration file into memory
	data, err := os.ReadFile(fingerprintsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CDN config file %q: %w", fingerprintsFile, err)
	}

	// Parse JSON data into CDN providers structure
	var cfg cdnfern.CdnProviders
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse CDN config file %q: %w", fingerprintsFile, err)
	}

	return &cfg, nil
}

// checkIPAgainstCdnRanges compares an IP address against all CDN provider IP ranges
// Returns the first matching CDN provider and any errors encountered
func checkIPAgainstCdnRanges(ctx context.Context, ip net.IP, cdnFingerprints *cdnfern.CdnProviders) (*cdnfern.CdnMatch, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	// Convert standard net.IP to more efficient netip.Addr for comparison
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		errors = append(errors, "Invalid IP address")
		return nil, errors
	}
	// Get IP Type
	addr = addr.Unmap()
	isIPv4 := addr.Is4()

	// Iterate through each CDN provider in the configuration
	for providerKey, provider := range cdnFingerprints.CdnProviders {
		log.Info("Checking provider", svc1log.SafeParam("providerKey", providerKey))

		// Select appropriate IP ranges based on address type
		var ranges []string
		if isIPv4 {
			ranges = provider.Ipv4Ranges
		} else {
			ranges = provider.Ipv6Ranges
		}

		// Check each IP range for this provider
		for _, raw := range ranges {
			s := strings.TrimSpace(raw)

			// Parse the IP range/subnet notation
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				log.Error("Error parsing prefix", svc1log.SafeParam("error", err.Error()))
				errors = append(errors, "Error parsing prefix")
				continue
			}

			// Check if the target IP falls within this range
			if prefix.Contains(addr) {
				// Convert provider key string to enum type
				cdnProvider, err := cdnfern.NewCdnProviderFromString(strings.ToUpper(providerKey))
				if err != nil {
					log.Error("Error parsing provider key", svc1log.SafeParam("error", err.Error()))
					errors = append(errors, "Error parsing provider key")
					continue
				}

				// Return first match found with the matching range info
				return &cdnfern.CdnMatch{
					Provider:     cdnProvider,
					MatchedRange: s,
				}, errors
			}
		}
	}

	return nil, errors
}

// resolvedomainToIPs resolves an domain to IP addresses using round-robin resolvers
// Returns a slice of IP address strings and any errors encountered
func resolvedomainToIPs(ctx context.Context, domain string, resolvers []*net.Resolver, log svc1log.Logger) ([]string, []string) {
	var resolverIndex int64
	var ipAddresses []string
	var errors []string

	// Use round-robin resolver selection
	currentIndex := atomic.AddInt64(&resolverIndex, 1) - 1
	resolverIdx := currentIndex % int64(len(resolvers))
	resolver := resolvers[resolverIdx]

	log.Info("Using resolver for domain resolution", svc1log.SafeParam("resolver_index", resolverIdx), svc1log.SafeParam("domain", domain))

	// Resolve the domain to IP addresses
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to resolve domain %s: %v", domain, err))
		return ipAddresses, errors
	}

	// Add all resolved IPs to the result
	ipAddresses = append(ipAddresses, ips...)

	log.Info("Resolved domain", svc1log.SafeParam("domain", domain), svc1log.SafeParam("ip_count", len(ips)))

	return ipAddresses, errors
}
