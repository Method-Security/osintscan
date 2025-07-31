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

	// Generated
	cdnfern "github.com/Method-Security/osintscan/generated/go/discover"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// RunDiscoverCdns checks IP addresses against known CDN provider ranges
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

	// Iterate through each IP address provided in the config
	for _, ipAddress := range config.IpAddresses {
		log.Info("Checking IP address", svc1log.SafeParam("ipAddress", ipAddress))

		// Initialize result structure for this specific IP
		ipResult := &cdnfern.IpCdnResult{
			IpAddress: ipAddress,
			Match:     nil,
		}

		// Parse and validate the IP address string
		ip := net.ParseIP(strings.TrimSpace(ipAddress))
		if ip == nil {
			log.Error("Invalid IP address", svc1log.SafeParam("ipAddress", ipAddress))
			continue
		}

		// Check if this IP falls within any CDN provider ranges
		match, errors := checkIPAgainstCdnRanges(ctx, ip, cdnFingerprints)
		if match != nil {
			ipResult.Match = match
			result.Results = append(result.Results, ipResult)
		}

		// Accumulate any errors encountered during checking
		report.Errors = append(report.Errors, errors...)
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
			log.Info("Checking range", svc1log.SafeParam("providerKey", providerKey), svc1log.SafeParam("raw", raw))
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
