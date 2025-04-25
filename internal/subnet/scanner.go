package subnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	// Import the generated Fern types for subnet research.
	subnetgenerated "github.com/Method-Security/osintscan/generated/go/subnet"
	// Revert back to using the libs sub-package
	libs "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/utils/env"
)

// ScanConfig holds the configuration options for a subnet scan, derived from CLI flags.
type ScanConfig struct {
	// Extended determines whether to perform extended OSINT gathering beyond core requirements.
	Extended bool
	// Timeout specifies the duration to wait for individual network lookups (e.g., PTR, WHOIS) before timing out.
	Timeout time.Duration
	// Workers specifies the number of concurrent goroutines to use for scanning IPs within the subnet.
	Workers int
	// Resolver specifies a custom DNS resolver address (e.g., "8.8.8.8:53").
	// If empty, the system's default resolver will be used.
	Resolver string
	// ASNAPIKey specifies the API key for the ASN lookup service (ProjectDiscovery Cloud Platform).
	// If empty, the PDCP_API_KEY environment variable will be used.
	ASNAPIKey string
}

// Scan initiates the OSINT research on the given IPv4 subnet CIDR.
// It parses the CIDR, validates it, sets up a worker pool according to the ScanConfig,
// and distributes IP scanning tasks to the workers.
//
// It returns a read-only channel (`<-chan`) that streams *subnetgenerated.IpReport results
// as they become available from the workers. The channel is closed once all IPs in the
// subnet have been processed or if the context (`ctx`) is cancelled.
//
// An error is returned immediately if the initial setup fails (e.g., invalid CIDR format,
// subnet too large). The caller is responsible for consuming all reports from the channel
// until it is closed.
func Scan(ctx context.Context, cidr string, cfg ScanConfig) (<-chan *subnetgenerated.IpReport, error) {
	// 1. Parse and validate the input 'cidr' string.
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format: %w", err)
	}

	// 2. Check if the subnet is IPv4 first using net.IP
	ipV4 := ip.To4()
	if ipV4 == nil {
		return nil, fmt.Errorf("invalid subnet: IPv6 is not supported")
	}

	// Now convert the 4-byte representation to netip.Addr
	ipNetIP, ok := netip.AddrFromSlice(ipV4)
	if !ok {
		// This should theoretically not happen if ip.To4() succeeded
		return nil, fmt.Errorf("failed to convert net.IP to netip.Addr after To4() check")
	}

	ones, _ := ipNet.Mask.Size()              // Capture both return values
	prefix := netip.PrefixFrom(ipNetIP, ones) // Use only 'ones'
	if !prefix.IsValid() {
		return nil, fmt.Errorf("failed to create valid netip.Prefix")
	}

	// 2a. Check subnet size limits.
	// We already know it's IPv4 from the ip.To4() check above.
	if ones < 16 {
		// Allow /16, but reject anything larger (e.g., /15, /8)
		return nil, fmt.Errorf("invalid subnet: size /%d is larger than the maximum allowed /16", ones)
	}

	// 3. Create the results and jobs channels.
	resultsChan := make(chan *subnetgenerated.IpReport)
	jobsCh := make(chan netip.Addr, cfg.Workers) // Buffered channel

	// Initialize ASN client using the libs package
	asnClient, err := libs.NewClient()
	if err != nil {
		// Consider logging the error instead of returning immediately
		// if ASN lookup is not strictly critical
		return nil, fmt.Errorf("failed to initialize ASN client: %w", err)
	}

	// Set the ASN API key if provided in the config
	// This will override the environment variable value only for this instance
	if cfg.ASNAPIKey != "" {
		// The libs package uses a package-level variable for the API key
		// We're modifying it here to use our config-provided key
		libs.PDCPApiKey = cfg.ASNAPIKey
	} else if asnAPIKey := env.GetEnvOrDefault("PDCP_API_KEY", ""); asnAPIKey != "" {
		// Double check that the environment variable is loaded
		libs.PDCPApiKey = asnAPIKey
	}
	// NOTE: Check if asnClient needs explicit closing (e.g., defer asnClient.Close())

	// 4. Start IP Enumeration Goroutine
	go func() {
		defer close(jobsCh) // Close jobs channel when enumeration is done
		addr := prefix.Addr()
		for {
			select {
			case <-ctx.Done(): // Check for cancellation
				return
			default:
				if prefix.Contains(addr) {
					jobsCh <- addr
				} else {
					// Stop if we've gone past the subnet range (handles /31, /32 correctly)
					return
				}

				// Handle wrap-around for the last IP in the address space
				if addr.IsUnspecified() || addr == netip.MustParseAddr("255.255.255.255") {
					return
				}
				addr = addr.Next()
			}
		}
	}()

	// 5. Start Worker Pool
	var wg sync.WaitGroup
	wg.Add(cfg.Workers) // Add workers to wait group

	for i := 0; i < cfg.Workers; i++ {
		go func(client *libs.Client) { // Use *libs.Client again
			defer wg.Done() // Signal worker completion
			for {
				select {
				case <-ctx.Done(): // Check for cancellation
					return
				case ipAddr, ok := <-jobsCh:
					if !ok {
						// jobsCh is closed, no more work
						return
					}

					// Create the report structure
					report := &subnetgenerated.IpReport{
						Ip:     ipAddr.String(),
						Errors: []string{}, // Initialize errors slice
					}

					// --- Create context for this IP's lookups ---
					lookupCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
					defer cancel() // Ensure context is cancelled even on errors

					// --- 1. Get PTR Records ---
					var resolver *net.Resolver // Use nil for default initially
					if cfg.Resolver != "" {
						resolver = &net.Resolver{
							PreferGo: true,
							Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
								d := net.Dialer{Timeout: cfg.Timeout}
								return d.DialContext(ctx, "udp", cfg.Resolver) // Use UDP for DNS
							},
						}
					}

					ptrRecords, err := getPTR(lookupCtx, ipAddr, resolver)
					if err != nil {
						report.Errors = append(report.Errors, fmt.Sprintf("PTR lookup failed: %v", err))
						// Continue to other lookups even if PTR fails
					} else {
						report.PtrRecords = ptrRecords // Assign PTR records
					}

					// --- 2. Get ASN Information ---
					asnInfo, err := getASN(lookupCtx, ipAddr, client) // Pass the asnClient instance
					if err != nil {
						// Append specific error related to ASN lookup, but don't stop processing
						report.Errors = append(report.Errors, fmt.Sprintf("ASN lookup failed: %v", err))
					} else if asnInfo != nil { // Only assign if ASN info was found
						report.Asn = asnInfo
					}

					// --- TODO: Add Ownership lookup logic here ---

					// --- TODO: Add Extended lookup logic here (if cfg.Extended) ---

					// Send result, checking for main context cancellation
					select {
					case resultsChan <- report:
					case <-ctx.Done():
						return // Don't block if main context is cancelled
					}
				}
			}
		}(asnClient) // Pass the client instance here
	}

	// 6. Start Goroutine to Close Results Channel
	// This goroutine waits for all workers to finish, then closes resultsChan.
	go func() {
		wg.Wait()          // Wait for all workers in the pool
		close(resultsChan) // Close the results channel
	}()

	// 7. Return the results channel and nil error.
	return resultsChan, nil
}

// getPTR performs a reverse DNS lookup for the given IP address.
// It uses the provided resolver or net.DefaultResolver if nil.
// Handles context cancellation/deadline and DNS "not found" errors specifically.
func getPTR(ctx context.Context, ip netip.Addr, resolver *net.Resolver) ([]string, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	names, err := resolver.LookupAddr(ctx, ip.String())

	// 1. Check for context errors first
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err // Propagate context errors directly
	}

	// 2. Check for DNS "not found" error
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return []string{}, nil // No PTR record found is not an error for us
	}

	// 3. Handle other potential errors
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %w", err) // Wrap other errors
	}

	// 4. Handle success (even if names slice is nil/empty)
	if names == nil {
		return []string{}, nil // Ensure we always return a non-nil slice
	}

	return names, nil
}

// getASN performs an ASN lookup for the given IP address using the provided asnmap client.
// It handles context cancellation/deadline and returns ASN information or an error.
func getASN(ctx context.Context, ip netip.Addr, client *libs.Client) (*subnetgenerated.AsnInfo, error) {
	// Perform the ASN lookup
	results, err := client.GetData(ip.String())

	// Check for context errors first
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err // Propagate context errors directly
	}

	// Handle other potential errors during lookup
	if err != nil {
		// This could be a temporary network issue or an internal asnmap error
		return nil, fmt.Errorf("asnmap lookup failed: %w", err)
	}

	// Handle cases where no ASN data is found for the IP
	if len(results) == 0 {
		return nil, nil // No ASN found is not treated as an error
	}

	// Map the first result to the ASNInfo struct
	// Assuming GetData returns a slice and the first element is the most relevant
	asnData := results[0]
	asnInfo := &subnetgenerated.AsnInfo{
		Number:  asnData.ASN,
		Org:     asnData.Org,
		Country: asnData.Country,
		// Name, Prefix, Registry could be mapped here if available and needed
		// Name: asnData.Name,
		// Prefix: asnData.Prefix,
		// Registry: asnData.Registry,
	}

	return asnInfo, nil
}

// TODO: Implement processIP function or integrate scanning logic directly
// into the worker goroutine above.
// func processIP(ctx context.Context, ip netip.Addr, cfg ScanConfig) *subnetgenerated.IpReport {
//	 // Placeholder for actual scanning logic (PTR, ASN, WHOIS, etc.)
//	 return &subnetgenerated.IpReport{Ip: ip.String()}
// }
