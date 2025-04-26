package cmd

import (
	"context" // Needed for context
	// Needed for JSON output - **REMOVING, no longer needed here**
	"fmt"
	"net"
	"os"        // Needed for os.Interrupt
	"os/signal" // Needed for signal.NotifyContext
	"syscall"   // Needed for syscall signals
	"time"      // Needed for time.Duration

	// Import the internal subnet package
	"github.com/Method-Security/osintscan/internal/subnet"
	// NOTE: We will need imports for the actual implementation logic from internal/ later
	subnetgenerated "github.com/Method-Security/osintscan/generated/go/subnet" // Needed for report types

	"github.com/spf13/cobra"
)

// Variables to hold flag values for the research subcommand
var (
	subnetStr  string
	workers    int
	timeout    int // Timeout in seconds
	extended   bool
	resolver   string
	apiKey     string // Added API key
	maxMindDB  string
	ptrTimeout time.Duration
)

// researchCmd represents the research command - **MOVED INSIDE InitSubnetCommand**
// var researchCmd = &cobra.Command{ ... } // Removed from here

// initResearchCmdFlags initializes the flags for the research command.
// It takes the command to add flags to as an argument.
func initResearchCmdFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&subnetStr, "subnet", "s", "", "IPv4 subnet to research (e.g., 1.1.1.0/24, 8.8.8.8/32)")
	cmd.Flags().IntVarP(&workers, "workers", "w", 10, "Number of concurrent workers")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 3, "Timeout in seconds for network lookups") // Kept as int for flag parsing
	cmd.Flags().BoolVarP(&extended, "extended", "x", false, "Perform extended OSINT gathering")
	cmd.Flags().StringVarP(&resolver, "resolver", "r", "", "Custom DNS resolver address (e.g., 8.8.8.8:53)")
	cmd.Flags().StringVar(&apiKey, "asn-api-key", "", "API key for ASN lookups (from https://cloud.projectdiscovery.io). Alternatively, set PDCP_API_KEY env var")
	cmd.Flags().StringVar(&maxMindDB, "maxmind-db", "", "Path to MaxMind GeoIP2 ASN database")
	cmd.Flags().DurationVar(&ptrTimeout, "ptr-timeout", 400*time.Millisecond, "Per-PTR lookup timeout (e.g. 500ms, 1s)")
	err := cmd.MarkFlagRequired("subnet")
	if err != nil {
		// Panicking during init is generally acceptable for CLI tools if a flag setup fails.
		panic(fmt.Sprintf("Error marking 'subnet' flag required: %v", err))
	}
}

// InitSubnetCommand initializes the Subnet command group and its subcommands.
func (a *OsintScan) InitSubnetCommand() {
	// Define the parent subnet command
	SubnetCmd := &cobra.Command{
		Use:   "subnet",
		Short: "Perform research and analysis on subnets.",
		Long:  `Provides tools for researching and analyzing IPv4 subnets, including OSINT gathering.`,
	}

	// Define the research subcommand *within* this method scope to access 'a'
	researchCmd := &cobra.Command{
		Use:   "research",
		Short: "Perform OSINT research on an IPv4 subnet",
		Long:  `Performs OSINT research on an IPv4 subnet, gathering information like PTR records, ASN details, and ownership data for each IP address within the specified range.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Create root context that cancels on Ctrl-C
			// Use cmd.Context() as the parent, which might already have logging etc.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop() // Ensure the signal handler is removed when the command finishes

			// --- Begin Flag Parsing & Validation ---
			// Basic CIDR format validation (more specific validation happens in subnet.Scan)
			_, _, err := net.ParseCIDR(subnetStr)
			if err != nil {
				return fmt.Errorf("invalid subnet format provided: %w", err)
			}
			// Validate workers and timeout
			if workers <= 0 {
				return fmt.Errorf("invalid number of workers: %d, must be positive", workers)
			}
			if timeout <= 0 {
				return fmt.Errorf("invalid timeout: %d seconds, must be positive", timeout)
			}
			// --- End Flag Parsing & Validation ---

			// 2. Build ScanConfig struct from parsed flags
			metrics := &subnetgenerated.RunMetrics{} // Initialize metrics struct
			cfg := subnet.ScanConfig{
				Extended:   extended,
				Timeout:    time.Duration(timeout) * time.Second, // Convert int seconds to time.Duration
				Workers:    workers,
				Resolver:   resolver,
				ASNAPIKey:  apiKey,                 // Pass the API key to the scanner
				MaxMindDB:  maxMindDB,              // path to MaxMind GeoIP2 ASN database
				PoliteWait: 200 * time.Millisecond, // optional throttle for net providers
				PTRTimeout: ptrTimeout,             // Pass the parsed PTR timeout
				Metrics:    metrics,                // Pass pointer to metrics struct
			}

			// 3. Call scanner.Scan(ctx, cidr, cfg)
			// fmt.Printf("Starting subnet scan for %s...\n", subnetStr) // Removed temp feedback

			resultsChan, err := subnet.Scan(ctx, subnetStr, cfg)
			if err != nil {
				// Proper error handling via signal:
				errMsg := err.Error()
				a.OutputSignal.ErrorMessage = &errMsg
				a.OutputSignal.Status = 1 // Indicate failure
				// Return nil because the error is handled by the signal writer
				return nil
				// Old way: return fmt.Errorf("failed to initialize subnet scan: %w", err)
			}

			// 4. Add a loop: for report := range resultsChan { /* Collect reports */ }
			var collectedReports []*subnetgenerated.IpReport // Slice to hold results
			var isCancelled bool                             // Flag to track if context was cancelled

			// fmt.Println("Scanning IPs...") // Removed temp feedback
			for report := range resultsChan {
				collectedReports = append(collectedReports, report)
				// Optional: Print progress (maybe behind a verbose flag later)
				// fmt.Printf("Received report for %s\n", report.Ip)
			}

			// Check if the context was cancelled (e.g., Ctrl-C pressed)
			if ctx.Err() != nil {
				if ctx.Err() == context.Canceled {
					// fmt.Println("Scan cancelled by user.") // Let signal/logging handle this
					isCancelled = true
					// Treat user cancellation as non-error completion for exit code
				} else {
					// Other context errors (like deadline exceeded, though less likely here)
					// fmt.Printf("Scan interrupted: %v\n", ctx.Err()) // Let signal/logging handle this
					isCancelled = true
					errMsg := fmt.Sprintf("Scan interrupted: %v", ctx.Err())
					a.OutputSignal.ErrorMessage = &errMsg
					a.OutputSignal.Status = 1 // Indicate failure
					// Return nil because the error is handled by the signal writer
					return nil
					// Old way: return ctx.Err()
				}
			}

			// 5. Assemble the final report structure
			// fmt.Println("Scan complete. Assembling final report...") // Removed temp feedback

			finalReport := subnetgenerated.SubnetReport{
				Subnet:    subnetStr,
				TotalIps:  len(collectedReports), // Use int, not int32
				ScannedAt: time.Now().UTC(),
				Reports:   collectedReports,
				Cancelled: &isCancelled, // Use address of bool for optional field
				Metrics:   metrics,      // Assign the populated metrics
			}

			// 6. Assign the result to the OutputSignal content
			a.OutputSignal.Content = finalReport

			// Remove manual JSON marshalling and printing
			// jsonData, err := json.MarshalIndent(finalReport, "", "  ")
			// if err != nil {
			// 	a.OutputSignal.ErrorMessage = fmt.Sprintf("failed to marshal final report to JSON: %w", err)
			// 	a.OutputSignal.Status = 1
			// 	return nil // Handle error via signal
			// 	// Old way: return fmt.Errorf("failed to marshal final report to JSON: %w", err)
			// }
			// fmt.Println(string(jsonData)) // Removed manual printing

			return nil // Return nil on successful completion (even if cancelled by user)
		},
	}

	// Initialize flags for the research subcommand
	initResearchCmdFlags(researchCmd)

	// Add subcommands to the parent command
	SubnetCmd.AddCommand(researchCmd)

	// Assign the configured command to the OsintScan struct field
	a.SubnetCmd = SubnetCmd

	// Add the parent command to the root command
	a.RootCmd.AddCommand(a.SubnetCmd)
}
