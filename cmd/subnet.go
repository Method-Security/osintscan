package cmd

import (
	"context"       // Needed for context
	"encoding/json" // Needed for JSON output
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

// researchCmd represents the research command
var researchCmd = &cobra.Command{
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
		fmt.Printf("Starting subnet scan for %s...\n", subnetStr) // Temporary feedback

		// NOTE: The actual OsintScan instance 'a' is not directly available here.
		// The results will need to be collected and then set on 'a.OutputSignal.Content'
		// after the loop. This requires modifying how 'a' is accessed, perhaps via context
		// or by changing the command structure slightly later.
		resultsChan, err := subnet.Scan(ctx, subnetStr, cfg)
		if err != nil {
			// Handle setup errors from Scan (e.g., invalid CIDR format, subnet too large)
			// In a real scenario, we'd use: a.OutputSignal.AddError(err)
			return fmt.Errorf("failed to initialize subnet scan: %w", err)
		}

		// 4. Add a loop: for report := range resultsChan { /* Do nothing for now */ }
		var collectedReports []*subnetgenerated.IpReport // Slice to hold results
		var isCancelled bool                             // Flag to track if context was cancelled

		fmt.Println("Scanning IPs...") // Indicate that scanning is in progress
		for report := range resultsChan {
			collectedReports = append(collectedReports, report)
			// Optional: Print progress (maybe behind a verbose flag later)
			// fmt.Printf("Received report for %s\n", report.Ip)
		}

		// Check if the context was cancelled (e.g., Ctrl-C pressed)
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				fmt.Println("\nScan cancelled by user.")
				isCancelled = true
				// Treat user cancellation as non-error completion for exit code
			} else {
				// Other context errors (like deadline exceeded, though less likely here)
				fmt.Printf("\nScan interrupted: %v\n", ctx.Err())
				isCancelled = true
				// Optionally, could return ctx.Err() here if other context errors should stop execution
				// return ctx.Err()
			}
		}

		// 5. Assemble and print the final report
		fmt.Println("Scan complete. Assembling final report...")

		finalReport := subnetgenerated.SubnetReport{
			Subnet:    subnetStr,
			TotalIps:  len(collectedReports), // Use int, not int32
			ScannedAt: time.Now().UTC(),
			Reports:   collectedReports,
			Cancelled: &isCancelled, // Use address of bool for optional field
			Metrics:   metrics,      // Assign the populated metrics
		}

		// Marshal to JSON with indentation
		jsonData, err := json.MarshalIndent(finalReport, "", "  ")
		if err != nil {
			// Handle JSON marshalling error
			return fmt.Errorf("failed to marshal final report to JSON: %w", err)
		}

		// Print the JSON report to stdout
		fmt.Println(string(jsonData))

		return nil // Return nil on successful completion (even if cancelled by user)
	},
}

// Init function for the researchCmd flags
func initResearchCmdFlags() {
	researchCmd.Flags().StringVarP(&subnetStr, "subnet", "s", "", "IPv4 subnet to research (e.g., 1.1.1.0/24, 8.8.8.8/32)")
	researchCmd.Flags().IntVarP(&workers, "workers", "w", 100, "Number of concurrent workers")
	researchCmd.Flags().IntVarP(&timeout, "timeout", "t", 3, "Timeout in seconds for network lookups") // Kept as int for flag parsing
	researchCmd.Flags().BoolVarP(&extended, "extended", "x", false, "Perform extended OSINT gathering")
	researchCmd.Flags().StringVarP(&resolver, "resolver", "r", "", "Custom DNS resolver address (e.g., 8.8.8.8:53)")
	researchCmd.Flags().StringVar(&apiKey, "asn-api-key", "", "API key for ASN lookups (from https://cloud.projectdiscovery.io). Alternatively, set PDCP_API_KEY env var")
	researchCmd.Flags().StringVar(&maxMindDB, "maxmind-db", "", "Path to MaxMind GeoIP2 ASN database")
	researchCmd.Flags().DurationVar(&ptrTimeout, "ptr-timeout", 400*time.Millisecond, "Per-PTR lookup timeout (e.g. 500ms, 1s)")
	err := researchCmd.MarkFlagRequired("subnet")
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

	// Initialize flags for subcommands
	initResearchCmdFlags()

	// Add subcommands to the parent command
	SubnetCmd.AddCommand(researchCmd)

	// Assign the configured command to the OsintScan struct field
	a.SubnetCmd = SubnetCmd

	// Add the parent command to the root command
	a.RootCmd.AddCommand(a.SubnetCmd)
}
