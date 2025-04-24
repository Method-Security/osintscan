package cmd

import (
	"context" // Needed for context
	"fmt"
	"net"
	"os"        // Needed for os.Interrupt
	"os/signal" // Needed for signal.NotifyContext
	"syscall"   // Needed for syscall signals
	"time"      // Needed for time.Duration

	// Import the internal subnet package
	"github.com/Method-Security/osintscan/internal/subnet"
	// NOTE: We will need imports for the actual implementation logic from internal/ later
	// subnetgenerated "github.com/Method-Security/osintscan/generated/go/subnet" // Needed later

	"github.com/spf13/cobra"
)

// Variables to hold flag values for the research subcommand
var (
	subnetStr string
	workers   int
	timeout   int // Timeout in seconds
	extended  bool
	resolver  string
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
		cfg := subnet.ScanConfig{
			Extended: extended,
			Timeout:  time.Duration(timeout) * time.Second, // Convert int seconds to time.Duration
			Workers:  workers,
			Resolver: resolver,
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
		// var collectedReports []*subnetgenerated.IpReport // Slice to hold results (needed later)
		fmt.Println("Scanning IPs...") // Indicate that scanning is in progress
		for report := range resultsChan {
			// TODO: Aggregate reports into a final SubnetReport structure.
			// For now, just consume the reports from the channel.
			_ = report // Use the report variable to avoid "unused" error.
			// If verbose logging is enabled, could print progress here:
			// svc1log.FromContext(ctx).Info("Received report", svc1log.SafeParam("ip", report.Ip))
		}

		// Check if the context was cancelled (e.g., Ctrl-C pressed)
		if ctx.Err() != nil && ctx.Err() != context.Canceled { // Ignore context.Canceled if it wasn't due to signal
			fmt.Println("\nScan interrupted.")
			// TODO: Set a 'cancelled: true' flag in the final report.
			// a.OutputSignal.AddError(ctx.Err()) // Report the cancellation
			return ctx.Err() // Propagate the context error (e.g., context.DeadlineExceeded or context.Canceled)
		}
		if ctx.Err() == context.Canceled {
			fmt.Println("\nScan cancelled by user.")
			// TODO: Set cancelled flag
			return nil // Treat user cancellation as non-error completion for exit code
		}

		// 5. After the loop, print a "Scan complete (stub)" message.
		fmt.Println("Scan complete (stub).") // Placeholder for final report generation/output

		// TODO: Assemble the final subnetgenerated.SubnetReport here using collectedReports
		// finalReport := subnetgenerated.SubnetReport{ ... }
		// a.OutputSignal.Content = finalReport // Set the final report for output

		return nil // Return nil on successful completion
	},
}

// Init function for the researchCmd flags
func initResearchCmdFlags() {
	researchCmd.Flags().StringVarP(&subnetStr, "subnet", "s", "", "IPv4 subnet to research (e.g., 1.1.1.0/24, 8.8.8.8/32)")
	researchCmd.Flags().IntVarP(&workers, "workers", "w", 100, "Number of concurrent workers")
	researchCmd.Flags().IntVarP(&timeout, "timeout", "t", 3, "Timeout in seconds for network lookups") // Kept as int for flag parsing
	researchCmd.Flags().BoolVarP(&extended, "extended", "x", false, "Perform extended OSINT gathering")
	researchCmd.Flags().StringVarP(&resolver, "resolver", "r", "", "Custom DNS resolver address (e.g., 8.8.8.8:53)")

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
