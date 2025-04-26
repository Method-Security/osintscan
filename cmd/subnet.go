package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	subnetgenerated "github.com/Method-Security/osintscan/generated/go/subnet"
	"github.com/Method-Security/osintscan/internal/subnet"

	"github.com/spf13/cobra"
)

var (
	subnetStr  string
	workers    int
	timeout    int // Timeout in seconds
	extended   bool
	resolver   string
	apiKey     string // API key for ProjectDiscovery
	maxMindDB  string
	ptrTimeout time.Duration
)

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
		panic(fmt.Sprintf("Error marking 'subnet' flag required: %v", err))
	}
}

// InitSubnetCommand initializes the Subnet command group and its subcommands.
func (a *OsintScan) InitSubnetCommand() {
	SubnetCmd := &cobra.Command{
		Use:   "subnet",
		Short: "Perform research and analysis on subnets.",
		Long:  `Provides tools for researching and analyzing IPv4 subnets, including OSINT gathering.`,
	}

	researchCmd := &cobra.Command{
		Use:   "research",
		Short: "Perform OSINT research on an IPv4 subnet",
		Long:  `Performs OSINT research on an IPv4 subnet, gathering information like PTR records, ASN details, and ownership data for each IP address within the specified range.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

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

			metrics := &subnetgenerated.RunMetrics{} // Initialize metrics struct
			cfg := subnet.ScanConfig{
				Extended:   extended,                             // to do: extended mode
				Timeout:    time.Duration(timeout) * time.Second, // Convert int seconds to time.Duration
				Workers:    workers,
				Resolver:   resolver,
				ASNAPIKey:  apiKey,                 // Pass the API key to the scanner
				MaxMindDB:  maxMindDB,              // path to MaxMind GeoIP2 ASN database
				PoliteWait: 200 * time.Millisecond, // optional throttle for net providers
				PTRTimeout: ptrTimeout,             // Pass the parsed PTR timeout
				Metrics:    metrics,                // Pass pointer to metrics struct
			}

			resultsChan, err := subnet.Scan(ctx, subnetStr, cfg)
			if err != nil {
				errMsg := err.Error()
				a.OutputSignal.ErrorMessage = &errMsg
				a.OutputSignal.Status = 1
				return nil
			}

			var collectedReports []*subnetgenerated.IpReport
			var isCancelled bool

			for report := range resultsChan {
				collectedReports = append(collectedReports, report)
			}

			// Check if the context was cancelled (e.g., Ctrl-C pressed)
			if ctx.Err() != nil {
				if ctx.Err() == context.Canceled {
					isCancelled = true
				} else {
					isCancelled = true
					errMsg := fmt.Sprintf("Scan interrupted: %v", ctx.Err())
					a.OutputSignal.ErrorMessage = &errMsg
					a.OutputSignal.Status = 1
					return nil
				}
			}

			finalReport := subnetgenerated.SubnetReport{
				Subnet:    subnetStr,
				TotalIps:  len(collectedReports),
				ScannedAt: time.Now().UTC(),
				Reports:   collectedReports,
				Cancelled: &isCancelled,
				Metrics:   metrics,
			}
			a.OutputSignal.Content = finalReport

			return nil
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
