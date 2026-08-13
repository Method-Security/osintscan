package cmd

import (
	// Standard
	"errors"
	// Generated
	dnsfern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	// Internal
	takeover "github.com/Method-Security/osintscan/internal/enumerate/dns/takeover"
	// External
	"github.com/spf13/cobra"
	// Utils
	"github.com/Method-Security/osintscan/utils"
)

func (a *OsintScan) InitEnumerateCommand() {
	// Enumerate Command
	// Subcommands:
	// - dns
	//   - takeover
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Actively enumerate detail about discovered assets",
		Long:  `Actively gather deeper detail about assets found during discovery, using public data sources and the providers those assets point at.`,
	}

	enumerateDNSCmd := &cobra.Command{
		Use:   "dns",
		Short: "Enumerate detail about DNS assets",
		Long:  `Actively enumerate deeper detail about DNS assets for a given set of targets.`,
	}

	enumerateCmd.AddCommand(enumerateDNSCmd)

	enumerateDNSTakeoverCmd := &cobra.Command{
		Use:   "takeover",
		Short: "Detect potential subdomain takeovers",
		Long: `Analyze the provided targets to identify DNS records that may be vulnerable to subdomain takeover attacks, using known fingerprints and heuristics.

This detects a claimable record; it does not claim it. The CNAME lookup and the
HTTP request both go to the third-party provider the record dangles at, never to
infrastructure the target still controls.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filePaths, err := cmd.Flags().GetStringSlice("target-files")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fileTargets, err := utils.GetEntriesFromFiles(filePaths)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			allTargets := append(targets, fileTargets...)
			if len(allTargets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets specified"))
				return
			}

			// Config
			fingerprintsPath, err := cmd.Flags().GetString("fingerprints-file")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fingerprints, err := takeover.RetrieveFingerprints(fingerprintsPath)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no fingerprints found"))
				return
			}

			successfulOnly, err := cmd.Flags().GetBool("successful-only")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := getDNSTakeoverConfig(allTargets, fileTargets, fingerprintsPath, successfulOnly, verifyTLS, timeout)

			report, err := takeover.DetectDomainTakeover(cmd.Context(), config, fingerprints)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateDNSTakeoverCmd.Flags().StringSlice("targets", []string{}, "A list of URLs or domains to analyze for takeover vulnerabilities")
	enumerateDNSTakeoverCmd.Flags().StringSlice("target-files", []string{}, "File paths containing lists of targets to analyze for takeover vulnerabilities")
	// Config Flags
	enumerateDNSTakeoverCmd.Flags().String("fingerprints-file", "", "Path to the JSON file containing service fingerprints for takeover detection")
	enumerateDNSTakeoverCmd.Flags().Bool("successful-only", false, "Show only confirmed successful takeovers in the results")
	enumerateDNSTakeoverCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests during takeover analysis")
	enumerateDNSTakeoverCmd.Flags().Int("timeout", 180, "Timeout in seconds for each takeover check request")

	// Mark Required Flags
	_ = enumerateDNSTakeoverCmd.MarkFlagRequired("targets")

	// Add command to 'dns' command
	enumerateDNSCmd.AddCommand(enumerateDNSTakeoverCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}

func getDNSTakeoverConfig(targets []string, targetFiles []string, fingerprintsFile string, successfulOnly bool, verifyTLS bool, timeout int) dnsfern.EnumerateDomainTakeoverConfig {
	config := dnsfern.EnumerateDomainTakeoverConfig{
		Targets:        targets,
		TargetFiles:    targetFiles,
		SuccessfulOnly: successfulOnly,
		VerifyTls:      verifyTLS,
	}
	if fingerprintsFile != "" {
		config.FingerprintsFile = &fingerprintsFile
	}

	if timeout >= 0 {
		config.Timeout = timeout
	} else {
		config.Timeout = 30
	}

	return config
}
