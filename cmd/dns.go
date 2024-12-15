package cmd

import (
	"errors"

	"github.com/Method-Security/osintscan/internal/dns"
	"github.com/Method-Security/osintscan/utils"
	"github.com/spf13/cobra"
)

// InitDNSCommand initializes the DNS command for the osintscan CLI that deals with gathering DNS records, certs, and subdomains.
func (a *OsintScan) InitDNSCommand() {
	a.DNSCmd = &cobra.Command{
		Use:   "dns",
		Short: "Scan and gather intel on DNS services",
		Long:  `Scan and gather intel on DNS services`,
	}

	certsCmd := &cobra.Command{
		Use:   "certs",
		Short: "Gather DNS certs for a given domain",
		Long:  `Gather DNS certs for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := dns.GetDomainCerts(cmd.Context(), domain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	certsCmd.Flags().String("domain", "", "Domain to get DNS certs for")

	recordCmd := &cobra.Command{
		Use:   "records",
		Short: "Gather DNS records for a given domain",
		Long:  `Gather DNS records for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := dns.GetDomainDNSRecords(cmd.Context(), domain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	recordCmd.Flags().String("domain", "", "Domain to get DNS records for")

	subenumCmd := &cobra.Command{
		Use:   "subenum",
		Short: "Enumerate subdomains for a given domain",
		Long:  `Enumerate subdomains for a given domain`,
	}

	subenumpassiveCmd := &cobra.Command{
		Use:   "passive",
		Short: "Passively enumerate subdomains for a given domain",
		Long:  `Passively enumerate subdomains for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := dns.GetDomainSubdomainsPassive(cmd.Context(), domain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	subenumpassiveCmd.Flags().String("domain", "", "Domain to get subdomains for")

	subenumCmd.AddCommand(subenumpassiveCmd)

	takeoverCmd := &cobra.Command{
		Use:   "takeover",
		Short: "Detect domain takeovers given a list of targets",
		Long:  `Detect domain takeovers given a list of targets`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filePaths, err := cmd.Flags().GetStringSlice("files")
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

			fingerprintsPath, err := cmd.Flags().GetString("fingerprints")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			onlySuccessful, err := cmd.Flags().GetBool("onlysuccessful")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			setHTTPS, err := cmd.Flags().GetBool("https")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := dns.DetectDomainTakeover(allTargets, fingerprintsPath, onlySuccessful, setHTTPS, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	takeoverCmd.Flags().StringSlice("targets", []string{}, "URL targets to analyze")
	takeoverCmd.Flags().String("fingerprints", "configs/fingerprints.json", "Path to fingerprints file")
	takeoverCmd.Flags().StringSlice("files", []string{}, "Paths to files containing the list of targets")
	takeoverCmd.Flags().Bool("onlysuccessful", false, "Only check sites with secure SSL")
	takeoverCmd.Flags().Bool("https", false, "Only check sites with secure SSL")
	takeoverCmd.Flags().Int("timeout", 10, "Request timeout in seconds")

	a.DNSCmd.AddCommand(recordCmd)
	a.DNSCmd.AddCommand(certsCmd)
	a.DNSCmd.AddCommand(subenumCmd)
	a.DNSCmd.AddCommand(takeoverCmd)
	a.RootCmd.AddCommand(a.DNSCmd)
}
