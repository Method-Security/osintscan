package cmd

import (
	"github.com/Method-Security/osintscan/internal/enumerate/dns/zonetransfer"
	"github.com/spf13/cobra"
)

func (a *OsintScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data using open-source intelligence techniques",
		Long:  `Enumerate information from various sources using open-source intelligence (OSINT) methods, focusing on DNS and related assets.`,
	}

	enumerateDNSCmd := &cobra.Command{
		Use:   "dns",
		Short: "Enumerate DNS-related information",
		Long:  `Enumerate DNS data, including zone transfers and other DNS-based intelligence gathering techniques.`,
	}

	enumerateCmd.AddCommand(enumerateDNSCmd)

	enumerateDNSZoneTransferCmd := &cobra.Command{
		Use:   "zonetransfer",
		Short: "Attempt DNS zone transfers (AXFR) for domains",
		Long:  `Attempt DNS zone transfers (AXFR) for the specified domains to enumerate all DNS records, if the server allows it. This can reveal all subdomains and records managed by the DNS server.`,
		Run: func(cmd *cobra.Command, args []string) {
			domains, err := cmd.Flags().GetStringSlice("domains")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := zonetransfer.TestZoneTransfer(cmd.Context(), domains, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateDNSZoneTransferCmd.Flags().StringSlice("domains", []string{}, "A list of domain names to attempt zone transfers on")
	// Config Flags
	enumerateDNSZoneTransferCmd.Flags().Int("timeout", 30, "Timeout in seconds for each zone transfer request")
	// Mark Required Flags
	_ = enumerateDNSZoneTransferCmd.MarkFlagRequired("domains")
	enumerateDNSCmd.AddCommand(enumerateDNSZoneTransferCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}
