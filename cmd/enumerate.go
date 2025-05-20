package cmd

import (
	zonetransfer "github.com/Method-Security/osintscan/internal/dns/zonetransfer"
	"github.com/spf13/cobra"
)

func (a *OsintScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate information using open-source intelligence sources",
		Long:  `Enumerate information using open-source intelligence sources`,
	}

	enumerateDNSCmd := &cobra.Command{
		Use:   "dns",
		Short: "Enumerate information about DNS services",
		Long:  `Enumerate information about DNS services`,
	}

	enumerateCmd.AddCommand(enumerateDNSCmd)

	enumerateDNSZoneTransferCmd := &cobra.Command{
		Use:   "zonetransfer",
		Short: "Perform zone transfers for a given domain",
		Long:  `Perform zone transfers for a given domain`,
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

	enumerateDNSZoneTransferCmd.Flags().StringSlice("domains", []string{}, "Domains to perform zone transfers for")
	enumerateDNSZoneTransferCmd.Flags().Int("timeout", 30, "Request timeout in seconds")
	_ = enumerateDNSZoneTransferCmd.MarkFlagRequired("domains")
	enumerateDNSCmd.AddCommand(enumerateDNSZoneTransferCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}
