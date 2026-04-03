package cmd

import (
	"fmt"

	dnsfern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	"github.com/Method-Security/osintscan/internal/enumerate/dns/zonetransfer"
	"github.com/Method-Security/osintscan/utils"
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
		Use:   "zone-transfer",
		Short: "Attempt DNS zone transfers (AXFR) for zones",
		Long:  "For each zone FQDN, discovers authoritative nameservers via NS records, resolves their IPs, and attempts an AXFR against each DNS application to test for unauthorized zone transfers.",
		Run: func(cmd *cobra.Command, args []string) {
			zones, err := cmd.Flags().GetStringSlice("zones")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			dnsResolvers, err := cmd.Flags().GetStringSlice("dns-resolvers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			for _, dnsResolver := range dnsResolvers {
				if err = utils.ValidateDNSServerAddress(dnsResolver); err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS resolver %s: %w", dnsResolver, err))
					return
				}
			}

			targetNameservers, err := cmd.Flags().GetStringSlice("target-nameservers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			for _, ns := range targetNameservers {
				if err = utils.ValidateDNSServerAddress(ns); err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid target nameserver %s: %w", ns, err))
					return
				}
			}

			config := getEnumerateDNSZoneTransferConfig(zones, dnsResolvers, targetNameservers, timeout)

			report, err := zonetransfer.TestZoneTransfer(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateDNSZoneTransferCmd.Flags().StringSlice("zones", []string{}, "Zone FQDNs to test for unauthorized zone transfers (e.g. example.com)")

	// Config Flags
	enumerateDNSZoneTransferCmd.Flags().Int("timeout", 30, "Timeout in seconds for each zone transfer request")
	enumerateDNSZoneTransferCmd.Flags().StringSlice("dns-resolvers", []string{"1.1.1.1:53"}, "DNS resolvers to use for NS lookups and hostname resolution (e.g. 1.1.1.1:53)")
	enumerateDNSZoneTransferCmd.Flags().StringSlice("target-nameservers", []string{}, "Nameserver IPs to attempt AXFR against directly, bypassing NS record lookup (e.g. 10.0.0.1:53)")

	_ = enumerateDNSZoneTransferCmd.MarkFlagRequired("zones")

	enumerateDNSCmd.AddCommand(enumerateDNSZoneTransferCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}

// getEnumerateDNSZoneTransferConfig creates and returns a configuration for DNS zone transfer enumeration
func getEnumerateDNSZoneTransferConfig(zones []string, dnsResolvers []string, targetNameservers []string, timeout int) dnsfern.EnumerateDnsZoneTransferConfig {
	return dnsfern.EnumerateDnsZoneTransferConfig{
		Zones:             zones,
		DnsResolvers:      dnsResolvers,
		TargetNameservers: targetNameservers,
		Timeout:           timeout,
	}
}
