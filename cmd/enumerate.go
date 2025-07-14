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
		Use:   "zonetransfer [domain...]",
		Short: "Attempt DNS zone transfers (AXFR) for domains",
		Long:  "Attempt DNS zone transfers (AXFR) for the specified domains to enumerate all DNS records, if the server allows it. This can reveal all subdomains and records",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			// Get domains from both flags and positional arguments
			domains, err := cmd.Flags().GetStringSlice("domains")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			nameserver, err := cmd.Flags().GetString("nameserver")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			if len(domains) == 0 && nameserver == "" {
				a.OutputSignal.AddError(fmt.Errorf("at least one domain or nameserver must be specified"))
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			dnsResolver, err := cmd.Flags().GetString("dns-resolver")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if dnsResolver != "" {
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
			}

			config := getEnumerateDnsZoneTransferConfig(domains, nameserver, dnsResolver, timeout)

			report, err := zonetransfer.TestZoneTransfer(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateDNSZoneTransferCmd.Flags().StringSlice("domains", []string{}, "A list of domain names to attempt zone transfers on")
	enumerateDNSZoneTransferCmd.Flags().String("nameserver", "", "Specific nameserver to test zone transfers against (e.g., ns1.example.com or 192.168.1.10)")

	// Config Flags
	enumerateDNSZoneTransferCmd.Flags().Int("timeout", 30, "Timeout in seconds for each zone transfer request")
	enumerateDNSZoneTransferCmd.Flags().String("dns-resolver", "", "Custom DNS resolver for NS lookups (e.g. 1.1.1.1:53). Only used when --nameserver is not specified")

	enumerateDNSCmd.AddCommand(enumerateDNSZoneTransferCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}

// getEnumerateDnsZoneTransferConfig creates and returns a configuration for DNS zone transfer enumeration
func getEnumerateDnsZoneTransferConfig(domains []string, nameserver, dnsResolver string, timeout int) dnsfern.EnumerateDnsZoneTransferConfig {
	return dnsfern.EnumerateDnsZoneTransferConfig{
		Domains:     domains,
		Nameserver:  &nameserver,
		DnsResolver: &dnsResolver,
		Timeout:     timeout,
	}
}
