package cmd

import (
	"github.com/Method-Security/osintscan/internal/dns"
	"github.com/spf13/cobra"
)

// InitDNSCommand initializes the DNS command for the osintscan CLI that deals with gathering DNS records, certs, and subdomains.
func (a *OsintScan) InitDNSCommand() {
	a.DNSCmd = &cobra.Command{
		Use:   "dns",
		Short: "Scan and gather intel on DNS services",
		Long:  `Scan and gather intel on DNS services`,
	}

	recordCmd := &cobra.Command{
		Use:   "records",
		Short: "Gather DNS records for a given domain",
		Long:  `Gather DNS records for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := dns.GetDomainDNSRecords(cmd.Context(), domain)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	recordCmd.Flags().String("domain", "", "Domain to get DNS records for")

	certsCmd := &cobra.Command{
		Use:   "certs",
		Short: "Gather DNS certs for a given domain",
		Long:  `Gather DNS certs for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := dns.GetDomainCerts(cmd.Context(), domain)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	certsCmd.Flags().String("domain", "", "Domain to get DNS certs for")

	subenumCmd := &cobra.Command{
		Use:   "subenum",
		Short: "Passively enumerate subdomains for a given domain",
		Long:  `Passively enumerate subdomains for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := dns.GetDomainSubdomains(cmd.Context(), domain)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	subenumCmd.Flags().String("domain", "", "Domain to get subdomains for")

	a.DNSCmd.AddCommand(recordCmd)
	a.DNSCmd.AddCommand(certsCmd)
	a.DNSCmd.AddCommand(subenumCmd)
	a.RootCmd.AddCommand(a.DNSCmd)
}
