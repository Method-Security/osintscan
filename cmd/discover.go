package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/Method-Security/osintscan/internal/dns"
	subdomain "github.com/Method-Security/osintscan/internal/dns/subdomain"
	"github.com/Method-Security/osintscan/internal/shodan"
	"github.com/Method-Security/osintscan/utils"
	"github.com/spf13/cobra"
)

func (a *OsintScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover DNS records, certs, subdomains and more",
		Long:  `Discover DNS records, certs, subdomains and more`,
	}

	discoverDNSCmd := &cobra.Command{
		Use:   "dns",
		Short: "Discover and gather intel on DNS services",
		Long:  `Discover and gather intel on DNS services`,
	}

	discoverCmd.AddCommand(discoverDNSCmd)

	discoverDNSCertsCmd := &cobra.Command{
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

	discoverDNSCertsCmd.Flags().String("domain", "", "Domain to get DNS certs for")
	discoverDNSCmd.AddCommand(discoverDNSCertsCmd)

	discoverDNSRecordsCmd := &cobra.Command{
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

	discoverDNSRecordsCmd.Flags().String("domain", "", "Domain to get DNS records for")
	discoverDNSCmd.AddCommand(discoverDNSRecordsCmd)
	discoverDNSReverseForwardCmd := &cobra.Command{
		Use:   "reverseforward",
		Short: "Reverse and forward lookup a given domain",
		Long:  `Reverse and forward lookup a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := dns.GetReverseForwardDNSLookup(domain)
			a.OutputSignal.Content = report
		},
	}

	discoverDNSReverseForwardCmd.Flags().String("domain", "", "Domain to get reverse and forward lookup for")
	_ = discoverDNSReverseForwardCmd.MarkFlagRequired("domain")
	discoverDNSCmd.AddCommand(discoverDNSReverseForwardCmd)

	discoverDNSSubdomainCmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Discover subdomains for a given domain",
		Long:  `Discover subdomains for a given domain`,
	}

	discoverDNSCmd.AddCommand(discoverDNSSubdomainCmd)

	discoverDNSSubdomainPassiveCmd := &cobra.Command{
		Use:   "passive",
		Short: "Passively discover subdomains for a given domain",
		Long:  `Passively discover subdomains for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := subdomain.GetDomainSubdomainsPassive(cmd.Context(), domain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	discoverDNSSubdomainPassiveCmd.Flags().String("domain", "", "Domain to get subdomains for")
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainPassiveCmd)

	discoverDNSSubdomainBruteCmd := &cobra.Command{
		Use:   "brute",
		Short: "Bruteforce subdomains for a given domain",
		Long:  `Bruteforce subdomains for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			subdomains, err := cmd.Flags().GetStringSlice("subdomain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			subdomainlistFiles, err := cmd.Flags().GetStringSlice("file")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			fileSubdomains, err := utils.GetEntriesFromFiles(subdomainlistFiles)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allSubdomains := append(subdomains, fileSubdomains...)
			if len(allSubdomains) == 0 {
				a.OutputSignal.AddError(errors.New("no subdomains provided"))
				return
			}

			parallelThreads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			recursiveDepth, err := cmd.Flags().GetInt("maxdepth")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			dnsServerAddress, err := cmd.Flags().GetString("dnsServerAddress")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := subdomain.GetDomainSubdomainsBrute(cmd.Context(), domain, allSubdomains, parallelThreads, recursiveDepth, timeout, dnsServerAddress)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverDNSSubdomainBruteCmd.Flags().String("domain", "", "Domain to get subdomains for")
	discoverDNSSubdomainBruteCmd.Flags().StringSlice("subdomain", []string{}, "List of subdomains to enumerate")
	discoverDNSSubdomainBruteCmd.Flags().StringSlice("file", []string{}, "List of files containing subdomains to enumerate")
	discoverDNSSubdomainBruteCmd.Flags().Int("threads", 20, "Number of parallel threads")
	discoverDNSSubdomainBruteCmd.Flags().Int("maxdepth", 3, "Maximum recursion depth")
	discoverDNSSubdomainBruteCmd.Flags().Int("timeout", 0, "Maximum time of enumeration (Minutes)")
	discoverDNSSubdomainBruteCmd.Flags().String("dnsServerAddress", "", "IP address + port of DNS server to use")

	_ = discoverDNSSubdomainBruteCmd.MarkFlagRequired("domain")

	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainBruteCmd)

	discoverShodanCmd := &cobra.Command{
		Use:   "shodan",
		Short: "Query Shodan for information",
		Long:  `Query Shodan for information`,
	}

	discoverCmd.AddCommand(discoverShodanCmd)

	discoverShodanHostnameCmd := &cobra.Command{
		Use:   "hostname",
		Short: "Query Shodan for a hostname string search",
		Long:  `Query Shodan for a hostname string search`,
		Run: func(cmd *cobra.Command, args []string) {
			var apiKey string
			var err error
			if os.Getenv("SHODAN_API_KEY") != "" {
				apiKey = os.Getenv("SHODAN_API_KEY")
			} else {
				apiKeyFlag, err := cmd.Flags().GetString("apikey")
				if err != nil {
					errorMessage := err.Error()
					a.OutputSignal.ErrorMessage = &errorMessage
					a.OutputSignal.Status = 1
					return
				}
				apiKey = apiKeyFlag
			}
			if apiKey == "" {
				err = fmt.Errorf("either SHODAN_API_KEY environment variable or --apikey must be set")
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			query, err := cmd.Flags().GetString("query")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			hostname, err := cmd.Flags().GetString("hostname")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := shodan.QueryShodanHostStrictHostnameMatch(cmd.Context(), apiKey, query, hostname)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	discoverShodanHostnameCmd.Flags().String("apikey", "", "Shodan API Key (reads from SHODAN_API_KEY env by default)")
	discoverShodanHostnameCmd.Flags().String("query", "", "Query string to search Shodan hostname:{} for")
	discoverShodanHostnameCmd.Flags().String("hostname", "", "The hostname suffix you want to ensure the Shodan record contains")
	discoverShodanCmd.AddCommand(discoverShodanHostnameCmd)

	a.RootCmd.AddCommand(discoverCmd)
}
