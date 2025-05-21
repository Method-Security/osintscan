package cmd

import (
	"errors"
	"fmt"
	"os"

	dns "github.com/Method-Security/osintscan/internal/discover/dns"
	subdomain "github.com/Method-Security/osintscan/internal/discover/dns/subdomain"
	shodan "github.com/Method-Security/osintscan/internal/discover/shodan"
	"github.com/Method-Security/osintscan/utils"
	"github.com/spf13/cobra"
)

func (a *OsintScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover DNS assets such as records, certificates, and subdomains",
		Long:  `Collect detailed information about DNS assets, including records, certificates, and subdomains, using various discovery techniques.`,
	}

	discoverDNSCmd := &cobra.Command{
		Use:   "dns",
		Short: "Gather intelligence on DNS services and assets",
		Long:  `Discover and analyze DNS services, including records, certificates, and subdomains for a given domain.`,
	}

	discoverCmd.AddCommand(discoverDNSCmd)

	discoverDNSCertsCmd := &cobra.Command{
		Use:   "certs",
		Short: "Retrieve SSL/TLS certificates for a domain",
		Long:  `Fetch and display SSL/TLS certificates associated with the specified domain, including certificate chains and metadata.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := dns.DiscoverDomainCerts(cmd.Context(), domain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	discoverDNSCertsCmd.Flags().String("domain", "", "The domain name to retrieve SSL/TLS certificates for")
	_ = discoverDNSCertsCmd.MarkFlagRequired("domain")
	discoverDNSCmd.AddCommand(discoverDNSCertsCmd)

	discoverDNSRecordsCmd := &cobra.Command{
		Use:   "records",
		Short: "Fetch DNS records for a domain",
		Long:  `Query and display all DNS records (A, AAAA, MX, TXT, etc.) for the specified domain.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := dns.DiscoverDomainDNSRecords(cmd.Context(), domain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	discoverDNSRecordsCmd.Flags().String("domain", "", "The domain name to query for DNS records")
	_ = discoverDNSRecordsCmd.MarkFlagRequired("domain")
	discoverDNSCmd.AddCommand(discoverDNSRecordsCmd)

	discoverDNSReverseForwardCmd := &cobra.Command{
		Use:   "reverseforward",
		Short: "Perform reverse and forward DNS lookups",
		Long:  `Perform both reverse and forward DNS lookups for the specified domain to identify associated IPs and hostnames.`,
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

	discoverDNSReverseForwardCmd.Flags().String("domain", "", "The domain name to perform reverse and forward lookups on")
	_ = discoverDNSReverseForwardCmd.MarkFlagRequired("domain")
	discoverDNSCmd.AddCommand(discoverDNSReverseForwardCmd)

	discoverDNSSubdomainCmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Enumerate subdomains for a domain",
		Long:  `Discover subdomains for the specified domain using passive and active enumeration techniques.`,
	}

	discoverDNSCmd.AddCommand(discoverDNSSubdomainCmd)

	discoverDNSSubdomainPassiveCmd := &cobra.Command{
		Use:   "passive",
		Short: "Passively enumerate subdomains",
		Long:  `Identify subdomains for the specified domain using only passive data sources (no direct interaction with the target).`,
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

	discoverDNSSubdomainPassiveCmd.Flags().String("domain", "", "The domain name to passively enumerate subdomains for")
	_ = discoverDNSSubdomainPassiveCmd.MarkFlagRequired("domain")
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainPassiveCmd)

	discoverDNSSubdomainBruteCmd := &cobra.Command{
		Use:   "brute",
		Short: "Actively bruteforce subdomains",
		Long:  `Actively enumerate subdomains for the specified domain by bruteforcing common subdomain names and patterns.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			subdomains, err := cmd.Flags().GetStringSlice("subdomains")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			subdomainlistFiles, err := cmd.Flags().GetStringSlice("files")
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

			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxDepth, err := cmd.Flags().GetInt("max-depth")
			if err != nil {
				a.OutputSignal.AddError(err)
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

			report, err := subdomain.GetDomainSubdomainsBrute(cmd.Context(), domain, allSubdomains, threads, maxDepth, timeout, dnsResolver)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverDNSSubdomainBruteCmd.Flags().String("domain", "", "The domain name to bruteforce subdomains for")
	discoverDNSSubdomainBruteCmd.Flags().StringSlice("subdomains", []string{}, "A list of subdomain names to test during bruteforce discovery")
	discoverDNSSubdomainBruteCmd.Flags().StringSlice("files", []string{}, "File paths containing lists of subdomains to use for bruteforce discovery")
	discoverDNSSubdomainBruteCmd.Flags().Int("threads", 20, "Number of parallel threads to use for bruteforce discovery")
	discoverDNSSubdomainBruteCmd.Flags().Int("max-depth", 3, "Maximum recursion depth for subdomain bruteforce")
	discoverDNSSubdomainBruteCmd.Flags().Int("timeout", 0, "Maximum time (in minutes) to spend on subdomain discovery")
	discoverDNSSubdomainBruteCmd.Flags().String("dns-resolver", "", "Custom DNS resolver/server to use for queries")

	_ = discoverDNSSubdomainBruteCmd.MarkFlagRequired("domain")

	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainBruteCmd)

	discoverShodanCmd := &cobra.Command{
		Use:   "shodan",
		Short: "Query Shodan for host and service information",
		Long:  `Search Shodan for information about hosts, services, and vulnerabilities using the Shodan API.`,
	}

	discoverCmd.AddCommand(discoverShodanCmd)

	discoverShodanHostnameCmd := &cobra.Command{
		Use:   "hostname",
		Short: "Search Shodan for a specific hostname",
		Long:  `Query Shodan for information about a specific hostname, filtering results to match the provided hostname suffix.`,
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

	discoverShodanHostnameCmd.Flags().String("api-key", "", "Shodan API Key (defaults to SHODAN_API_KEY environment variable if not provided)")
	discoverShodanHostnameCmd.Flags().String("query", "", "The search query string to use with Shodan (e.g., 'apache', 'nginx')")
	discoverShodanHostnameCmd.Flags().String("hostname", "", "The hostname suffix to match in Shodan search results")
	_ = discoverShodanHostnameCmd.MarkFlagRequired("query")
	_ = discoverShodanHostnameCmd.MarkFlagRequired("hostname")
	discoverShodanCmd.AddCommand(discoverShodanHostnameCmd)

	a.RootCmd.AddCommand(discoverCmd)
}
