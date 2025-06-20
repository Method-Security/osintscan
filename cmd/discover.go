package cmd

import (
	"fmt"
	"os"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
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

	// Add command to the 'discover' command
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

			config := dnsfern.DiscoverDnsCertsConfig{
				Domain: domain,
			}

			report, err := dns.DiscoverDomainCerts(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSCertsCmd.Flags().String("domain", "", "The domain name to retrieve SSL/TLS certificates for")

	// Mark Required Flags
	_ = discoverDNSCertsCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
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

			config := dnsfern.DiscoverDnsRecordsConfig{
				Domain: domain,
			}

			report, err := dns.DiscoverDomainDNSRecords(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSRecordsCmd.Flags().String("domain", "", "The domain name to query for DNS records")

	// Mark Required Flags
	_ = discoverDNSRecordsCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSRecordsCmd)

	discoverDNSForwardReverseCmd := &cobra.Command{
		Use:   "forwardreverse",
		Short: "Perform forward and reverse DNS lookups",
		Long:  `Perform both forward and reverse DNS lookups for the specified domain to identify associated IPs and hostnames.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := dnsfern.DiscoverDnsForwardReverseConfig{
				Domain: domain,
			}

			report := dns.GetForwardReverseDNSLookup(config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSForwardReverseCmd.Flags().String("domain", "", "The domain name to perform forward and reverse lookups on")

	// Mark Required Flags
	_ = discoverDNSForwardReverseCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSForwardReverseCmd)

	discoverDNSSubdomainCmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Discover subdomains for a domain",
		Long:  `Discover subdomains for the specified domain using passive and active enumeration techniques.`,
	}

	discoverDNSCmd.AddCommand(discoverDNSSubdomainCmd)

	discoverDNSSubdomainPassiveCmd := &cobra.Command{
		Use:   "passive",
		Short: "Passively discover subdomains",
		Long:  `Identify subdomains for the specified domain using only passive data sources (no direct interaction with the target).`,
		Run: func(cmd *cobra.Command, args []string) {
			// Parse flags
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create config
			config := dnsfern.DiscoverDnsSubdomainConfig{
				DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypePassive)),
				Passive: &dnsfern.DiscoverDnsSubdomainPassiveConfig{
					Domain: domain,
				},
			}

			// Create report
			report, err := subdomain.GetDomainSubdomainsPassive(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSSubdomainPassiveCmd.Flags().String("domain", "", "The domain name to passively enumerate subdomains for")

	// Mark Required Flags
	_ = discoverDNSSubdomainPassiveCmd.MarkFlagRequired("domain")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainPassiveCmd)

	discoverDNSSubdomainActiveCmd := &cobra.Command{
		Use:   "active",
		Short: "Actively discover subdomains",
		Long:  `Actively discover subdomains for the specified domain by bruteforcing common subdomain names and patterns.`,
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

			wordlistFile, err := cmd.Flags().GetString("wordlist-file")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			wordlistSize, err := cmd.Flags().GetString("wordlist-size")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			var wordlistSubdomains []string
			var wordlistSizeEnum *dnsfern.WordlistSize

			// Priority 1: Use custom wordlist file if specified
			if wordlistFile != "" {
				wordlistSubdomains, err = utils.GetEntriesFromFiles([]string{wordlistFile})
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
			} else if wordlistSize != "" {
				// Priority 2: Use built-in wordlist if size specified
				wordlistSizeEnumValue, err := dnsfern.NewWordlistSizeFromString(wordlistSize)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				wordlistSizeEnum = &wordlistSizeEnumValue

				filePath := utils.GetDiscoverDNSSubdomainActiveWordlistPath(wordlistSize)
				if filePath != "" {
					wordlistSubdomains, err = utils.GetEntriesFromFiles([]string{filePath})
					if err != nil {
						a.OutputSignal.AddError(err)
						return
					}
				}
			}

			allSubdomains := append(subdomains, wordlistSubdomains...)

			// Fail if no subdomains are provided
			if len(allSubdomains) == 0 {
				a.OutputSignal.AddError(fmt.Errorf("no subdomains provided: specify either --subdomains, --wordlist-size, or --wordlist-file"))
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
			if dnsResolver != "" {
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
			}
			config := dnsfern.DiscoverDnsSubdomainConfig{
				DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypeActive)),
				Active: &dnsfern.DiscoverDnsSubdomainActiveConfig{
					Domain:       domain,
					Subdomains:   allSubdomains,
					WordlistSize: wordlistSizeEnum,
					WordlistFile: &wordlistFile,
					Threads:      threads,
					MaxDepth:     maxDepth,
					Timeout:      timeout,
					DnsResolver:  &dnsResolver,
				},
			}

			report, err := subdomain.GetDomainSubdomainsActive(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSSubdomainActiveCmd.Flags().String("domain", "", "The domain name to discover subdomains for")

	// Config Flags
	discoverDNSSubdomainActiveCmd.Flags().StringSlice("subdomains", []string{}, "A list of subdomain names to test during discovery")
	discoverDNSSubdomainActiveCmd.Flags().String("wordlist-size", "", "The size of the in-built wordlist to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().String("wordlist-file", "", "The file containing the wordlist to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("threads", 20, "Number of parallel threads to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("max-depth", 2, "Maximum recursion depth for subdomain discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("timeout", 0, "Maximum time (in minutes) to spend on subdomain discovery")
	discoverDNSSubdomainActiveCmd.Flags().String("dns-resolver", "", "Custom DNS resolver/server to use for queries (e.g. 1.1.1.1:53)")

	// Mark Required Flags
	_ = discoverDNSSubdomainActiveCmd.MarkFlagRequired("domain")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainActiveCmd)

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

	// Target Flags
	discoverShodanHostnameCmd.Flags().String("api-key", "", "Shodan API Key (defaults to SHODAN_API_KEY environment variable if not provided)")
	discoverShodanHostnameCmd.Flags().String("query", "", "The search query string to use with Shodan (e.g., 'apache', 'nginx')")
	discoverShodanHostnameCmd.Flags().String("hostname", "", "The hostname suffix to match in Shodan search results")

	// Mark Required Flags
	_ = discoverShodanHostnameCmd.MarkFlagRequired("query")
	_ = discoverShodanHostnameCmd.MarkFlagRequired("hostname")

	// Add command to 'shodan' command
	discoverShodanCmd.AddCommand(discoverShodanHostnameCmd)

	a.RootCmd.AddCommand(discoverCmd)
}
