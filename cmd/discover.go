package cmd

import (
	// Standard
	"fmt"
	"net"
	"os"
	"strings"

	// Generated
	common "github.com/Method-Security/osintscan/generated/go/common"
	asnfern "github.com/Method-Security/osintscan/generated/go/discover/asn"
	cdnfern "github.com/Method-Security/osintscan/generated/go/discover/cdn"
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	idpfern "github.com/Method-Security/osintscan/generated/go/discover/idp"
	ipfern "github.com/Method-Security/osintscan/generated/go/discover/ip"

	// Internal
	discover "github.com/Method-Security/osintscan/internal/discover"
	dns "github.com/Method-Security/osintscan/internal/discover/dns"
	cctld "github.com/Method-Security/osintscan/internal/discover/dns/cctld"
	subdomain "github.com/Method-Security/osintscan/internal/discover/dns/subdomain"
	subdomainpassive "github.com/Method-Security/osintscan/internal/discover/dns/subdomain/passive"
	ip "github.com/Method-Security/osintscan/internal/discover/ip"

	// External
	shodan "github.com/Method-Security/osintscan/internal/discover/shodan"
	"github.com/spf13/cobra"

	// Configs
	"github.com/Method-Security/osintscan/configs"
	// Utils
	"github.com/Method-Security/osintscan/utils"
)

func (a *OsintScan) InitDiscoverCommand() {
	// Discover Command
	// Subcommands:
	// - asn
	// - cdn
	// - dns
	// - ip
	// - shodan
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover DNS assets such as records, certificates, and subdomains",
		Long:  `Collect detailed information about DNS assets, including records, certificates, and subdomains, using various discovery techniques.`,
	}

	// ASN Command
	discoverASNCmd := &cobra.Command{
		Use:   "asn",
		Short: "Discover ASN information",
		Long:  `Discover information about ASN, including ASN description, CIDRs, country, and other metadata. This relies on BGPView's API and has built in retry and timeout mechanisms.`,
		Run: func(cmd *cobra.Command, args []string) {
			asnFlag, err := cmd.Flags().GetString("asn")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config := getDiscoverASNConfig(asnFlag, timeout)
			report, err := discover.GetASNInfo(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverASNCmd.Flags().String("asn", "", "The ASN number to lookup (e.g., AS23028 or 23028)")
	discoverASNCmd.Flags().Int("timeout", 120, "The timeout in seconds for the ASN lookup")

	// Mark Required Flags
	_ = discoverASNCmd.MarkFlagRequired("asn")

	// Add command to 'discover' command
	discoverCmd.AddCommand(discoverASNCmd)

	// DNS Commands
	// Subcommands:
	// - certs
	// - records
	// - forward
	// - reverse
	// - subdomain
	//   - active
	//   - passive
	discoverDNSCmd := &cobra.Command{
		Use:   "dns",
		Short: "Gather intelligence on DNS services and assets",
		Long:  `Discover and analyze DNS services, including records, certificates, and subdomains for a given domain.`,
	}

	// Add command to the 'discover' command
	discoverCmd.AddCommand(discoverDNSCmd)

	// Certs Command
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

			config := getDiscoverDNSCertsConfig(domain)

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

	// Records Command
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

			recordTypes, err := cmd.Flags().GetStringSlice("record-types")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			for _, recordType := range recordTypes {
				_, err := common.NewDnsRecordTypeFromString(recordType)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS record type: %s", recordType))
					return
				}
			}

			dnsResolvers, err := cmd.Flags().GetStringSlice("dns-resolvers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			useTCP, err := cmd.Flags().GetBool("use-tcp")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create config
			config := getDiscoverDNSRecordsConfig(domain, recordTypes, dnsResolvers, useTCP, timeout)

			// Create report
			report := dns.DiscoverDomainDNSRecords(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSRecordsCmd.Flags().String("domain", "", "The domain name to query for DNS records")
	discoverDNSRecordsCmd.Flags().StringSlice("record-types", []string{"ALL"}, "Comma-separated list of DNS record types to query (A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, ALL)")
	discoverDNSRecordsCmd.Flags().StringSlice("dns-resolvers", []string{}, "DNS resolvers to use for record lookups (e.g. 10.0.0.1:53).")
	discoverDNSRecordsCmd.Flags().Bool("use-tcp", false, "Query DNS resolvers over TCP instead of UDP")
	discoverDNSRecordsCmd.Flags().Int("timeout", 10, "Per-query timeout in seconds")

	// Mark Required Flags
	_ = discoverDNSRecordsCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSRecordsCmd)

	// Forward-Reverse Command
	discoverDNSForwardCmd := &cobra.Command{
		Use:   "forward",
		Short: "Perform forward DNS lookups",
		Long:  `Perform forward DNS lookups for the specified domain to identify associated IPs.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			dnsResolvers, err := cmd.Flags().GetStringSlice("dns-resolvers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config := getDiscoverDNSForwardConfig(domain, dnsResolvers)

			report := dns.GetForwardDNSLookup(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSForwardCmd.Flags().String("domain", "", "The domain name to perform forward lookups on")
	discoverDNSForwardCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 10.0.0.1).")

	// Mark Required Flags
	_ = discoverDNSForwardCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSForwardCmd)

	// Reverse Command
	discoverDNSReverseCmd := &cobra.Command{
		Use:   "reverse",
		Short: "Perform a reverse DNS lookup on a single IP, list of IPs, or a CIDR range",
		Long:  `Perform a reverse DNS lookup on a single IP, list of IPs, or a CIDR range.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Target Flags
			ips, err := cmd.Flags().GetStringSlice("ip-addresses")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			cidr, err := cmd.Flags().GetString("cidr")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(ips) == 0 && cidr == "" {
				a.OutputSignal.AddError(fmt.Errorf("either --ip-addresses or --cidr must be provided"))
				return
			}

			// Config Flags
			dnsResolvers, err := cmd.Flags().GetStringSlice("dns-resolvers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create config
			config := getDiscoverDNSReverseConfig(ips, cidr, dnsResolvers, threads)

			// Create report
			report := dns.GetReverseLookup(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSReverseCmd.Flags().StringSlice("ip-addresses", []string{}, "The IP addresses to perform reverse DNS lookup on")
	discoverDNSReverseCmd.Flags().String("cidr", "", "The CIDR range to perform reverse DNS lookup on")
	discoverDNSReverseCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 10.0.0.1).")
	discoverDNSReverseCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSReverseCmd)

	// subdomain Cmd
	// Subcommands:
	//  - active
	//  - passive
	discoverDNSSubdomainCmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Discover subdomains for a domain",
		Long:  `Discover subdomains for the specified domain using passive and active enumeration techniques`,
	}

	discoverDNSCmd.AddCommand(discoverDNSSubdomainCmd)

	// Active Command
	discoverDNSSubdomainActiveCmd := &cobra.Command{
		Use:   "active",
		Short: "Actively discover subdomains",
		Long:  `Actively discover subdomains for the specified domain by bruteforcing common subdomain names and patterns.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Parse domains
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Parse config flags
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

				embeddedPath := subdomain.GetDiscoverDNSSubdomainActiveWordlistEmbeddedPath(wordlistSize)
				if embeddedPath != "" {
					wordlistSubdomains, err = configs.ReadLines(embeddedPath)
					if err != nil {
						a.OutputSignal.AddError(err)
						return
					}
				}
			}
			allSubdomains := append(subdomains, wordlistSubdomains...)

			if len(allSubdomains) == 0 {
				a.OutputSignal.AddError(fmt.Errorf("no subdomains provided"))
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
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			wildcardChecks, err := cmd.Flags().GetInt("wildcard-checks")
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
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS resolver: %w", err))
					return
				}
			}
			config := getDiscoverDNSActiveSubdomainConfig(domain, wordlistSizeEnum, &wordlistFile, threads, maxDepth, timeout, sleep, wildcardChecks, dnsResolvers)

			report, err := subdomain.GetDomainSubdomainsActive(cmd.Context(), allSubdomains, config)
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
	discoverDNSSubdomainActiveCmd.Flags().String("wordlist-size", "SMALL", "The size of the in-built wordlist to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().String("wordlist-file", "", "The file containing the wordlist to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("threads", 100, "Number of parallel threads to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("max-depth", 1, "Maximum recursion depth for subdomain discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("timeout", 65, "Maximum time (in minutes) to spend on subdomain discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("sleep", 0, "Sleep time in milliseconds between requests to avoid rate limiting")
	discoverDNSSubdomainActiveCmd.Flags().Int("wildcard-checks", 5, "Number of random subdomain probes used to detect wildcard DNS records")
	discoverDNSSubdomainActiveCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 10.0.0.1).")

	// Mark Required Flags
	_ = discoverDNSSubdomainActiveCmd.MarkFlagRequired("domain")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainActiveCmd)

	// Passive Command
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

			// Config Flags
			requestsPerSecond, err := cmd.Flags().GetInt("requests-per-second")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allSources, err := cmd.Flags().GetBool("all-sources")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			modules, err := cmd.Flags().GetStringSlice("modules")
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
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS resolver: %w", err))
					return
				}
			}
			maxDNSQueries, err := cmd.Flags().GetInt("max-dns-queries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxResolversQPS, err := cmd.Flags().GetInt("max-resolvers-qps")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			recursiveDepth, err := cmd.Flags().GetInt("recursive-depth")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create config
			config, err := getDiscoverDNSPassiveSubdomainConfig(domain, requestsPerSecond, threads, allSources, modules, dnsResolvers, maxDNSQueries, maxResolversQPS, recursiveDepth)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create report
			report, err := subdomainpassive.GetDomainSubdomainsPassive(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSSubdomainPassiveCmd.Flags().String("domain", "", "The domain name to passively enumerate subdomains for")
	discoverDNSSubdomainPassiveCmd.Flags().Int("requests-per-second", 0, "Maximum number of requests per second to send to the DNS resolvers")
	discoverDNSSubdomainPassiveCmd.Flags().Int("threads", 50, "Number of concurrent threads for scanning")
	discoverDNSSubdomainPassiveCmd.Flags().Bool("all-sources", true, "Use all passive sources (subfinder equivalent of --all)")
	discoverDNSSubdomainPassiveCmd.Flags().StringSlice("modules", []string{"SUBFINDER"}, "Which passive modules to run: SUBFINDER, AMASS, or ALL")
	discoverDNSSubdomainPassiveCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 10.0.0.1).")
	discoverDNSSubdomainPassiveCmd.Flags().Int("max-dns-queries", 2000, "Maximum number of DNS queries to perform per request")
	discoverDNSSubdomainPassiveCmd.Flags().Int("max-resolvers-qps", 20, "Maximum number of queries per second per resolver")
	discoverDNSSubdomainPassiveCmd.Flags().Int("recursive-depth", 0, "Recursive discovery depth (0=none, 1=re-scan discovered domains, 2=two levels deep, etc.)")

	// Mark Required Flags
	_ = discoverDNSSubdomainPassiveCmd.MarkFlagRequired("domain")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainPassiveCmd)

	// ccTLD Command
	discoverDNSCctldCmd := &cobra.Command{
		Use:   "cctld",
		Short: "Pivot across ccTLDs to discover lookalike apex domains",
		Long:  `Permute <base>.<tld> candidates across a list or preset of country-code TLDs to discover lookalike or alt-region apex domains. Resolves DNS (A, AAAA, NS, MX) records for each candidate.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			cctlds, err := cmd.Flags().GetStringSlice("cctlds")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			cctldsPreset, err := cmd.Flags().GetString("cctlds-preset")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			if len(cctlds) == 0 && cctldsPreset == "" {
				a.OutputSignal.AddError(fmt.Errorf("either --cctlds or --cctlds-preset must be provided"))
				return
			}

			threads, err := cmd.Flags().GetInt("threads")
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
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS resolver: %w", err))
					return
				}
			}

			config, err := getDiscoverDNSCctldConfig(domain, cctlds, cctldsPreset, threads, timeout, dnsResolvers)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := cctld.PivotCcTLD(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSCctldCmd.Flags().String("domain", "", "The domain name to pivot ccTLDs from (e.g. acme.com)")
	discoverDNSCctldCmd.Flags().StringSlice("cctlds", []string{}, "Explicit list of ccTLD labels to test (e.g. ru,cn,de)")
	discoverDNSCctldCmd.Flags().String("cctlds-preset", "", "Named preset of ccTLDs: APT_RELEVANT, TOP50, EU27, ASEAN, ALL")
	discoverDNSCctldCmd.Flags().Int("threads", 50, "Number of concurrent DNS probe goroutines")
	discoverDNSCctldCmd.Flags().Int("timeout", 5000, "Per-request timeout in milliseconds for DNS probes")
	discoverDNSCctldCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 1.1.1.1,8.8.8.8)")

	// Mark Required Flags
	_ = discoverDNSCctldCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSCctldCmd)

	// Shodan Command
	// Subcommands:
	// - hostname
	discoverShodanCmd := &cobra.Command{
		Use:   "shodan",
		Short: "Query Shodan for host and service information",
		Long:  `Search Shodan for information about hosts, services, and vulnerabilities using the Shodan API.`,
	}

	discoverCmd.AddCommand(discoverShodanCmd)

	// Hostname Command
	discoverShodanHostnameCmd := &cobra.Command{
		Use:   "hostname",
		Short: "Search Shodan for a specific hostname",
		Long:  `Query Shodan for information about a specific hostname, filtering results to match the provided hostname suffix.`,
		Run: func(cmd *cobra.Command, args []string) {
			var apiKey string
			if os.Getenv("SHODAN_API_KEY") != "" {
				apiKey = os.Getenv("SHODAN_API_KEY")
			} else {
				apiKeyFlag, err := cmd.Flags().GetString("api-key")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				apiKey = apiKeyFlag
			}
			if apiKey == "" {
				a.OutputSignal.AddError(fmt.Errorf("either SHODAN_API_KEY environment variable or --api-key must be set"))
				return
			}

			query, err := cmd.Flags().GetString("query")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			hostname, err := cmd.Flags().GetString("hostname")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := shodan.QueryShodanHostStrictHostnameMatch(cmd.Context(), apiKey, query, hostname)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverShodanHostnameCmd.Flags().String("api-key", "", "Shodan API Key")
	discoverShodanHostnameCmd.Flags().String("query", "", "The search query string to use with Shodan (e.g., 'apache', 'nginx')")
	discoverShodanHostnameCmd.Flags().String("hostname", "", "The hostname suffix to match in Shodan search results")

	// Mark Required Flags
	_ = discoverShodanHostnameCmd.MarkFlagRequired("query")
	_ = discoverShodanHostnameCmd.MarkFlagRequired("hostname")

	// Add command to 'shodan' command
	discoverShodanCmd.AddCommand(discoverShodanHostnameCmd)

	// IdP Command
	discoverIdpCmd := &cobra.Command{
		Use:   "idp",
		Short: "Discover identity providers for a domain",
		Long:  `Detect identity providers (Azure AD/Entra ID, Okta, etc.) associated with a domain by querying public endpoints, DNS records, and federation metadata.`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := getDiscoverIdpConfig(domain, timeout)
			report, err := discover.DiscoverIdp(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	discoverIdpCmd.Flags().String("domain", "", "The domain name to discover identity providers for")
	discoverIdpCmd.Flags().Int("timeout", 30, "The timeout in seconds for each HTTP request")

	_ = discoverIdpCmd.MarkFlagRequired("domain")

	discoverCmd.AddCommand(discoverIdpCmd)

	// CDN Command
	discoverCdnCmd := &cobra.Command{
		Use:   "cdn",
		Short: "Discover CDN providers for IP addresses",
		Long:  `Check if an IP address belongs to a known CDN provider by comparing against known CDN IP ranges.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Parse flags
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ipAddresses, err := cmd.Flags().GetStringSlice("ip-addresses")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fingerprintsFile, err := cmd.Flags().GetString("fingerprints-file")
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
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS resolver: %w", err))
					return
				}
			}

			// Create config
			config := getDiscoverCdnConfig(domain, ipAddresses, dnsResolvers, fingerprintsFile)

			// Create report
			report := discover.RunDiscoverCdns(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverCdnCmd.Flags().String("domain", "", "The domain name to check against CDN provider ranges")
	discoverCdnCmd.Flags().StringSlice("ip-addresses", []string{}, "IP addresses or CIDRs to check (e.g. 1.2.3.4 or 1.2.3.0/24)")
	discoverCdnCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 10.0.0.1).")
	discoverCdnCmd.Flags().String("fingerprints-file", "", "The path to the CDN fingerprints file")

	// Mark Required Flags
	_ = discoverCdnCmd.MarkFlagRequired("domain")

	// Add command to the 'discover' command
	discoverCmd.AddCommand(discoverCdnCmd)

	// IP Address Command
	// Subcommands:
	// - domain-asn
	// - reverse
	discoverIPCmd := &cobra.Command{
		Use:   "ip",
		Short: "Discover IP address and CIDR information",
		Long:  `Discover information about IP addresses or CIDR Ranges including linked domains, ASN, geolocation.`,
	}

	// Add discoverIPCmd to the 'discover' command
	discoverCmd.AddCommand(discoverIPCmd)

	// Domain ASN Command
	discoverIPDomainASNCmd := &cobra.Command{
		Use:   "domain-asn",
		Short: "Perform a reverse DNS lookup and ASN lookup on a single IP, list of IPs, or a CIDR range",
		Long:  `Perform a reverse DNS lookup and ASN lookup on a single IP, list of IPs, or a CIDR range. Warning: /16 and larger can take upwards of 30 minutes.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Parse flags
			ips, err := cmd.Flags().GetStringSlice("ip-addresses")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			cidr, err := cmd.Flags().GetString("cidr")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			dnsResolvers, err := cmd.Flags().GetStringSlice("dns-resolvers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate that either ip or cidr is provided
			if len(ips) == 0 && cidr == "" {
				a.OutputSignal.AddError(fmt.Errorf("either --ip-addresses or --cidr must be provided"))
				return
			}

			// Validate IP addresses if provided
			if len(ips) > 0 {
				for _, ip := range ips {
					if net.ParseIP(ip) == nil {
						a.OutputSignal.AddError(fmt.Errorf("invalid IP address: %s", ip))
						return
					}
				}
			}

			// Validate CIDR if provided
			if cidr != "" {
				if _, _, err := net.ParseCIDR(cidr); err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid CIDR range: %s", cidr))
					return
				}
			}

			// Validate DNS resolvers
			for _, dnsResolver := range dnsResolvers {
				err = utils.ValidateDNSServerAddress(dnsResolver)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid DNS resolver: %w", err))
					return
				}
			}

			// Generate the report
			config := getDiscoverIPDomainASNConfig(ips, cidr, dnsResolvers)
			report := ip.GetDomainASNLookup(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverIPDomainASNCmd.Flags().StringSlice("ip-addresses", []string{}, "The IP addresses to perform reverse DNS and ASN lookup on")
	discoverIPDomainASNCmd.Flags().String("cidr", "", "The CIDR range to perform reverse DNS and ASN lookup on")
	discoverIPDomainASNCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolvers (e.g. 10.0.0.1).")

	// Add command to 'ip' command
	discoverIPCmd.AddCommand(discoverIPDomainASNCmd)

	// Add the 'discover' command to the root command
	a.RootCmd.AddCommand(discoverCmd)
}

// getDiscoverASNConfig creates and returns a configuration for ASN discovery
func getDiscoverASNConfig(asn string, timeout int) *asnfern.DiscoverAsnConfig {
	return &asnfern.DiscoverAsnConfig{
		Asn:     asn,
		Timeout: &timeout,
	}
}

// getDiscoverDNSCertsConfig creates and returns a configuration for DNS certificate discovery
func getDiscoverDNSCertsConfig(domain string) dnsfern.DiscoverDnsCertsConfig {
	return dnsfern.DiscoverDnsCertsConfig{
		Domain: domain,
	}
}

// getDiscoverDNSRecordsConfig creates and returns a configuration for DNS records discovery
func getDiscoverDNSRecordsConfig(domain string, recordTypes []string, dnsResolvers []string, useTCP bool, timeout int) dnsfern.DiscoverDnsRecordsConfig {
	config := dnsfern.DiscoverDnsRecordsConfig{
		Domain:       domain,
		RecordTypes:  recordTypes,
		DnsResolvers: dnsResolvers,
	}
	if useTCP {
		config.UseTcp = &useTCP
	}
	// Always forward the flag value (default 10) so an explicit --timeout=0 is
	// preserved as "no deadline"; only a genuinely omitted timeout (library/MCP
	// callers leaving it nil) falls back to the schema default.
	config.Timeout = &timeout
	return config
}

// getDiscoverDNSForwardConfig creates and returns a configuration for forward DNS lookup
func getDiscoverDNSForwardConfig(domain string, dnsResolvers []string) dnsfern.DiscoverDnsForwardConfig {
	return dnsfern.DiscoverDnsForwardConfig{
		Domain:       domain,
		DnsResolvers: dnsResolvers,
	}
}

// getDiscoverDNSReverseConfig creates and returns a configuration for DNS reverse lookup
func getDiscoverDNSReverseConfig(ips []string, cidr string, dnsResolvers []string, threads int) *dnsfern.DiscoverDnsReverseConfig {
	config := &dnsfern.DiscoverDnsReverseConfig{
		IpAddresses:  ips,
		DnsResolvers: dnsResolvers,
		Threads:      max(threads, 1),
	}
	if cidr != "" {
		config.Cidr = &cidr
	}
	return config
}

// getDiscoverDNSActiveSubdomainConfig creates and returns a configuration for active subdomain discovery
func getDiscoverDNSActiveSubdomainConfig(domain string, wordlistSize *dnsfern.WordlistSize, wordlistFile *string, threads, maxDepth, timeout, sleep, wildcardChecks int, dnsResolvers []string) dnsfern.DiscoverDnsSubdomainConfig {
	return dnsfern.DiscoverDnsSubdomainConfig{
		DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypeActive)),
		Active: &dnsfern.DiscoverDnsSubdomainActiveConfig{
			Domain:         domain,
			WordlistSize:   wordlistSize,
			WordlistFile:   wordlistFile,
			Threads:        threads,
			MaxDepth:       maxDepth,
			Timeout:        timeout,
			Sleep:          sleep,
			WildcardChecks: wildcardChecks,
			DnsResolvers:   dnsResolvers,
		},
	}
}

// getDiscoverDNSPassiveSubdomainConfig creates and returns a configuration for passive subdomain discovery
func getDiscoverDNSPassiveSubdomainConfig(domain string, requestsPerSecond int, threads int, allSources bool, modules []string, dnsResolvers []string, maxDNSQueries int, maxResolversQPS int, recursiveDepth int) (dnsfern.DiscoverDnsSubdomainConfig, error) {

	var modulesEnum []dnsfern.DiscoverDnsSubdomainModule
	for _, module := range modules {
		moduleEnum, err := dnsfern.NewDiscoverDnsSubdomainModuleFromString(strings.ToUpper(module))
		if err != nil {
			return dnsfern.DiscoverDnsSubdomainConfig{}, err
		}
		modulesEnum = append(modulesEnum, moduleEnum)
	}

	config := dnsfern.DiscoverDnsSubdomainConfig{
		DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypePassive)),
		Passive: &dnsfern.DiscoverDnsSubdomainPassiveConfig{
			Domain:            domain,
			RequestsPerSecond: requestsPerSecond,
			Threads:           max(threads, 1),
			AllSources:        allSources,
			Modules:           modulesEnum,
			DnsResolvers:      dnsResolvers,
			MaxDnsQueries:     max(maxDNSQueries, 0),
			MaxResolversQps:   max(maxResolversQPS, 0),
			RecursiveDepth:    max(recursiveDepth, 0),
		},
	}
	return config, nil
}

// getDiscoverCdnConfig creates and returns a configuration for CDN discovery
func getDiscoverCdnConfig(domain string, ipAddresses []string, dnsResolvers []string, fingerprintsFile string) cdnfern.DiscoverCdnConfig {
	config := cdnfern.DiscoverCdnConfig{
		Domain:       domain,
		DnsResolvers: dnsResolvers,
	}
	if fingerprintsFile != "" {
		config.FingerprintsFile = &fingerprintsFile
	}
	if len(ipAddresses) > 0 {
		config.IpAddresses = ipAddresses
	}
	return config
}

// getDiscoverIdpConfig creates and returns a configuration for IdP discovery
func getDiscoverIdpConfig(domain string, timeout int) *idpfern.DiscoverIdpConfig {
	return &idpfern.DiscoverIdpConfig{
		Domain:  domain,
		Timeout: &timeout,
	}
}

// getDiscoverIPDomainASNConfig creates and returns a configuration for IP domain ASN discovery
func getDiscoverIPDomainASNConfig(ips []string, cidr string, dnsResolvers []string) *ipfern.DiscoverIpDomainAsnConfig {
	config := &ipfern.DiscoverIpDomainAsnConfig{
		IpAddresses:  ips,
		DnsResolvers: dnsResolvers,
	}

	// Only set CIDR if it's not empty
	if cidr != "" {
		config.Cidr = &cidr
	}

	return config
}

// getDiscoverDNSCctldConfig creates and returns a configuration for ccTLD pivot discovery.
func getDiscoverDNSCctldConfig(domain string, cctlds []string, cctldsPreset string, threads int, timeout int, dnsResolvers []string) (dnsfern.DiscoverDnsCctldConfig, error) {
	config := dnsfern.DiscoverDnsCctldConfig{
		Domain:       domain,
		Threads:      max(threads, 1),
		Timeout:      timeout,
		DnsResolvers: dnsResolvers,
	}

	if len(cctlds) > 0 {
		config.Cctlds = cctlds
	}

	if cctldsPreset != "" {
		preset, err := dnsfern.NewDiscoverDnsCctldPresetFromString(strings.ToUpper(cctldsPreset))
		if err != nil {
			return dnsfern.DiscoverDnsCctldConfig{}, fmt.Errorf("invalid --cctlds-preset value %q: %w", cctldsPreset, err)
		}
		config.CctldsPreset = &preset
	}

	return config, nil
}
