package cmd

import (
	// Standard
	"fmt"
	"net"
	"os"
	"strings"

	// Generated
	cdnfern "github.com/Method-Security/osintscan/generated/go/discover"
	asnfern "github.com/Method-Security/osintscan/generated/go/discover/asn"
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	ipfern "github.com/Method-Security/osintscan/generated/go/discover/ip"

	// Internal
	discover "github.com/Method-Security/osintscan/internal/discover"
	dns "github.com/Method-Security/osintscan/internal/discover/dns"
	subdomain "github.com/Method-Security/osintscan/internal/discover/dns/subdomain"
	ip "github.com/Method-Security/osintscan/internal/discover/ip"

	// External
	shodan "github.com/Method-Security/osintscan/internal/discover/shodan"
	"github.com/spf13/cobra"

	// Utils
	"github.com/Method-Security/osintscan/utils"
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

			config := getDiscoverDNSRecordsConfig(domain)

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
		Use:   "forward-reverse",
		Short: "Perform forward and reverse DNS lookups",
		Long:  `Perform both forward and reverse DNS lookups for the specified domain to identify associated IPs and hostnames.`,
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

			config := getDiscoverDNSForwardReverseConfig(domain, dnsResolvers)

			report := dns.GetForwardReverseDNSLookup(config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSForwardReverseCmd.Flags().String("domain", "", "The domain name to perform forward and reverse lookups on")
	discoverDNSForwardReverseCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)")

	// Mark Required Flags
	_ = discoverDNSForwardReverseCmd.MarkFlagRequired("domain")

	// Add command to 'dns' command
	discoverDNSCmd.AddCommand(discoverDNSForwardReverseCmd)

	// subdomain Commands
	// subdomain active
	// subdomain correlation
	// subdomain passive
	discoverDNSSubdomainCmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Discover subdomains for a domain",
		Long:  `Discover subdomains for the specified domain using passive and active enumeration techniques.`,
	}

	discoverDNSCmd.AddCommand(discoverDNSSubdomainCmd)

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

				filePath := subdomain.GetDiscoverDNSSubdomainActiveWordlistPath(wordlistSize)
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
			config := getDiscoverDNSActiveSubdomainConfig(domain, allSubdomains, wordlistSizeEnum, &wordlistFile, threads, maxDepth, timeout, dnsResolvers)

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
	discoverDNSSubdomainActiveCmd.Flags().Int("threads", 10, "Number of parallel threads to use for discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("max-depth", 2, "Maximum recursion depth for subdomain discovery")
	discoverDNSSubdomainActiveCmd.Flags().Int("timeout", 0, "Maximum time (in minutes) to spend on subdomain discovery")
	discoverDNSSubdomainActiveCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)")

	// Mark Required Flags
	_ = discoverDNSSubdomainActiveCmd.MarkFlagRequired("domain")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainActiveCmd)

	discoverDNSSubdomainCorrelationCmd := &cobra.Command{
		Use:   "correlation",
		Short: "Correlate subdomains across multiple domains",
		Long:  `Correlate subdomains across multiple domains using active data sources (no direct interaction with the target).`,
		Run: func(cmd *cobra.Command, args []string) {
			// Grab Domains
			domains, err := cmd.Flags().GetStringSlice("domains")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Config Flags
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

			// Create config
			config := getDiscoverDNSCorrelationSubdomainConfig(domains, threads, timeout, dnsResolvers)

			// Create report
			report, err := subdomain.GetDomainSubdomainsCorrelation(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	discoverDNSSubdomainCorrelationCmd.Flags().StringSlice("domains", []string{}, "The domains to test")
	discoverDNSSubdomainCorrelationCmd.Flags().Int("threads", 10, "Number of parallel threads to use for testing")
	discoverDNSSubdomainCorrelationCmd.Flags().Int("timeout", 0, "Maximum time (in seconds) to spend on each lookup")
	discoverDNSSubdomainCorrelationCmd.Flags().StringSlice("dns-resolvers", []string{}, "Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)")

	// Mark Required Flags
	_ = discoverDNSSubdomainCorrelationCmd.MarkFlagRequired("domains")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainCorrelationCmd)

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

			// Create config
			config := getDiscoverDNSPassiveSubdomainConfig(domain, requestsPerSecond, threads)

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
	discoverDNSSubdomainPassiveCmd.Flags().Int("requests-per-second", 0, "Maximum number of requests per second to send to the DNS resolvers")
	discoverDNSSubdomainPassiveCmd.Flags().Int("threads", 10, "Number of concurrent threads for scanning")

	// Mark Required Flags
	_ = discoverDNSSubdomainPassiveCmd.MarkFlagRequired("domain")

	// Add command to 'subdomain' command
	discoverDNSSubdomainCmd.AddCommand(discoverDNSSubdomainPassiveCmd)

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

	// CDN Commands
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
			if len(dnsResolvers) == 0 {
				a.OutputSignal.AddError(fmt.Errorf("no DNS resolvers provided"))
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
	discoverCdnCmd.Flags().StringSlice("ip-addresses", []string{}, "The IP addresses to check against CDN provider ranges")
	discoverCdnCmd.Flags().StringSlice("dns-resolvers", []string{"1.1.1.1:53"}, "Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)")
	discoverCdnCmd.Flags().String("fingerprints-file", "/opt/method/osintscan/var/conf/discover/cdn/providers.json", "The path to the CDN fingerprints file")

	// Mark Required Flags
	_ = discoverCdnCmd.MarkFlagRequired("domain")

	// Add command to the 'discover' command
	discoverCmd.AddCommand(discoverCdnCmd)

	// IP Address Discover Commands
	discoverIPCmd := &cobra.Command{
		Use:   "ip",
		Short: "Discover IP address and CIDR information",
		Long:  `Discover information about IP addresses or CIDR Ranges including linked domains, ASN, geolocation.`,
	}

	// Add discoverIPCmd to the 'discover' command
	discoverCmd.AddCommand(discoverIPCmd)

	discoverIPDomainASNCmd := &cobra.Command{
		Use:   "domain-asn",
		Short: "Perform a reverse DNS lookup and ASN lookup on a single IP, list of IPs, or a CIDR range",
		Long:  `Perform a reverse DNS lookup and ASN lookup on a single IP, list of IPs, or a CIDR range. Warning: /16 and larger can take upwards of 30 minutes.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Parse flags
			ips, err := cmd.Flags().GetStringSlice("ips")
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
				a.OutputSignal.AddError(fmt.Errorf("either --ips or --cidr must be provided"))
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
			if len(dnsResolvers) == 0 {
				a.OutputSignal.AddError(fmt.Errorf("no DNS resolvers provided"))
				return
			}
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
	discoverIPDomainASNCmd.Flags().StringSlice("ips", []string{}, "The IP addresses to perform reverse DNS and ASN lookup on")
	discoverIPDomainASNCmd.Flags().String("cidr", "", "The CIDR range to perform reverse DNS and ASN lookup on")
	discoverIPDomainASNCmd.Flags().StringSlice("dns-resolvers", []string{"1.1.1.1:53"}, "Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)")

	// Add command to 'ip' command
	discoverIPCmd.AddCommand(discoverIPDomainASNCmd)

	// ASN Address Discover Commands
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

	// Add the 'discover' command to the root command
	a.RootCmd.AddCommand(discoverCmd)
}

// getDiscoverDNSCertsConfig creates and returns a configuration for DNS certificate discovery
func getDiscoverDNSCertsConfig(domain string) dnsfern.DiscoverDnsCertsConfig {
	return dnsfern.DiscoverDnsCertsConfig{
		Domain: domain,
	}
}

// getDiscoverDNSRecordsConfig creates and returns a configuration for DNS records discovery
func getDiscoverDNSRecordsConfig(domain string) dnsfern.DiscoverDnsRecordsConfig {
	return dnsfern.DiscoverDnsRecordsConfig{
		Domain: domain,
	}
}

// getDiscoverDNSForwardReverseConfig creates and returns a configuration for forward/reverse DNS lookup
func getDiscoverDNSForwardReverseConfig(domain string, dnsResolvers []string) dnsfern.DiscoverDnsForwardReverseConfig {
	return dnsfern.DiscoverDnsForwardReverseConfig{
		Domain:       domain,
		DnsResolvers: dnsResolvers,
	}
}

// getDiscoverDNSActiveSubdomainConfig creates and returns a configuration for active subdomain discovery
func getDiscoverDNSActiveSubdomainConfig(domain string, subdomains []string, wordlistSize *dnsfern.WordlistSize, wordlistFile *string, threads, maxDepth, timeout int, dnsResolvers []string) dnsfern.DiscoverDnsSubdomainConfig {
	return dnsfern.DiscoverDnsSubdomainConfig{
		DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypeActive)),
		Active: &dnsfern.DiscoverDnsSubdomainActiveConfig{
			Domain:       domain,
			Subdomains:   subdomains,
			WordlistSize: wordlistSize,
			WordlistFile: wordlistFile,
			Threads:      threads,
			MaxDepth:     maxDepth,
			Timeout:      timeout,
			DnsResolvers: dnsResolvers,
		},
	}
}

// getDiscoverDNSCorrelationSubdomainConfig creates and returns a configuration for correlation subdomain discovery
func getDiscoverDNSCorrelationSubdomainConfig(domains []string, threads int, timeout int, dnsResolvers []string) dnsfern.DiscoverDnsSubdomainConfig {
	return dnsfern.DiscoverDnsSubdomainConfig{
		DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypeCorrelation)),
		Correlation: &dnsfern.DiscoverDnsSubdomainCorrelationConfig{
			Domains:      domains,
			Threads:      threads,
			Timeout:      timeout,
			DnsResolvers: dnsResolvers,
		},
	}
}

// getDiscoverDNSPassiveSubdomainConfig creates and returns a configuration for passive subdomain discovery
func getDiscoverDNSPassiveSubdomainConfig(domain string, requestsPerSecond int, threads int) dnsfern.DiscoverDnsSubdomainConfig {
	return dnsfern.DiscoverDnsSubdomainConfig{
		DiscoveryType: strings.ToLower(string(dnsfern.DiscoverDnsSubdomainTypePassive)),
		Passive: &dnsfern.DiscoverDnsSubdomainPassiveConfig{
			Domain:            domain,
			RequestsPerSecond: requestsPerSecond,
			Threads:           threads,
		},
	}
}

// getDiscoverCdnConfig creates and returns a configuration for CDN discovery
func getDiscoverCdnConfig(domain string, ipAddresses []string, dnsResolvers []string, fingerprintsFile string) cdnfern.DiscoverCdnConfig {
	config := cdnfern.DiscoverCdnConfig{
		Domain:           domain,
		DnsResolvers:     dnsResolvers,
		FingerprintsFile: fingerprintsFile,
	}
	if len(ipAddresses) > 0 {
		config.IpAddresses = ipAddresses
	}
	return config
}

// getDiscoverIPDomainASNConfig creates and returns a configuration for IP domain ASN discovery
func getDiscoverIPDomainASNConfig(ips []string, cidr string, dnsResolvers []string) *ipfern.DiscoverIpDomainAsnConfig {
	config := &ipfern.DiscoverIpDomainAsnConfig{
		Ips:          ips,
		DnsResolvers: dnsResolvers,
	}

	// Only set CIDR if it's not empty
	if cidr != "" {
		config.Cidr = &cidr
	}

	return config
}

// getDiscoverASNConfig creates and returns a configuration for ASN discovery
func getDiscoverASNConfig(asn string, timeout int) *asnfern.DiscoverAsnConfig {
	return &asnfern.DiscoverAsnConfig{
		Asn:     asn,
		Timeout: &timeout,
	}
}
