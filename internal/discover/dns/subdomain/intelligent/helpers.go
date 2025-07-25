package intelligent

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Method-Security/osintscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// =============================================================================
// WORDLISTS
// =============================================================================

// Location codes: major cities, countries, and geographic regions
var commonLocationCodes = []string{
	// Major cities
	"nyc", "ny", "newyork", "la", "losangeles", "california", "chi", "chicago",
	"mia", "miami", "lon", "london", "par", "paris", "tok", "tokyo", "syd", "sydney",
	"tor", "toronto", "van", "vancouver", "sea", "seattle", "sf", "sanfrancisco",
	"bos", "boston", "atl", "atlanta", "den", "denver", "dal", "dallas", "hou", "houston",
	"phx", "phoenix", "det", "detroit", "min", "minneapolis",

	// Country codes (ISO 3166-1 alpha-2) and common variations
	"us", "usa", "uk", "gb", "ca", "canada", "de", "germany", "fr", "france",
	"jp", "japan", "au", "australia", "br", "brazil", "in", "india", "cn", "china",
	"ru", "russia", "it", "italy", "es", "spain", "nl", "netherlands", "se", "sweden",
	"no", "norway", "dk", "denmark", "fi", "finland", "ch", "switzerland", "at", "austria",
	"be", "belgium", "ie", "ireland", "pt", "portugal", "pl", "poland", "cz", "czech",
	"hu", "hungary", "sk", "slovakia", "si", "slovenia", "hr", "croatia", "bg", "bulgaria",
	"ro", "romania", "gr", "greece", "tr", "turkey", "il", "israel", "ae", "uae",
	"sa", "saudi", "za", "southafrica", "eg", "egypt", "ng", "nigeria", "ke", "kenya",
	"ma", "morocco", "mx", "mexico", "ar", "argentina", "cl", "chile", "co", "colombia",
	"pe", "peru", "ve", "venezuela", "uy", "uruguay", "ec", "ecuador", "bo", "bolivia",
	"py", "paraguay", "kr", "korea", "th", "thailand", "sg", "singapore", "my", "malaysia",
	"id", "indonesia", "ph", "philippines", "vn", "vietnam", "tw", "taiwan", "hk", "hongkong",
	"nz", "newzealand",

	// Geographic regions
	"eu", "europe", "as", "asia", "na", "northamerica", "sa", "southamerica", "af", "africa",
	"oc", "oceania", "east", "west", "north", "south", "central", "northwest", "northeast",
	"southwest", "southeast",
}

// Infrastructure terms: servers, networking, cloud, monitoring, CI/CD
var commonInfrastructureTerms = []string{
	// Load Balancers & Proxies
	"lb", "lb01", "lb02", "lb03", "elb", "alb", "nlb", "proxy", "haproxy", "nginx", "apache", "reverse-proxy",

	// Cache & CDN
	"cache", "redis", "memcached", "cdn", "cdn1", "cdn2", "cdn3", "static", "assets", "media",
	"images", "files", "img", "download", "dl", "content", "edge", "edge1", "edge2",

	// Cloud Infrastructure
	"ec2", "s3", "rds", "eks", "ecs", "lambda", "cloudfront", "route53", "azure", "gcp", "aws",
	"cloud", "k8s", "kubernetes", "docker", "container", "containers",

	// Monitoring & Observability
	"grafana", "prometheus", "kibana", "elasticsearch", "logstash", "splunk", "datadog", "newrelic",
	"monitoring", "metrics", "logs", "logging", "alerts", "alerting", "apm", "tracing", "jaeger", "zipkin",

	// CI/CD & Build Systems
	"jenkins", "gitlab", "github", "bitbucket", "drone", "travis", "circleci", "buildbot", "teamcity",
	"bamboo", "ci", "cd", "deploy", "deployment", "build", "builder", "pipeline", "pipelines", "runner", "runners",

	// Databases
	"db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb", "cassandra", "influx",
	"influxdb", "elastic", "oracle", "mssql", "sqlite",

	// Security & Secrets
	"vault", "consul", "etcd", "secrets", "cert", "certs", "certificate", "ca", "pki", "ssl", "tls",

	// Message Queues & Streaming
	"kafka", "rabbitmq", "activemq", "queue", "queues", "mq", "stream", "streaming", "pub", "sub", "pubsub",

	// Search & Analytics
	"search", "solr", "analytics", "data", "warehouse", "lake", "etl",

	// Network & Connectivity
	"vpn", "ssh", "bastion", "jump", "gateway", "firewall", "fw", "router", "switch", "dns",
	"nameserver", "ns", "ns1", "ns2", "ns3",

	// Storage
	"storage", "backup", "backups", "archive", "nfs", "filer", "san", "nas",

	// Testing & Quality
	"test", "testing", "qa", "quality", "perf", "performance", "load", "stress", "benchmark", "selenium",

	// Development Tools
	"git", "svn", "repo", "repository", "nexus", "artifactory", "registry", "harbor", "quay",
}

// Environment terms: deployment environments and stages
var commonEnvironmentTerms = []string{
	"dev", "development", "staging", "stage", "prod", "production", "test", "testing",
	"uat", "demo", "qa", "sandbox", "preview", "pre-prod", "preprod", "live", "dr", "backup",
}

// Service terms: APIs, applications, and user-facing services
var commonServiceTerms = []string{
	// Core API/App services
	"api", "apig", "apim", "app", "apps", "admin", "portal", "dashboard", "console",
	"manage", "management", "control", "panel", "backend", "frontend", "service", "svc", "web", "www",

	// Communication services
	"mail", "smtp", "imap", "pop", "pop3", "exchange", "owa", "webmail", "mx", "email",

	// File/Content services
	"ftp", "sftp", "files", "download", "dl", "upload", "share", "docs", "documents",

	// Authentication/Security services
	"auth", "oauth", "sso", "login", "signin", "signup", "register", "account", "profile", "user", "users",

	// Monitoring/Health services
	"health", "status", "ping", "heartbeat", "metrics", "stats", "analytics",

	// Mobile/Client services
	"mobile", "m", "touch", "wap", "client", "clients",
}

// Internal terms: private and corporate infrastructure
var commonInternalTerms = []string{
	"internal", "private", "corp", "int", "intranet", "lan", "local", "priv", "secure",
}

// =============================================================================
// CORE INTELLIGENT DISCOVERY FUNCTIONS
// =============================================================================

// Simple wrapper functions that add cache support
func TestWordlistSubstitutionWithCache(ctx context.Context, fqdn string, dnsServerAddress string, existingDomains []string, maxWorkers int, dnsCache *sync.Map) ([]string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting wordlist substitution analysis", svc1log.SafeParam("fqdn", fqdn))

	var candidates []string

	// All wordlists to check
	wordlists := map[string][]string{
		"location":       commonLocationCodes,
		"infrastructure": commonInfrastructureTerms,
		"environment":    commonEnvironmentTerms,
		"service":        commonServiceTerms,
		"internal":       commonInternalTerms,
	}

	// For each existing domain, find substitution opportunities
	for _, domain := range existingDomains {
		// Split domain into parts (treating both . and - as separators) and preserve structure
		parts, separators := splitDomainPartsWithStructure(domain)

		// Check each part against all wordlists
		for partIndex, part := range parts {
			for listName, wordlist := range wordlists {
				// Check for exact matches
				if contains(wordlist, part) {
					log.Info("Found exact wordlist match for substitution",
						svc1log.SafeParam("domain", domain),
						svc1log.SafeParam("matched_word", part),
						svc1log.SafeParam("wordlist", listName))

					// Replace with all other words from the same list
					for _, replacement := range wordlist {
						if replacement == part {
							continue // Skip the same word
						}

						// Create new domain with replacement, preserving original structure
						newParts := make([]string, len(parts))
						copy(newParts, parts)
						newParts[partIndex] = replacement
						newDomain := reconstructDomain(newParts, separators)
						candidates = append(candidates, newDomain)
					}
				}

				// Check for prefix matches with digits
				for _, word := range wordlist {
					if len(word) >= 2 && strings.HasPrefix(part, word) {
						// Check if the part after the word contains only digits
						remainder := part[len(word):]
						if len(remainder) > 0 && isDigitsOnly(remainder) {
							log.Info("Found wordlist match followed by numbers",
								svc1log.SafeParam("domain", domain),
								svc1log.SafeParam("part", part),
								svc1log.SafeParam("matched_word", word),
								svc1log.SafeParam("suffix", remainder),
								svc1log.SafeParam("wordlist", listName))

							// Replace the word part with all other words from the same list
							for _, replacement := range wordlist {
								if replacement == word {
									continue // Skip the same word
								}

								// Create new part with replacement + original number suffix
								newPart := replacement + remainder
								// Create new domain with replacement, preserving original structure
								newParts := make([]string, len(parts))
								copy(newParts, parts)
								newParts[partIndex] = newPart
								newDomain := reconstructDomain(newParts, separators)
								candidates = append(candidates, newDomain)
							}
						}
					}
				}
			}
		}
	}

	// Add existing domains to candidates for testing
	candidates = append(candidates, existingDomains...)

	// Remove duplicates and test with cache
	uniqueCandidates := removeDuplicateStrings(candidates)
	log.Info("Generated substitution candidates", svc1log.SafeParam("count", len(uniqueCandidates)))

	if len(candidates) == 0 {
		return []string{}, nil
	}

	return testDomainsWithCache(ctx, uniqueCandidates, dnsServerAddress, maxWorkers, dnsCache)
}

func TestHighEntropyDomainsWithCache(ctx context.Context, fqdn string, dnsServerAddress string, existingDomains []string, dnsCache *sync.Map) ([]string, error) {
	log := svc1log.FromContext(ctx)
	highEntropyPatterns := extractHighEntropyPatterns(ctx, existingDomains)

	if len(highEntropyPatterns) == 0 {
		return []string{}, nil
	}

	// Use channels to generate candidates in parallel
	candidateChan := make(chan []string, len(highEntropyPatterns))
	var wg sync.WaitGroup

	// Process each pattern in parallel
	for _, pattern := range highEntropyPatterns {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			candidates := generateHighEntropyVariations(p)
			candidateChan <- candidates
		}(pattern)
	}

	// Close channel when all workers are done
	go func() {
		wg.Wait()
		close(candidateChan)
	}()

	// Collect all candidates
	var allCandidates []string
	for candidates := range candidateChan {
		allCandidates = append(allCandidates, candidates...)
	}

	allCandidates = append(allCandidates, existingDomains...)
	uniqueCandidates := removeDuplicateStrings(allCandidates)

	log.Info("Generated high entropy candidates", svc1log.SafeParam("count", len(uniqueCandidates)-len(existingDomains)))

	return testDomainsWithCache(ctx, uniqueCandidates, dnsServerAddress, 50, dnsCache)
}

func TestNumericSequenceDomainsWithCache(ctx context.Context, fqdn string, dnsServerAddress string, existingDomains []string, dnsCache *sync.Map) ([]string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting numeric sequence analysis", svc1log.SafeParam("fqdn", fqdn))

	numericPatterns := extractNumericSequences(existingDomains)

	if len(numericPatterns) == 0 {
		log.Info("No numeric sequences found")
		return []string{}, nil
	}

	var candidates []string

	// Generate candidates based on found sequences
	for pattern, numbers := range numericPatterns {
		log.Info("Found numeric pattern",
			svc1log.SafeParam("pattern", pattern),
			svc1log.SafeParam("numbers", numbers))

		if len(numbers) == 0 {
			continue
		}

		// Try all numbers from 0 to 1000
		for i := 0; i <= 1000; i++ {
			candidate := fmt.Sprintf(pattern, i)
			if !contains(existingDomains, candidate) {
				candidates = append(candidates, candidate)
			}
		}
	}

	log.Info("Generated numeric sequence candidates", svc1log.SafeParam("count", len(candidates)))

	if len(candidates) == 0 {
		return []string{}, nil
	}

	candidates = append(candidates, existingDomains...)
	uniqueCandidates := removeDuplicateStrings(candidates)

	return testDomainsWithCache(ctx, uniqueCandidates, dnsServerAddress, 50, dnsCache)
}

func TestAdvancedPatternAnalysisWithCache(ctx context.Context, domain string, dnsServerAddress string, allDomains []string, dnsCache *sync.Map) ([]string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting advanced pattern analysis", svc1log.SafeParam("domain", domain))

	// Use channels to collect candidates from parallel workers
	candidateChan := make(chan []string, 3) // 3 different analysis types
	var analysisWg sync.WaitGroup

	// Pattern extraction worker
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		candidates := extractCrossPatterns(allDomains, domain)
		candidateChan <- candidates
	}()

	// Environment correlation worker
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		candidates := extractEnvironmentPatterns(allDomains)
		candidateChan <- candidates
	}()

	// Service pattern worker
	analysisWg.Add(1)
	go func() {
		defer analysisWg.Done()
		candidates := extractServicePatterns(allDomains)
		candidateChan <- candidates
	}()

	// Close channel when all workers are done
	go func() {
		analysisWg.Wait()
		close(candidateChan)
	}()

	// Collect all candidates
	var allCandidates []string
	for candidates := range candidateChan {
		allCandidates = append(allCandidates, candidates...)
	}

	log.Info("Generated advanced pattern candidates", svc1log.SafeParam("count", len(allCandidates)))

	if len(allCandidates) == 0 {
		return []string{}, nil
	}

	// Remove duplicates and existing domains in parallel
	uniqueCandidates := removeDuplicateStrings(allCandidates)
	var finalCandidates []string
	existingSet := make(map[string]bool)
	for _, domain := range allDomains {
		existingSet[domain] = true
	}

	for _, candidate := range uniqueCandidates {
		if !existingSet[candidate] {
			finalCandidates = append(finalCandidates, candidate)
		}
	}

	return testDomainsWithCache(ctx, finalCandidates, dnsServerAddress, 50, dnsCache)
}

// generateHighEntropyVariations generates variations for a single high entropy pattern
func generateHighEntropyVariations(pattern string) []string {
	var candidates []string

	parts, separators := splitDomainPartsWithStructure(pattern)
	leftmostPart := parts[0]

	var remainingParts string
	if len(parts) > 1 {
		remainingParts = reconstructDomain(parts[1:], separators[1:])
		if remainingParts != "" {
			// Add the first separator back to connect leftmost part with remaining parts
			if len(separators) > 0 {
				remainingParts = separators[0] + remainingParts
			} else {
				remainingParts = "." + remainingParts
			}
		}
	}

	// Test with numbers 0-9 appended
	for i := 0; i <= 9; i++ {
		newDomain := fmt.Sprintf("%s%d%s", leftmostPart, i, remainingParts)
		candidates = append(candidates, newDomain)
	}
	// Test with letters a-z appended
	for i := 'a'; i <= 'z'; i++ {
		newDomain := fmt.Sprintf("%s%c%s", leftmostPart, i, remainingParts)
		candidates = append(candidates, newDomain)
	}

	return candidates
}

// extractCrossPatterns generates cross-combinations of common prefixes and suffixes
func extractCrossPatterns(existingDomains []string, fqdn string) []string {
	var candidates []string

	// Extract common prefixes and suffixes from domain names directly
	prefixes := make(map[string]int)
	suffixes := make(map[string]int)

	for _, domain := range existingDomains {
		// Split domain on dots and hyphens to analyze parts
		parts := splitDomainParts(domain)

		if len(parts) >= 1 {
			prefixes[parts[0]]++
		}
		if len(parts) >= 2 {
			suffixes[parts[len(parts)-2]]++ // Second to last part (before TLD)
		}
	}

	// Cross-pollinate high-frequency patterns (seen 2+ times)
	var topPrefixes, topSuffixes []string
	for prefix, count := range prefixes {
		if count >= 2 {
			topPrefixes = append(topPrefixes, prefix)
		}
	}
	for suffix, count := range suffixes {
		if count >= 2 {
			topSuffixes = append(topSuffixes, suffix)
		}
	}

	// Generate cross-combinations by creating new domain names
	for _, prefix := range topPrefixes {
		for _, suffix := range topSuffixes {
			if prefix != suffix {
				candidates = append(candidates, fmt.Sprintf("%s.%s", prefix, suffix))
				candidates = append(candidates, fmt.Sprintf("%s-%s.%s", prefix, suffix, fqdn))
				candidates = append(candidates, fmt.Sprintf("%s_%s.%s", prefix, suffix, fqdn))
			}
		}
	}

	return candidates
}

// extractEnvironmentPatterns generates environment-based variations
func extractEnvironmentPatterns(existingDomains []string) []string {
	var candidates []string
	environments := []string{"dev", "staging", "prod", "test", "qa", "demo", "uat", "pre", "beta", "alpha"}

	for _, domain := range existingDomains {
		parts, separators := splitDomainPartsWithStructure(domain)

		for i, part := range parts {
			for _, env := range environments {
				if part == env {
					// Try other environments in the same position
					for _, otherEnv := range environments {
						if otherEnv != env {
							newParts := make([]string, len(parts))
							copy(newParts, parts)
							newParts[i] = otherEnv
							candidates = append(candidates, reconstructDomain(newParts, separators))
						}
					}
				}
			}
		}
	}

	return candidates
}

// extractServicePatterns generates service-based variations
func extractServicePatterns(existingDomains []string) []string {
	var candidates []string
	services := []string{"api", "app", "web", "www", "mail", "ftp", "admin", "portal", "dashboard", "auth", "sso"}

	// Look for service patterns and generate variations
	for _, domain := range existingDomains {
		parts, separators := splitDomainPartsWithStructure(domain)

		for i, part := range parts {
			for _, service := range services {
				if strings.Contains(part, service) {
					// Try other services in similar position
					for _, otherService := range services {
						if otherService != service {
							newPart := strings.ReplaceAll(part, service, otherService)
							newParts := make([]string, len(parts))
							copy(newParts, parts)
							newParts[i] = newPart
							candidates = append(candidates, reconstructDomain(newParts, separators))
						}
					}
				}
			}
		}
	}

	return candidates
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// splitDomainParts splits a domain on both dots (.) and hyphens (-) to analyze all components
func splitDomainParts(domain string) []string {
	// Replace hyphens with dots, then split on dots
	normalized := strings.ReplaceAll(domain, "-", ".")
	return strings.Split(normalized, ".")
}

// splitDomainPartsWithStructure splits a domain and returns both parts and structure info
func splitDomainPartsWithStructure(domain string) ([]string, []string) {
	var parts []string

	var separators []string

	currentPart := ""
	for _, char := range domain {
		if char == '.' || char == '-' {
			if currentPart != "" {
				parts = append(parts, currentPart)
				separators = append(separators, string(char))
				currentPart = ""
			}
		} else {
			currentPart += string(char)
		}
	}

	// Add the last part
	if currentPart != "" {
		parts = append(parts, currentPart)
	}

	return parts, separators
}

// reconstructDomain rebuilds a domain from parts and separators
func reconstructDomain(parts []string, separators []string) string {
	if len(parts) == 0 {
		return ""
	}

	if len(parts) == 1 {
		return parts[0]
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		var separator string
		if i-1 < len(separators) {
			separator = separators[i-1]
		} else {
			separator = "." // Default to dot if no separator info
		}
		result += separator + parts[i]
	}

	return result
}

// testDomainsConcurrently tests potential domains concurrently
func testDomainsConcurrently(ctx context.Context, candidates []string, dnsServerAddress string, maxWorkers int) ([]string, error) {
	return testDomainsWithCache(ctx, candidates, dnsServerAddress, maxWorkers, nil)
}

func testDomainsWithCache(ctx context.Context, candidates []string, dnsServerAddress string, maxWorkers int, dnsCache *sync.Map) ([]string, error) {
	log := svc1log.FromContext(ctx)
	resolver := utils.GetResolver(dnsServerAddress, log)

	// Limit workers to avoid overwhelming the DNS server
	if maxWorkers <= 0 {
		maxWorkers = 10
	}
	if maxWorkers > 100 {
		maxWorkers = 100
	}

	// Use buffered channels for better performance
	work := make(chan string, min(len(candidates), 1000))
	results := make(chan string, len(candidates))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range work {
				select {
				case <-ctx.Done():
					return
				default:
					if testDomainExistsWithCache(ctx, candidate, resolver, dnsCache) {
						select {
						case results <- candidate:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	// Send work in batches to avoid blocking
	go func() {
		defer close(work)
		for i, candidate := range candidates {
			select {
			case work <- candidate:
				// Log progress every 1000 candidates
				if i > 0 && i%1000 == 0 {
					log.Debug("DNS testing progress", svc1log.SafeParam("tested", i), svc1log.SafeParam("total", len(candidates)))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	var foundDomains []string
	for result := range results {
		foundDomains = append(foundDomains, result)
	}

	log.Info("DNS testing completed",
		svc1log.SafeParam("candidates_tested", len(candidates)),
		svc1log.SafeParam("valid_domains", len(foundDomains)))

	return foundDomains, nil
}

// testDomainExists checks if a domain exists by performing multiple DNS lookups
func testDomainExists(ctx context.Context, domain string, resolver *net.Resolver) bool {
	log := svc1log.FromContext(ctx)
	domain = strings.TrimSpace(domain)
	log.Info("Testing domain existence", svc1log.SafeParam("domain", domain))

	if domain == "" {
		log.Warn("Empty domain input")
		return false
	}

	// Helper for early exit with optional debug logging
	check := func(lookupType string, fn func(context.Context, string) ([]string, error)) bool {
		_, err := fn(ctx, domain)
		if err == nil {
			return true
		}
		log.Debug("DNS lookup failed",
			svc1log.SafeParam("domain", domain),
			svc1log.SafeParam("type", lookupType),
			svc1log.SafeParam("error", err.Error()),
		)
		return false
	}

	if check("A/AAAA", resolver.LookupHost) ||
		check("CNAME", func(ctx context.Context, host string) ([]string, error) {
			records, err := resolver.LookupCNAME(ctx, host)
			if err != nil {
				return nil, err
			}
			return []string{records}, nil
		}) ||
		check("MX", func(ctx context.Context, host string) ([]string, error) {
			records, err := resolver.LookupMX(ctx, host)
			if err != nil {
				return nil, err
			}
			var result []string
			for _, r := range records {
				result = append(result, r.Host)
			}
			return result, nil
		}) ||
		check("NS", func(ctx context.Context, host string) ([]string, error) {
			records, err := resolver.LookupNS(ctx, host)
			if err != nil {
				return nil, err
			}
			var result []string
			for _, r := range records {
				result = append(result, r.Host)
			}
			return result, nil
		}) ||
		check("TXT", resolver.LookupTXT) {
		return true
	}

	return false
}

// testDomainExistsWithCache checks cache first, then does DNS lookup if needed
func testDomainExistsWithCache(ctx context.Context, domain string, resolver *net.Resolver, dnsCache *sync.Map) bool {
	// Check cache first if available
	if dnsCache != nil {
		if cached, found := dnsCache.Load(domain); found {
			return cached.(bool)
		}
	}

	// Not in cache, do DNS lookup and cache result
	exists := testDomainExists(ctx, domain, resolver)

	if dnsCache != nil {
		dnsCache.Store(domain, exists)
	}

	return exists
}

// extractHighEntropyPatterns identifies high entropy (random-looking) domains
func extractHighEntropyPatterns(ctx context.Context, domains []string) []string {
	var patterns []string

	log := svc1log.FromContext(ctx)
	log.Info("Extracting high entropy patterns", svc1log.SafeParam("domains", domains))

	for _, domain := range domains {
		// Check if any part of the domain is high entropy
		parts := splitDomainParts(domain)
		for _, part := range parts {
			if isHighEntropy(part) {
				patterns = append(patterns, domain)
				break // Only add the domain once
			}
		}
	}

	return patterns
}

// isHighEntropy determines if a string appears to be high entropy (random characters)
func isHighEntropy(s string) bool {
	if len(s) < 8 {
		return false
	}

	hasLower, hasUpper, hasDigit := false, false, false
	vowels, consonants := 0, 0
	vowelSet := map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true}

	for _, char := range strings.ToLower(s) {
		if char >= 'a' && char <= 'z' {
			hasLower = true
			if vowelSet[char] {
				vowels++
			} else {
				consonants++
			}
		}
	}

	for _, char := range s {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
		} else if char >= '0' && char <= '9' {
			hasDigit = true
		}
	}

	varietyCount := 0
	if hasLower {
		varietyCount++
	}
	if hasUpper {
		varietyCount++
	}
	if hasDigit {
		varietyCount++
	}

	// Check for randomness indicators
	totalLetters := vowels + consonants
	if totalLetters > 0 {
		vowelRatio := float64(vowels) / float64(totalLetters)
		// Normal English has ~40% vowels, random strings often have very different ratios
		if vowelRatio < 0.15 || vowelRatio > 0.65 {
			if varietyCount >= 2 && len(s) >= 8 {
				return true
			}
		}
	}

	// Mixed case + digits + unusual length suggests randomness
	if varietyCount >= 3 && len(s) >= 12 {
		return true
	}

	// Long strings with mixed case
	if varietyCount >= 2 && len(s) >= 16 {
		if hasLower && hasUpper && (hasDigit || strings.ContainsAny(s, "+-/=")) {
			return true
		}
	}

	// Strings ending with multiple digits (common pattern for random IDs)
	if varietyCount >= 2 && len(s) >= 8 {
		digitCount := 0
		for i := len(s) - 1; i >= 0; i-- {
			if s[i] >= '0' && s[i] <= '9' {
				digitCount++
			} else {
				break
			}
		}
		if digitCount >= 2 {
			return true
		}
	}

	// Very low consonant-to-vowel ratio with digits
	if varietyCount >= 2 && len(s) >= 8 && totalLetters >= 4 {
		consonantRatio := float64(consonants) / float64(totalLetters)
		if consonantRatio > 0.8 && hasDigit {
			return true
		}
	}

	return false
}

// extractNumericSequences finds numeric patterns in domains
func extractNumericSequences(domains []string) map[string][]int {
	patterns := make(map[string][]int)
	numericRegex := regexp.MustCompile(`^([a-zA-Z-]+)(\d+)([a-zA-Z-]*)$`)

	for _, domain := range domains {
		parts, separators := splitDomainPartsWithStructure(domain)

		for _, part := range parts {
			matches := numericRegex.FindStringSubmatch(part)
			if len(matches) == 4 {
				prefix := matches[1]
				numStr := matches[2]
				suffix := matches[3]

				num, err := strconv.Atoi(numStr)
				if err != nil {
					continue
				}

				var patternTemplate string
				if suffix == "" {
					patternTemplate = prefix + "%d"
				} else {
					patternTemplate = prefix + "%d" + suffix
				}

				// If multi-level domain, reconstruct the full pattern
				if len(parts) > 1 {
					for i, p := range parts {
						if p == part {
							templateParts := make([]string, len(parts))
							copy(templateParts, parts)
							templateParts[i] = patternTemplate
							patternTemplate = reconstructDomain(templateParts, separators)
							break
						}
					}
				}

				patterns[patternTemplate] = append(patterns[patternTemplate], num)
			}
		}
	}

	return patterns
}

// Utility functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeDuplicateStrings(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func isDigitsOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
