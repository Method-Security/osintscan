package utils

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"
)

// Whois is used for getting information on IPs, Domains, and ASNs

// WhoisClient represents a whois client
type WhoisClient struct {
	servers []string
	timeout time.Duration
}

// Common WHOIS servers for different TLDs and IP ranges
var defaultWhoisServers = []string{
	"whois.iana.org",
	"whois.arin.net",
	"whois.ripe.net",
	"whois.apnic.net",
	"whois.lacnic.net",
	"whois.afrinic.net",
	"whois.verisign-grs.com",
	"whois.crsnic.net",
	"whois.nic.com",
	"whois.nic.org",
	"whois.nic.net",
	"whois.nic.edu",
	"whois.nic.gov",
	"whois.nic.mil",
	"whois.nic.int",
	"whois.radb.net",
	"whois.cymru.com",
}

// NewWhoisClient creates a new whois client
func NewWhoisClient() *WhoisClient {
	return &WhoisClient{
		servers: defaultWhoisServers,
		timeout: 10 * time.Second,
	}
}

// SetServers sets the whois servers to use
func (c *WhoisClient) SetServers(servers []string) *WhoisClient {
	c.servers = servers
	return c
}

// SetTimeout sets the timeout for whois queries
func (c *WhoisClient) SetTimeout(timeout time.Duration) *WhoisClient {
	c.timeout = timeout
	return c
}

// Whois performs a whois lookup on the given domain/IP
func (c *WhoisClient) Whois(query string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.WhoisWithContext(ctx, query)
}

// WhoisWithServer performs a whois lookup on the given domain/IP with a specified server
func (c *WhoisClient) WhoisWithServer(query string, server string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.WhoisWithContextAndServer(ctx, query, server)
}

// WhoisWithServerVerbose performs a whois lookup on the given domain/IP with a specified server and verbose output
func (c *WhoisClient) WhoisWithServerVerbose(query string, server string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return c.WhoisWithContextAndServerVerbose(ctx, query, server)
}

// WhoisWithContext performs a whois lookup with a custom context
func (c *WhoisClient) WhoisWithContext(ctx context.Context, query string) (string, error) {
	// Create a new context with timeout if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Determine the appropriate WHOIS server for the query
	server, err := c.selectWhoisServer(query)
	if err != nil {
		return "", fmt.Errorf("failed to select WHOIS server: %w", err)
	}

	// Perform the WHOIS query
	return c.rawQuery(ctx, query, server)
}

// WhoisWithContextAndServer performs a whois lookup with a custom context and specified server
func (c *WhoisClient) WhoisWithContextAndServer(ctx context.Context, query string, server string) (string, error) {
	// Create a new context with timeout if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Validate server parameter
	if server == "" {
		return "", fmt.Errorf("WHOIS server cannot be empty")
	}

	// Perform the WHOIS query with the specified server
	return c.rawQuery(ctx, query, server)
}

// WhoisWithContextAndServerVerbose performs a whois lookup with a custom context, specified server, and verbose output
func (c *WhoisClient) WhoisWithContextAndServerVerbose(ctx context.Context, query string, server string) (string, error) {
	// Create a new context with timeout if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Validate server parameter
	if server == "" {
		return "", fmt.Errorf("WHOIS server cannot be empty")
	}

	// Perform the WHOIS query with the specified server and verbose flag
	return c.rawQueryWithOptions(ctx, query, server, true)
}

// selectWhoisServer determines the appropriate WHOIS server for the query
func (c *WhoisClient) selectWhoisServer(query string) (string, error) {
	// For IP addresses, try to determine the appropriate RIR
	if net.ParseIP(query) != nil {
		return c.selectRIRServer(query), nil
	}

	// For domains, we'll use a random server from our list
	// In a more sophisticated implementation, you could maintain a mapping
	// of TLDs to their specific WHOIS servers
	if len(c.servers) == 0 {
		return "", fmt.Errorf("no WHOIS servers configured")
	}

	// Randomly select a server
	rand.Seed(time.Now().UnixNano())
	return c.servers[rand.Intn(len(c.servers))], nil
}

// selectRIRServer selects the appropriate Regional Internet Registry server for an IP
func (c *WhoisClient) selectRIRServer(ip string) string {
	// Parse the IP to determine the RIR
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		// Fallback to a random server
		rand.Seed(time.Now().UnixNano())
		return c.servers[rand.Intn(len(c.servers))]
	}

	// Simple RIR selection based on IP ranges
	if parsedIP.To4() != nil {
		// IPv4
		firstOctet := parsedIP[0]
		switch {
		case firstOctet <= 127:
			return "whois.arin.net" // North America
		case firstOctet <= 191:
			return "whois.ripe.net" // Europe
		case firstOctet <= 223:
			return "whois.apnic.net" // Asia Pacific
		default:
			return "whois.arin.net" // Default fallback
		}
	} else {
		// IPv6 - simplified selection
		// In practice, you'd want more sophisticated IPv6 RIR detection
		return "whois.ripe.net"
	}
}

// rawQuery performs a raw TCP WHOIS query
func (c *WhoisClient) rawQuery(ctx context.Context, query, server string) (string, error) {
	return c.rawQueryWithOptions(ctx, query, server, false)
}

// rawQueryWithOptions performs a raw TCP WHOIS query with optional verbose flag
func (c *WhoisClient) rawQueryWithOptions(ctx context.Context, query, server string, verbose bool) (string, error) {
	// Connect to the WHOIS server
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %w", server, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			// Log the close error but don't return it as it's not critical
		}
	}()

	// Set deadline for the connection
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return "", fmt.Errorf("failed to set deadline: %w", err)
		}
	}

	// Prepare the query with optional verbose flag
	var queryLine string
	if verbose {
		queryLine = " -v " + query + "\r\n"
	} else {
		queryLine = query + "\r\n"
	}

	// Send the query
	_, err = conn.Write([]byte(queryLine))
	if err != nil {
		return "", fmt.Errorf("failed to send query to WHOIS server: %w", err)
	}

	// Read the response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		line := scanner.Text()
		response.WriteString(line)
		response.WriteString("\n")

		// Check for end of response indicators
		if strings.Contains(line, "%") && (strings.Contains(line, "end") || strings.Contains(line, "End")) {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read response from WHOIS server: %w", err)
	}

	return response.String(), nil
}

// ExtractASN extracts ASN information from whois output
func ExtractASN(whoisOutput string) []string {
	// Common patterns for ASN in whois output
	asnPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)origin(?:al)?\s*as(?:n)?:?\s*(as\d+)`),
		regexp.MustCompile(`(?i)autonomous\s+system\s+number:?\s*(as\d+|\d+)`),
		regexp.MustCompile(`(?i)asn:?\s*(as\d+|\d+)`),
		regexp.MustCompile(`(?i)as(?:n|num):?\s*(as\d+|\d+)`),
		regexp.MustCompile(`(?i)origin:?\s*(as\d+)`),
	}

	lines := strings.Split(whoisOutput, "\n")
	asns := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, pattern := range asnPatterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				asn := strings.ToUpper(matches[1])
				// Ensure ASN starts with "AS"
				if !strings.HasPrefix(asn, "AS") {
					asn = "AS" + asn
				}
				asns = append(asns, asn)
			}
		}
	}

	return asns
}

// WhoisASN performs a whois lookup and extracts ASN information
func WhoisASN(query string) ([]string, error) {
	client := NewWhoisClient()
	output, err := client.Whois(query)
	if err != nil {
		return nil, err
	}
	return ExtractASN(output), nil
}

// WhoisASNWithContext performs a whois lookup with context and extracts ASN information
func WhoisASNWithContext(ctx context.Context, query string) ([]string, error) {
	client := NewWhoisClient()
	output, err := client.WhoisWithContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return ExtractASN(output), nil
}
