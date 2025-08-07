package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// BGPView offers quality ASN and CIDR information particularly for ASN info lookups

// BGPViewClient represents a client for the BGPView.io API
type BGPViewClient struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// BGPViewResponse represents the top-level response from BGPView API
type BGPViewResponse struct {
	Status        string       `json:"status"`
	StatusMessage string       `json:"status_message"`
	Data          *BGPViewData `json:"data"`
	Meta          *BGPViewMeta `json:"@meta"`
}

// BGPViewData represents the data section of BGPView response
type BGPViewData struct {
	IPv4Prefixes []BGPViewPrefix `json:"ipv4_prefixes"`
	IPv6Prefixes []BGPViewPrefix `json:"ipv6_prefixes"`
	// ASN Info fields
	ASN           int                   `json:"asn"`
	Name          string                `json:"name"`
	Description   string                `json:"description_short"`
	CountryCode   string                `json:"country_code"`
	Website       string                `json:"website"`
	EmailContacts []string              `json:"email_contacts"`
	AbuseContacts []string              `json:"abuse_contacts"`
	RIRAllocation *BGPViewRIRAllocation `json:"rir_allocation"`
}

// BGPViewPrefix represents a BGP prefix from BGPView API
type BGPViewPrefix struct {
	Prefix      string               `json:"prefix"`
	IP          string               `json:"ip"`
	CIDR        int                  `json:"cidr"`
	ROAStatus   string               `json:"roa_status"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	CountryCode string               `json:"country_code"`
	Parent      *BGPViewPrefixParent `json:"parent"`
}

// BGPViewPrefixParent represents parent prefix information
type BGPViewPrefixParent struct {
	Prefix           string `json:"prefix"`
	IP               string `json:"ip"`
	CIDR             int    `json:"cidr"`
	RIRName          string `json:"rir_name"`
	AllocationStatus string `json:"allocation_status"`
}

// BGPViewRIRAllocation represents RIR allocation information
type BGPViewRIRAllocation struct {
	RIRName          string `json:"rir_name"`
	CountryCode      string `json:"country_code"`
	DateAllocated    string `json:"date_allocated"`
	AllocationStatus string `json:"allocation_status"`
}

// BGPViewMeta represents metadata from BGPView API
type BGPViewMeta struct {
	TimeZone      string `json:"time_zone"`
	APIVersion    int    `json:"api_version"`
	ExecutionTime string `json:"execution_time"`
}

// NewBGPViewClient creates a new BGPView API client
func NewBGPViewClient() *BGPViewClient {
	// Initialize random seed for backoff calculations
	rand.Seed(time.Now().UnixNano())

	return &BGPViewClient{
		baseURL: "https://api.bgpview.io",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: "osintscan/1.0 (https://github.com/Method-Security/osintscan)",
	}
}

// SetTimeout sets the HTTP client timeout
func (c *BGPViewClient) SetTimeout(timeout time.Duration) *BGPViewClient {
	c.httpClient.Timeout = timeout
	return c
}

// SetUserAgent sets a custom User-Agent header
func (c *BGPViewClient) SetUserAgent(userAgent string) *BGPViewClient {
	c.userAgent = userAgent
	return c
}

// makeRequestWithRetry makes an HTTP request with retry logic for 429 responses
func (c *BGPViewClient) makeRequestWithRetry(ctx context.Context, url string, timeout time.Duration) (*http.Response, error) {
	log := svc1log.FromContext(ctx)
	startTime := time.Now()

	// If timeout is specified, create a context with timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	for attempt := 1; ; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("request cancelled: %w", ctx.Err())
		default:
		}

		// Create request with context
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}

		// Set headers
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")

		// Make the request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make HTTP request to BGPView API: %w", err)
		}

		// If we get a 429, implement retry logic
		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close() // Explicitly ignore close error for retry logic

			// Check if we've exceeded the timeout
			if timeout > 0 && time.Since(startTime) >= timeout {
				return nil, fmt.Errorf("timeout exceeded after %v while retrying 429 responses", timeout)
			}

			// Calculate random backoff between 10-60 seconds
			backoff := time.Duration(10+rand.Intn(51)) * time.Second

			log.Warn("Received 429 from BGPView API, retrying with backoff",
				svc1log.SafeParam("attempt", attempt),
				svc1log.SafeParam("backoff_seconds", backoff.Seconds()),
				svc1log.SafeParam("elapsed_time", time.Since(startTime).String()))

			// Wait for the backoff period
			select {
			case <-time.After(backoff):
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("request cancelled during backoff: %w", ctx.Err())
			}
		}

		// For any other status code, return the response (let caller handle it)
		return resp, nil
	}
}

// GetASNPrefixes retrieves all BGP prefixes for a given ASN
func (c *BGPViewClient) GetASNPrefixes(ctx context.Context, asn string) (*BGPViewResponse, error) {
	log := svc1log.FromContext(ctx)

	// Normalize ASN format for API call
	normalizedASN := normalizeASNForAPI(asn)

	url := fmt.Sprintf("%s/asn/%s/prefixes", c.baseURL, normalizedASN)
	log.Debug("Making BGPView API request", svc1log.SafeParam("url", url), svc1log.SafeParam("asn", normalizedASN))

	// Use the retry logic
	resp, err := c.makeRequestWithRetry(ctx, url, 0) // No timeout for this method
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from BGPView API")
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", closeErr.Error()))
		}
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("BGPView API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON response
	var bgpResponse BGPViewResponse
	if err := json.Unmarshal(body, &bgpResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Check API status
	if bgpResponse.Status != "ok" {
		return nil, fmt.Errorf("BGPView API error: %s", bgpResponse.StatusMessage)
	}

	log.Debug("BGPView API response received",
		svc1log.SafeParam("ipv4_prefixes", len(bgpResponse.Data.IPv4Prefixes)),
		svc1log.SafeParam("ipv6_prefixes", len(bgpResponse.Data.IPv6Prefixes)),
		svc1log.SafeParam("execution_time", bgpResponse.Meta.ExecutionTime))

	return &bgpResponse, nil
}

// GetASNCIDRs retrieves all CIDR prefixes for a given ASN using BGPView API
// This is the main function called by the ASN discovery module
func GetASNCIDRs(ctx context.Context, asn string) ([]string, error) {
	log := svc1log.FromContext(ctx)

	client := NewBGPViewClient()

	log.Info("Retrieving ASN CIDRs from BGPView", svc1log.SafeParam("asn", asn))

	response, err := client.GetASNPrefixes(ctx, asn)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASN prefixes from BGPView: %w", err)
	}

	if response.Data == nil {
		return nil, fmt.Errorf("no data returned from BGPView API")
	}

	// Extract CIDRs from both IPv4 and IPv6 prefixes
	var cidrs []string

	// Add IPv4 prefixes
	for _, prefix := range response.Data.IPv4Prefixes {
		if prefix.Prefix != "" {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	// Add IPv6 prefixes
	for _, prefix := range response.Data.IPv6Prefixes {
		if prefix.Prefix != "" {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	log.Info("Retrieved ASN CIDRs from BGPView",
		svc1log.SafeParam("asn", asn),
		svc1log.SafeParam("total_cidrs", len(cidrs)),
		svc1log.SafeParam("ipv4_cidrs", len(response.Data.IPv4Prefixes)),
		svc1log.SafeParam("ipv6_cidrs", len(response.Data.IPv6Prefixes)))

	return cidrs, nil
}

// GetASNCIDRsWithTimeout retrieves all CIDR prefixes for a given ASN using BGPView API with timeout
func GetASNCIDRsWithTimeout(ctx context.Context, asn string, timeout time.Duration) ([]string, error) {
	log := svc1log.FromContext(ctx)

	client := NewBGPViewClient()

	log.Info("Retrieving ASN CIDRs from BGPView with timeout",
		svc1log.SafeParam("asn", asn),
		svc1log.SafeParam("timeout", timeout.String()))

	response, err := client.GetASNPrefixesWithTimeout(ctx, asn, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get ASN prefixes from BGPView: %w", err)
	}

	if response.Data == nil {
		return nil, fmt.Errorf("no data returned from BGPView API")
	}

	// Extract CIDRs from both IPv4 and IPv6 prefixes
	var cidrs []string

	// Add IPv4 prefixes
	for _, prefix := range response.Data.IPv4Prefixes {
		if prefix.Prefix != "" {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	// Add IPv6 prefixes
	for _, prefix := range response.Data.IPv6Prefixes {
		if prefix.Prefix != "" {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	log.Info("Retrieved ASN CIDRs from BGPView",
		svc1log.SafeParam("asn", asn),
		svc1log.SafeParam("total_cidrs", len(cidrs)),
		svc1log.SafeParam("ipv4_cidrs", len(response.Data.IPv4Prefixes)),
		svc1log.SafeParam("ipv6_cidrs", len(response.Data.IPv6Prefixes)))

	return cidrs, nil
}

// GetASNCIDRsDetailed retrieves detailed CIDR information for a given ASN
// Returns the full BGPView response with additional metadata
func GetASNCIDRsDetailed(ctx context.Context, asn string) (*BGPViewResponse, error) {
	client := NewBGPViewClient()
	return client.GetASNPrefixes(ctx, asn)
}

// normalizeASNForAPI normalizes ASN format for BGPView API calls
// BGPView expects format like "AS23028"
func normalizeASNForAPI(asn string) string {
	// Remove whitespace and convert to uppercase
	normalized := strings.TrimSpace(strings.ToUpper(asn))

	// If it doesn't start with AS, add it
	if !strings.HasPrefix(normalized, "AS") {
		normalized = "AS" + normalized
	}

	return normalized
}

// ExtractCIDRsByCountry filters CIDRs by country code from BGPView response
func ExtractCIDRsByCountry(response *BGPViewResponse, countryCode string) []string {
	if response == nil || response.Data == nil {
		return nil
	}

	var cidrs []string
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))

	// Filter IPv4 prefixes by country
	for _, prefix := range response.Data.IPv4Prefixes {
		if strings.ToUpper(prefix.CountryCode) == countryCode {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	// Filter IPv6 prefixes by country
	for _, prefix := range response.Data.IPv6Prefixes {
		if strings.ToUpper(prefix.CountryCode) == countryCode {
			cidrs = append(cidrs, prefix.Prefix)
		}
	}

	return cidrs
}

// GetASNInfo retrieves comprehensive ASN information using BGPView API
func GetASNInfo(ctx context.Context, asn string) (*BGPViewResponse, error) {
	client := NewBGPViewClient()
	return client.GetASNInfo(ctx, asn)
}

// GetASNInfoWithTimeout retrieves comprehensive ASN information using BGPView API with timeout
func GetASNInfoWithTimeout(ctx context.Context, asn string, timeout time.Duration) (*BGPViewResponse, error) {
	client := NewBGPViewClient()
	return client.GetASNInfoWithTimeout(ctx, asn, timeout)
}

// GetASNInfo retrieves basic ASN information using BGPView API
// This provides an alternative to Cymru DNS for ASN description lookup
func (c *BGPViewClient) GetASNInfo(ctx context.Context, asn string) (*BGPViewResponse, error) {
	log := svc1log.FromContext(ctx)

	// Normalize ASN format for API call
	normalizedASN := normalizeASNForAPI(asn)

	url := fmt.Sprintf("%s/asn/%s", c.baseURL, normalizedASN)
	log.Debug("Making BGPView ASN info request", svc1log.SafeParam("url", url))

	// Use the retry logic
	resp, err := c.makeRequestWithRetry(ctx, url, 0) // No timeout for this method
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from BGPView API")
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", closeErr.Error()))
		}
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("BGPView API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var bgpResponse BGPViewResponse
	if err := json.Unmarshal(body, &bgpResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if bgpResponse.Status != "ok" {
		return nil, fmt.Errorf("BGPView API error: %s", bgpResponse.StatusMessage)
	}

	return &bgpResponse, nil
}

// GetASNPrefixesWithTimeout retrieves all BGP prefixes for a given ASN with timeout
func (c *BGPViewClient) GetASNPrefixesWithTimeout(ctx context.Context, asn string, timeout time.Duration) (*BGPViewResponse, error) {
	log := svc1log.FromContext(ctx)

	// Normalize ASN format for API call
	normalizedASN := normalizeASNForAPI(asn)

	url := fmt.Sprintf("%s/asn/%s/prefixes", c.baseURL, normalizedASN)
	log.Debug("Making BGPView API request with timeout",
		svc1log.SafeParam("url", url),
		svc1log.SafeParam("asn", normalizedASN),
		svc1log.SafeParam("timeout", timeout.String()))

	// Use the retry logic with timeout
	resp, err := c.makeRequestWithRetry(ctx, url, timeout)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from BGPView API")
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", closeErr.Error()))
		}
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("BGPView API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON response
	var bgpResponse BGPViewResponse
	if err := json.Unmarshal(body, &bgpResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Check API status
	if bgpResponse.Status != "ok" {
		return nil, fmt.Errorf("BGPView API error: %s", bgpResponse.StatusMessage)
	}

	log.Debug("BGPView API response received",
		svc1log.SafeParam("ipv4_prefixes", len(bgpResponse.Data.IPv4Prefixes)),
		svc1log.SafeParam("ipv6_prefixes", len(bgpResponse.Data.IPv6Prefixes)),
		svc1log.SafeParam("execution_time", bgpResponse.Meta.ExecutionTime))

	return &bgpResponse, nil
}

// GetASNInfoWithTimeout retrieves basic ASN information using BGPView API with timeout
func (c *BGPViewClient) GetASNInfoWithTimeout(ctx context.Context, asn string, timeout time.Duration) (*BGPViewResponse, error) {
	log := svc1log.FromContext(ctx)

	// Normalize ASN format for API call
	normalizedASN := normalizeASNForAPI(asn)

	url := fmt.Sprintf("%s/asn/%s", c.baseURL, normalizedASN)
	log.Debug("Making BGPView ASN info request with timeout",
		svc1log.SafeParam("url", url),
		svc1log.SafeParam("timeout", timeout.String()))

	// Use the retry logic with timeout
	resp, err := c.makeRequestWithRetry(ctx, url, timeout)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from BGPView API")
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", closeErr.Error()))
		}
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("BGPView API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var bgpResponse BGPViewResponse
	if err := json.Unmarshal(body, &bgpResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if bgpResponse.Status != "ok" {
		return nil, fmt.Errorf("BGPView API error: %s", bgpResponse.StatusMessage)
	}

	return &bgpResponse, nil
}
