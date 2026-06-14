package cctld

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	httpclient "github.com/Method-Security/pkg/httpclient"
)

const (
	maxBodyBytes  = 512 * 1024 // 512 KB cap for similarity + title extraction
	maxTitleBytes = 512        // title truncation cap
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// ProbeResult holds the output of an HTTP/HTTPS probe against one candidate.
type ProbeResult struct {
	HTTPStatus   *int
	HTTPSStatus  *int
	FinalURL     *string
	Title        *string
	ServerHeader *string
	CertSubject  *string
	CertSANs     []string
	Body         string // raw body, capped at maxBodyBytes, for similarity

	// RedirectedOffCandidate is true when the probe followed redirects to a
	// final URL whose host is no longer the candidate FQDN (case-insensitive,
	// port-insensitive). Callers should NOT use the body / title / similarity
	// signal when this is set — what we tokenized is the redirect target's
	// content, not the candidate's. This protects against a regional
	// subsidiary that redirects to the global site looking like an
	// impersonation just because the tokens are identical.
	RedirectedOffCandidate bool
}

// ProbeWeb fetches HTTPS then HTTP for the given host (bare hostname).
// timeoutMs is the per-request timeout in milliseconds.
func ProbeWeb(ctx context.Context, host string, timeoutMs int) ProbeResult {
	result := ProbeResult{}
	dur := time.Duration(timeoutMs) * time.Millisecond

	// HTTPS probe
	httpsResult, httpsBody := probeURL(ctx, "https://"+host, dur)
	if httpsResult != nil {
		result.HTTPSStatus = &httpsResult.StatusCode
		if httpsResult.FinalURL != "" {
			result.FinalURL = &httpsResult.FinalURL
		}
		if httpsResult.ServerHeader != "" {
			result.ServerHeader = &httpsResult.ServerHeader
		}
		if httpsResult.Title != "" {
			result.Title = &httpsResult.Title
		}
		if httpsResult.CertSubject != "" {
			result.CertSubject = &httpsResult.CertSubject
		}
		result.CertSANs = httpsResult.CertSANs
		result.Body = httpsBody
		if redirectLeftHost(host, httpsResult.FinalURL) {
			result.RedirectedOffCandidate = true
		}
	}

	// HTTP probe (always run, captures status even if HTTPS succeeded)
	httpResult, httpBody := probeURL(ctx, "http://"+host, dur)
	if httpResult != nil {
		result.HTTPStatus = &httpResult.StatusCode
		// If HTTPS gave no usable body/title, fall back to HTTP
		if result.Body == "" {
			result.Body = httpBody
		}
		if result.FinalURL == nil && httpResult.FinalURL != "" {
			result.FinalURL = &httpResult.FinalURL
		}
		if result.Title == nil && httpResult.Title != "" {
			result.Title = &httpResult.Title
		}
		if result.ServerHeader == nil && httpResult.ServerHeader != "" {
			result.ServerHeader = &httpResult.ServerHeader
		}
		// If only the HTTP probe had a usable body and that body came from
		// off-candidate, propagate the off-candidate flag too.
		if !result.RedirectedOffCandidate && redirectLeftHost(host, httpResult.FinalURL) {
			result.RedirectedOffCandidate = true
		}
	}

	return result
}

// redirectLeftHost reports whether finalURL points at a host that differs
// from the candidate. The candidate is a bare hostname; finalURL is the
// post-redirect URL. Case-insensitive on host, port-insensitive. Returns
// false for unparseable or empty finalURL.
func redirectLeftHost(candidate string, finalURL string) bool {
	if finalURL == "" {
		return false
	}
	u, err := url.Parse(finalURL)
	if err != nil || u == nil {
		return false
	}
	finalHost := strings.ToLower(u.Hostname())
	if finalHost == "" {
		return false
	}
	return finalHost != strings.ToLower(candidate)
}

// rawProbeResult is an intermediate internal result from a single URL probe.
type rawProbeResult struct {
	StatusCode   int
	FinalURL     string
	Title        string
	ServerHeader string
	CertSubject  string
	CertSANs     []string
}

func probeURL(ctx context.Context, rawURL string, timeout time.Duration) (*rawProbeResult, string) {
	client := httpclient.New(
		httpclient.WithTimeout(timeout),
		httpclient.WithTLSVerify(false),
		httpclient.WithMaxRedirects(10),
		httpclient.WithRedirectTracking(),
	)

	resp, err := client.Get(ctx, rawURL)
	if err != nil {
		return nil, ""
	}

	result := &rawProbeResult{
		StatusCode:   resp.StatusCode,
		ServerHeader: resp.Headers.Get("Server"),
	}

	// Determine final URL from redirect chain
	if len(resp.RedirectChain) > 0 {
		result.FinalURL = resp.RedirectChain[len(resp.RedirectChain)-1].URL
	} else {
		result.FinalURL = rawURL
	}

	// Cap body
	body := resp.Body
	if len(body) > maxBodyBytes {
		body = body[:maxBodyBytes]
	}
	bodyStr := string(body)

	// Extract title
	if m := titleRe.FindSubmatch(body); len(m) > 1 {
		title := strings.TrimSpace(string(m[1]))
		if len(title) > maxTitleBytes {
			title = title[:maxTitleBytes]
		}
		result.Title = title
	}

	// Extract TLS cert info if this is an HTTPS probe
	if strings.HasPrefix(rawURL, "https://") {
		extractTLSInfo(rawURL, timeout, result)
	}

	return result, bodyStr
}

// extractTLSInfo performs a raw TLS dial to extract cert subject and SANs.
// We do a separate dial because http.Client doesn't expose the TLS state easily
// after following redirects.
func extractTLSInfo(rawURL string, timeout time.Duration, result *rawProbeResult) {
	// Parse host from URL
	host := strings.TrimPrefix(rawURL, "https://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, "?"); idx >= 0 {
		host = host[:idx]
	}

	// Ensure host has port. Use net.JoinHostPort so IPv6 literals like
	// "[::1]" get bracketed correctly; bare hostnames pass through.
	hostPort := host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		hostPort = net.JoinHostPort(host, "443")
	}

	// A ccTLD recon probe needs to capture certs from arbitrary registries —
	// many candidates legitimately have self-signed, expired, or hostname-
	// mismatched certs (parked, misconfigured, lookalike-with-cheap-cert).
	// Validating would drop most of the signal this tool exists to produce.
	skipVerify := true
	tlsConf := &tls.Config{
		InsecureSkipVerify: skipVerify, //nolint:gosec // intentional for recon
		ServerName:         host,
	}
	dialer := &tls.Dialer{
		Config: tlsConf,
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}

	leaf := state.PeerCertificates[0]
	result.CertSubject = leaf.Subject.String()

	// Collect SANs: DNS names + IP addresses
	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	result.CertSANs = sans
}

// FetchBody fetches the body of a URL for baseline computation.
func FetchBody(ctx context.Context, rawURL string, timeoutMs int) string {
	dur := time.Duration(timeoutMs) * time.Millisecond
	client := httpclient.New(
		httpclient.WithTimeout(dur),
		httpclient.WithTLSVerify(false),
		httpclient.WithMaxRedirects(10),
	)
	resp, err := client.Get(ctx, rawURL)
	if err != nil {
		return ""
	}
	body := resp.Body
	if len(body) > maxBodyBytes {
		body = body[:maxBodyBytes]
	}
	return string(body)
}
