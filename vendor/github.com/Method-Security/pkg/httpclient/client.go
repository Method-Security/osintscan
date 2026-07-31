// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Client wraps http.Client with Method-specific defaults and helpers.
type Client struct {
	httpClient     *http.Client
	options        Options
	defaultHeaders map[string]string
	proxyConfigErr error
}

// Options configures the HTTP client behavior.
type Options struct {
	Timeout                   time.Duration
	VerifyTLS                 bool
	MaxRedirects              int
	TrackRedirects            bool
	BlockCrossDomainRedirects bool
	DefaultHeaders            map[string]string
	HTTPProxy                 string
	SOCKSProxy                string
}

// Option is a functional option for configuring the HTTP client.
type Option func(*Options)

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.Timeout = d
	}
}

// WithTLSVerify controls whether TLS certificate verification is enabled.
func WithTLSVerify(verify bool) Option {
	return func(o *Options) {
		o.VerifyTLS = verify
	}
}

// WithMaxRedirects sets the maximum number of redirects to follow.
// Set to 0 to disable redirects. Default is 10.
func WithMaxRedirects(n int) Option {
	return func(o *Options) {
		o.MaxRedirects = n
	}
}

// WithRedirectTracking enables tracking of the full redirect chain in responses.
func WithRedirectTracking() Option {
	return func(o *Options) {
		o.TrackRedirects = true
	}
}

// WithBlockCrossDomainRedirects blocks redirects that change the host.
func WithBlockCrossDomainRedirects() Option {
	return func(o *Options) {
		o.BlockCrossDomainRedirects = true
	}
}

// WithDefaultHeaders sets headers that are applied to every request.
func WithDefaultHeaders(headers map[string]string) Option {
	return func(o *Options) {
		o.DefaultHeaders = headers
	}
}

// WithHTTPProxy sets an HTTP/HTTPS proxy URL for all requests.
// The proxyURL should be in the format: http://[user:pass@]host:port
func WithHTTPProxy(proxyURL string) Option {
	return func(o *Options) {
		o.HTTPProxy = proxyURL
	}
}

// WithSOCKSProxy sets a SOCKS5 proxy URL for all requests.
// The proxyURL should be in the format: socks5://[user:pass@]host:port
func WithSOCKSProxy(proxyURL string) Option {
	return func(o *Options) {
		o.SOCKSProxy = proxyURL
	}
}

// defaultOptions returns the default client options.
func defaultOptions() Options {
	return Options{
		Timeout:        30 * time.Second,
		VerifyTLS:      true,
		MaxRedirects:   10,
		TrackRedirects: false,
	}
}

// New creates a new HTTP client with the given options.
func New(opts ...Option) *Client {
	options := defaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	transport := &http.Transport{
		// Force HTTP/2 negotiation over ALPN. Setting a custom TLSClientConfig
		// otherwise disables Go's automatic HTTP/2 upgrade, so this flag is
		// required to keep HTTP/2 enabled.
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !options.VerifyTLS, //nolint:gosec // configurable by caller
		},
	}

	proxyConfigErr := configureProxy(transport, &options)

	client := &http.Client{
		Timeout:   options.Timeout,
		Transport: transport,
	}

	// Disable Go's built-in redirect following — we handle redirects manually in Do().
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{
		httpClient:     client,
		options:        options,
		defaultHeaders: options.DefaultHeaders,
		proxyConfigErr: proxyConfigErr,
	}
}

// configureProxy sets up proxy configuration on the transport.
// Supports both HTTP/HTTPS and SOCKS5 proxies.
// If both are specified, SOCKS5 takes precedence.
func configureProxy(transport *http.Transport, options *Options) error {
	// SOCKS5 proxy takes precedence if both are specified
	if options.SOCKSProxy != "" {
		return configureSOCKS5Proxy(transport, options.SOCKSProxy)
	}

	if options.HTTPProxy != "" {
		return configureHTTPProxy(transport, options.HTTPProxy)
	}

	return nil
}

// configureHTTPProxy configures an HTTP/HTTPS proxy.
func configureHTTPProxy(transport *http.Transport, proxyURL string) error {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid HTTP proxy URL: %w", err)
	}

	transport.Proxy = http.ProxyURL(parsedURL)
	return nil
}

func noHTTPProxy(*http.Request) (*url.URL, error) {
	return nil, nil
}

// configureSOCKS5Proxy configures a SOCKS5 proxy.
func configureSOCKS5Proxy(transport *http.Transport, proxyURL string) error {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 proxy URL: %w", err)
	}

	// Create SOCKS5 dialer
	dialer, err := proxy.FromURL(parsedURL, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("SOCKS5 dialer does not support context-aware dialing")
	}

	// Configure transport to use SOCKS5 dialer
	transport.Proxy = noHTTPProxy
	transport.DialContext = contextDialer.DialContext

	return nil
}

// Response wraps an HTTP response with additional metadata.
type Response struct {
	StatusCode    int
	Headers       http.Header
	Body          []byte
	RedirectChain []RedirectHop
}

// RedirectHop records a single redirect in the chain.
type RedirectHop struct {
	URL        string
	StatusCode int
}

// applyDefaultHeaders sets default headers on the request.
// Does not override headers already set on the request.
func (c *Client) applyDefaultHeaders(req *http.Request) {
	for k, v := range c.defaultHeaders {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
}

// applyHeaders sets per-request headers, then fills in any remaining defaults.
func (c *Client) applyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.applyDefaultHeaders(req)
}

// Get performs an HTTP GET request.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.GetWithHeaders(ctx, url, nil)
}

// GetWithHeaders performs an HTTP GET request with custom headers.
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.applyHeaders(req, headers)
	return c.Do(req)
}

// Head performs an HTTP HEAD request.
func (c *Client) Head(ctx context.Context, url string) (*Response, error) {
	return c.HeadWithHeaders(ctx, url, nil)
}

// HeadWithHeaders performs an HTTP HEAD request with custom headers.
func (c *Client) HeadWithHeaders(ctx context.Context, url string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.applyHeaders(req, headers)
	return c.Do(req)
}

// Post performs an HTTP POST request with a JSON body.
func (c *Client) Post(ctx context.Context, url string, body any) (*Response, error) {
	return c.PostWithHeaders(ctx, url, body, nil)
}

// PostWithHeaders performs an HTTP POST request with a JSON body and custom headers.
func (c *Client) PostWithHeaders(ctx context.Context, url string, body any, headers map[string]string) (*Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.applyHeaders(req, headers)
	// Set Content-Type after applyHeaders so defaults can't override it.
	req.Header.Set("Content-Type", "application/json")
	return c.Do(req)
}

// PostForm performs an HTTP POST request with form-encoded body.
func (c *Client) PostForm(ctx context.Context, requestURL string, values url.Values) (*Response, error) {
	return c.PostFormWithHeaders(ctx, requestURL, values, nil)
}

// PostFormWithHeaders performs an HTTP POST request with form-encoded body and custom headers.
func (c *Client) PostFormWithHeaders(ctx context.Context, requestURL string, values url.Values, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.applyHeaders(req, headers)
	// Set Content-Type after applyHeaders so defaults can't override it.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(req)
}

// Request performs an HTTP request with an arbitrary method, body, and headers.
func (c *Client) Request(ctx context.Context, method, requestURL string, body io.Reader, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.applyHeaders(req, headers)
	return c.Do(req)
}

// readResponse reads the body and constructs a Response.
func readResponse(resp *http.Response, redirectChain []RedirectHop) (*Response, error) {
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response body: %w", readErr)
	}
	return &Response{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		Body:          body,
		RedirectChain: redirectChain,
	}, nil
}

// Do executes an HTTP request, handling redirects manually.
func (c *Client) Do(req *http.Request) (*Response, error) {
	if c.proxyConfigErr != nil {
		return nil, fmt.Errorf("proxy configuration failed: %w", c.proxyConfigErr)
	}

	var redirectChain []RedirectHop

	// Buffer the request body for replay on 307/308 redirects.
	var bodyBuffer []byte
	if req.Body != nil {
		var err error
		bodyBuffer, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to buffer request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBuffer))
	}

	// Capture the original headers for replay on redirects.
	originalHeaders := req.Header.Clone()
	currentReq := req

	for redirects := 0; ; redirects++ {
		resp, err := c.httpClient.Do(currentReq)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}

		// Only treat actual redirect status codes as redirects (not 304 Not Modified, etc.).
		isRedirect := resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusSeeOther ||
			resp.StatusCode == http.StatusTemporaryRedirect ||
			resp.StatusCode == http.StatusPermanentRedirect

		if !isRedirect || redirects >= c.options.MaxRedirects {
			return readResponse(resp, redirectChain)
		}

		// It's a redirect. Record the hop if tracking.
		if c.options.TrackRedirects {
			redirectChain = append(redirectChain, RedirectHop{
				URL:        currentReq.URL.String(),
				StatusCode: resp.StatusCode,
			})
		}

		// Get location header.
		location := resp.Header.Get("Location")
		if location == "" {
			// Redirect with no Location — return the response as-is.
			return readResponse(resp, redirectChain)
		}
		_ = resp.Body.Close()

		// Resolve relative redirect URL.
		nextURL, parseErr := currentReq.URL.Parse(location)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse redirect location: %w", parseErr)
		}

		// Block cross-domain redirects if configured.
		if c.options.BlockCrossDomainRedirects && currentReq.URL.Host != nextURL.Host {
			return nil, fmt.Errorf("cross-domain redirect blocked: %s -> %s", currentReq.URL.Host, nextURL.Host)
		}

		// Determine method for the redirected request:
		// - 307/308: preserve original method and body
		// - 301/302/303: preserve GET/HEAD, convert others to GET (per HTTP spec)
		nextMethod := currentReq.Method
		var nextBody io.Reader
		if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			if bodyBuffer != nil {
				nextBody = bytes.NewReader(bodyBuffer)
			}
		} else {
			if nextMethod != http.MethodGet && nextMethod != http.MethodHead {
				nextMethod = http.MethodGet
			}
		}

		nextReq, err := http.NewRequestWithContext(currentReq.Context(), nextMethod, nextURL.String(), nextBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create redirect request: %w", err)
		}
		// Preserve original headers across redirects, but strip sensitive
		// headers on cross-domain redirects to prevent credential leaking.
		nextHeaders := originalHeaders.Clone()
		if currentReq.URL.Host != nextURL.Host {
			nextHeaders.Del("Authorization")
			nextHeaders.Del("Cookie")
			nextHeaders.Del("Www-Authenticate")
		}
		nextReq.Header = nextHeaders
		currentReq = nextReq
	}
}

// GetJSON performs a GET request and unmarshals the JSON response into dest.
func (c *Client) GetJSON(ctx context.Context, url string, dest any) (*Response, error) {
	resp, err := c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	if err := json.Unmarshal(resp.Body, dest); err != nil {
		return resp, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	return resp, nil
}

// PostJSON performs a POST request with a JSON body and unmarshals the response into dest.
func (c *Client) PostJSON(ctx context.Context, url string, body any, dest any) (*Response, error) {
	resp, err := c.Post(ctx, url, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	if err := json.Unmarshal(resp.Body, dest); err != nil {
		return resp, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	return resp, nil
}

// IsAlive checks if a URL responds with a non-404/502 status code.
func (c *Client) IsAlive(ctx context.Context, url string) bool {
	resp, err := c.Get(ctx, url)
	if err != nil {
		return false
	}
	return resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadGateway
}
