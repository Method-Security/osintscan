package config

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/Method-Security/pkg/httpclient"
)

func TestProxyConfigFromContext(t *testing.T) {
	ctx := SetProxyConfig(context.Background(), "http://127.0.0.1:8080", "socks5://127.0.0.1:1080")

	proxyConfig := ProxyConfigFromContext(ctx)
	if proxyConfig.HttpProxy != "http://127.0.0.1:8080" {
		t.Fatalf("expected HTTP proxy to round trip, got %q", proxyConfig.HttpProxy)
	}
	if proxyConfig.SocksProxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("expected SOCKS proxy to round trip, got %q", proxyConfig.SocksProxy)
	}
}

func TestHTTPClientOptionsFromContext(t *testing.T) {
	ctx := SetProxyConfig(context.Background(), "http://127.0.0.1:8080", "socks5://127.0.0.1:1080")

	options := HTTPClientOptionsFromContext(ctx, httpclient.WithMaxRedirects(0))
	if len(options) != 3 {
		t.Fatalf("expected base option plus two proxy options, got %d", len(options))
	}
}

func TestConfigureHTTPTransportFromContextUsesHTTPProxy(t *testing.T) {
	ctx := SetProxyConfig(context.Background(), "http://127.0.0.1:8080", "")
	transport := &http.Transport{}

	if err := ConfigureHTTPTransportFromContext(ctx, transport); err != nil {
		t.Fatalf("expected HTTP proxy configuration to succeed: %v", err)
	}
	if transport.Proxy == nil {
		t.Fatal("expected HTTP proxy function to be configured")
	}

	requestURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("failed to parse request URL: %v", err)
	}
	proxyURL, err := transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatalf("expected proxy lookup to succeed: %v", err)
	}
	if proxyURL.String() != "http://127.0.0.1:8080" {
		t.Fatalf("expected configured proxy URL, got %s", proxyURL.String())
	}
}

func TestConfigureHTTPTransportFromContextRejectsInvalidSOCKSProxy(t *testing.T) {
	ctx := SetProxyConfig(context.Background(), "", "http://127.0.0.1:8080")
	transport := &http.Transport{}

	if err := ConfigureHTTPTransportFromContext(ctx, transport); err == nil {
		t.Fatal("expected invalid SOCKS proxy scheme to fail")
	}
}
