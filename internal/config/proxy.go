package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Method-Security/pkg/httpclient"
	"golang.org/x/net/proxy"
)

type proxyContextKey struct{}

type ProxyConfig struct {
	HttpProxy  string
	SocksProxy string
}

func SetProxyConfig(ctx context.Context, httpProxy string, socksProxy string) context.Context {
	return context.WithValue(ctx, proxyContextKey{}, ProxyConfig{
		HttpProxy:  httpProxy,
		SocksProxy: socksProxy,
	})
}

func ProxyConfigFromContext(ctx context.Context) ProxyConfig {
	if ctx == nil {
		return ProxyConfig{}
	}
	proxyConfig, ok := ctx.Value(proxyContextKey{}).(ProxyConfig)
	if !ok {
		return ProxyConfig{}
	}
	return proxyConfig
}

func HTTPClientOptionsFromContext(ctx context.Context, options ...httpclient.Option) []httpclient.Option {
	proxyConfig := ProxyConfigFromContext(ctx)
	if proxyConfig.HttpProxy != "" {
		options = append(options, httpclient.WithHTTPProxy(proxyConfig.HttpProxy))
	}
	if proxyConfig.SocksProxy != "" {
		options = append(options, httpclient.WithSOCKSProxy(proxyConfig.SocksProxy))
	}
	return options
}

func NewHTTPClientFromContext(ctx context.Context, verifyTLS bool, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !verifyTLS, //nolint:gosec // configurable by caller
		},
	}
	if err := ConfigureHTTPTransportFromContext(ctx, transport); err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

func ConfigureHTTPTransportFromContext(ctx context.Context, transport *http.Transport) error {
	proxyConfig := ProxyConfigFromContext(ctx)
	return proxyConfig.ConfigureHTTPTransport(transport)
}

func (p ProxyConfig) ConfigureHTTPTransport(transport *http.Transport) error {
	if transport == nil {
		return fmt.Errorf("HTTP transport is nil")
	}

	if p.SocksProxy != "" {
		return configureSOCKSProxy(transport, p.SocksProxy)
	}
	if p.HttpProxy != "" {
		return configureHTTPProxy(transport, p.HttpProxy)
	}
	return nil
}

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

func configureSOCKSProxy(transport *http.Transport, proxyURL string) error {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid SOCKS proxy URL: %w", err)
	}

	dialer, err := proxy.FromURL(parsedURL, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS proxy dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("SOCKS proxy dialer does not support context-aware dialing")
	}

	transport.Proxy = noHTTPProxy
	transport.DialContext = contextDialer.DialContext
	return nil
}
