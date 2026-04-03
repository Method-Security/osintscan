package utils

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// ValidateDNSServerAddress checks if the DNS server address is valid.
// Accepts IP, IP:PORT, HOSTNAME, or HOSTNAME:PORT formats. Port 53 is assumed when omitted.
func ValidateDNSServerAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// No port specified — that's fine, we'll default to 53.
		// Validate the bare address as an IP or hostname.
		if ip := net.ParseIP(address); ip != nil {
			return nil // Valid bare IP
		}
		// Try as hostname (no port)
		host = address
		port = "53"
		_ = port // port is only used for format validation below when SplitHostPort succeeds
		// Fall through to hostname validation
		host = strings.TrimSuffix(host, ".")
		if len(host) == 0 || len(host) > 253 {
			return fmt.Errorf("invalid hostname length: %s", host)
		}
		validHostname := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
		if !validHostname.MatchString(host) {
			return fmt.Errorf("invalid DNS server address format: %s", address)
		}
		return nil
	}

	// Validate port number
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number in DNS server address: %s", port)
	}

	// Check if it's an IP address
	if ip := net.ParseIP(host); ip != nil {
		return nil // Valid IP
	}

	// Not an IP, try to validate as hostname
	// Quick validation: check basic hostname rules
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("invalid hostname length: %s", host)
	}

	// Check for valid hostname characters and structure
	// This regex allows alphanumeric, dots, and hyphens in valid positions
	validHostname := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	// Remove trailing dot if present (valid in FQDN)
	host = strings.TrimSuffix(host, ".")

	if !validHostname.MatchString(host) {
		return fmt.Errorf("invalid hostname format: %s", host)
	}

	return nil
}

// GetResolver returns a new resolver with the given DNS server address.
// If the DNS server address is empty, the system default resolver is used.
// If the DNS server address is provided, the resolver is configured to use the given DNS server address.
// If no port is specified, port 53 is assumed.
func GetResolver(dnsServerAddress string, log svc1log.Logger) *net.Resolver {
	var resolver *net.Resolver
	if dnsServerAddress == "" {
		log.Info("Using system default DNS resolver")
		resolver = &net.Resolver{}
	} else {
		addr := NormalizeDNSAddress(dnsServerAddress)
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 10,
				}
				return d.DialContext(ctx, "udp", addr)
			},
		}
	}
	return resolver
}

// GetResolvers creates a list of resolvers from the given addresses.
// If the list is empty, returns a single system default resolver.
func GetResolvers(dnsServerAddresses []string, log svc1log.Logger) []*net.Resolver {
	if len(dnsServerAddresses) == 0 {
		log.Info("No DNS resolvers specified, using system default")
		return []*net.Resolver{{}}
	}
	resolvers := make([]*net.Resolver, len(dnsServerAddresses))
	for i, addr := range dnsServerAddresses {
		resolvers[i] = GetResolver(addr, log)
	}
	return resolvers
}

// NormalizeDNSAddress ensures a DNS server address includes a port.
// If no port is specified, it defaults to port 53.
func NormalizeDNSAddress(address string) string {
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return net.JoinHostPort(address, "53")
	}
	return address
}
