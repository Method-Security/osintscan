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

// ValidateDNSServerAddress checks if the DNS server address is in the correct format (IP:PORT or HOSTNAME:PORT)
func ValidateDNSServerAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If no port specified, provide helpful error
		if !strings.Contains(address, ":") {
			return fmt.Errorf("DNS server address must include port (e.g., %s:53)", address)
		}
		return fmt.Errorf("invalid DNS server address format: %v", err)
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
func GetResolver(dnsServerAddress string, log svc1log.Logger) *net.Resolver {
	var resolver *net.Resolver
	if dnsServerAddress == "" {
		log.Info("Using system default DNS resolver")
		resolver = &net.Resolver{}
	} else {
		log.Info("Using custom DNS server address", svc1log.SafeParam("dnsServerAddress", dnsServerAddress))
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 10,
				}
				return d.DialContext(ctx, "udp", dnsServerAddress)
			},
		}
	}
	return resolver
}
