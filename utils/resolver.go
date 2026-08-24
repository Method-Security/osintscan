package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// ValidateDNSServerAddress checks if the DNS server address is valid.
// Accepts IP, IP:PORT, HOSTNAME, or HOSTNAME:PORT formats. Port 53 is assumed when omitted.
func ValidateDNSServerAddress(address string) error {
	// Normalize to host:port so we can validate uniformly
	normalized := NormalizeDNSAddress(address)
	host, port, err := net.SplitHostPort(normalized)
	if err != nil {
		return fmt.Errorf("invalid DNS server address format: %s", address)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number in DNS server address: %s", port)
	}

	// Valid if it's an IP
	if net.ParseIP(host) != nil {
		return nil
	}

	// Otherwise validate as hostname via net.LookupHost-compatible check
	if len(host) == 0 || len(host) > 253 {
		return fmt.Errorf("invalid DNS server address: %s", address)
	}

	return nil
}

// GetResolver returns a new resolver with the given DNS server address.
// If the DNS server address is empty, the system default resolver is used.
// If the DNS server address is provided, the resolver is configured to use the given DNS server address.
// If no port is specified, port 53 is assumed.
func GetResolver(dnsServerAddress string, log svc1log.Logger) *net.Resolver {
	var resolver *net.Resolver
	dnsServerAddress = strings.TrimSpace(dnsServerAddress)
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
				return d.DialContext(ctx, network, addr)
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
	address = strings.TrimSpace(address)
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return net.JoinHostPort(address, "53")
	}
	return address
}
