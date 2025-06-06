package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// validateDNSServerAddress checks if the DNS server address is in the correct format (IP:PORT)
func ValidateDNSServerAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid DNS server address format: %v", err)
	}

	// Validate IP address
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("invalid IP address in DNS server address: %s", host)
	}

	// Validate port number
	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number in DNS server address: %s", port)
	}

	return nil
}

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
