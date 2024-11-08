package dns

import (
	"context"
	"fmt"
	"net"
)

func BruteEnumDomainSubdomains(ctx context.Context, domain string) (RecordsReport, error) {
	resolveDNS(ctx, domain)
	return RecordsReport{}, nil
}

func resolveDNS(ctx context.Context, url string) {
	// Perform DNS resolution using net.LookupHost
	ips, err := net.LookupHost(url)
	if err != nil {
		fmt.Println("Error resolving DNS:", err)
		return
	}

	// Print the resolved IP addresses
	fmt.Printf("DNS resolution for %s:\n", url)
	for _, ip := range ips {
		fmt.Println(ip)
	}
}
