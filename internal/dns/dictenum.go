package dns

import (
	"context"
	"fmt"
	"net"
)

func BruteEnumDomainSubdomains(ctx context.Context, domain string, words []string) (RecordsReport, error) {
	for _, word := range words {
		resolveDNS(ctx, word+"."+domain)
	}
	return RecordsReport{}, nil
}

func resolveDNS(ctx context.Context, url string) {
	// Next step here is to read wordlist and loop through it.
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
