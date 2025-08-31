package utils

import (
	"fmt"
	"net"
)

// ExpandCIDR expands a CIDR range into individual IP addresses
func ExpandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ExplodeIPsFromAddressesAndCIDR extracts and expands all IPs from individual IP addresses and CIDR range
func ExplodeIPsFromAddressesAndCIDR(ipAddresses []string, cidr *string) ([]string, error) {
	allIPs := []string{}

	// Add individual IPs
	for _, ip := range ipAddresses {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ip)
		}
		allIPs = append(allIPs, ip)
	}

	// Add CIDR range IPs
	if cidr != nil && *cidr != "" {
		cidrIPs, err := ExpandCIDR(*cidr)
		if err != nil {
			return nil, fmt.Errorf("error expanding CIDR %s: %w", *cidr, err)
		}
		allIPs = append(allIPs, cidrIPs...)
	}

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses or CIDR range provided")
	}

	return allIPs, nil
}
