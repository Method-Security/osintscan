package subnet

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/openrdap/rdap"
	subnetfern "github.com/Method-Security/osintscan/generated/go/subnet"
)

func ptr[T any](v T) *T {
	return &v
}

func containsLetter(s string) bool {
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}

// ✅ Now accepts a custom DNS resolver IP
func ResearchSubnet(ctx context.Context, network *net.IPNet, dnsResolver string) (*subnetfern.SubnetResearchOutput, error) {
	ips := enumerateIPs(network)
	results := make([]*subnetfern.IpInfo, len(ips))

	maxWorkers := 20
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(index int, ipAddr net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			ipStr := ipAddr.String()
			result := subnetfern.IpInfo{Ip: ipStr}

			// Use custom DNS resolver if provided
			var resolver *net.Resolver
			if dnsResolver != "" {
				resolver = &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{}
						return d.DialContext(ctx, "udp", dnsResolver+":53")
					},
				}
			} else {
				resolver = net.DefaultResolver
			}

			if names, err := resolver.LookupAddr(ctx, ipStr); err == nil && len(names) > 0 {
				result.Ptr = ptr(names[0])
			}

			if asnInfo, err := lookupASN(ipStr); err == nil && asnInfo != nil {
				result.Asn = asnInfo
			}

			rdapClient := &rdap.Client{}
			if whoisInfo, err := lookupRDAP(rdapClient, ipStr); err == nil && whoisInfo != nil {
				result.Whois = whoisInfo
			}

			results[index] = &result
		}(i, ip)
	}

	wg.Wait()

	return &subnetfern.SubnetResearchOutput{
		Subnet: network.String(),
		Hosts:  results,
	}, nil
}

func enumerateIPs(network *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := network.IP.Mask(network.Mask); network.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func lookupASN(ip string) (*subnetfern.AsnInfo, error) {
	conn, err := net.DialTimeout("tcp", "whois.cymru.com:43", 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to whois.cymru.com:43 for IP %s: %v", ip, err)
		return nil, err
	}
	defer conn.Close()

	query := fmt.Sprintf("begin\nverbose\n%s\nend\n", ip)
	_, err = conn.Write([]byte(query))
	if err != nil {
		log.Printf("Failed to send WHOIS query for IP %s: %v", ip, err)
		return nil, err
	}

	scanner := bufio.NewScanner(conn)
	var response []string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Bulk mode;") && !strings.HasPrefix(line, "Error:") {
			response = append(response, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Failed to read WHOIS response for IP %s: %v", ip, err)
		return nil, err
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("empty WHOIS response for IP %s", ip)
	}

	fields := strings.Split(response[0], "|")
	if len(fields) < 7 {
		return nil, fmt.Errorf("unexpected WHOIS response format for IP %s: %v", ip, fields)
	}

	asnStr := strings.TrimSpace(fields[0])
	asName := strings.TrimSpace(fields[6])

	var asn int
	if _, err := fmt.Sscanf(asnStr, "%d", &asn); err != nil {
		return nil, fmt.Errorf("invalid ASN number for IP %s: %v", ip, err)
	}

	return &subnetfern.AsnInfo{
		Number: asn,
		Name:   asName,
	}, nil
}

func lookupRDAP(client *rdap.Client, ip string) (*subnetfern.WhoisInfo, error) {
	resp, err := client.QueryIP(ip)
	if err != nil {
		return nil, err
	}

	whois := &subnetfern.WhoisInfo{
		Organization: ptr(resp.Name),
		Handle:       ptr(resp.Handle),
		Country:      ptr(resp.Country),
		Range:        ptr(fmt.Sprintf("%s - %s", resp.StartAddress, resp.EndAddress)),
	}

	for _, ev := range resp.Events {
		if ev.Action == "registration" {
			t, err := time.Parse(time.RFC3339, ev.Date)
			if err == nil {
				whois.RegistrationDate = &t
			}
		}
	}

	for _, ent := range resp.Entities {
		for _, role := range ent.Roles {
			if role == "abuse" || role == "administrative" || role == "registrant" {
				if ent.VCard != nil && ent.VCard.Email() != "" {
					whois.ContactEmail = ptr(ent.VCard.Email())
					return whois, nil
				}
			}
		}
	}

	return whois, nil
}

