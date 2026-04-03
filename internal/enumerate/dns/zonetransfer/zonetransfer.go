package zonetransfer

import (
	"context"
	"fmt"
	"net"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	"github.com/Method-Security/osintscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TestZoneTransfer discovers authoritative nameservers for each zone via NS records,
// resolves each NS hostname to an IP, then attempts an AXFR against each resolved DNS application.
func TestZoneTransfer(ctx context.Context, config dnsfern.EnumerateDnsZoneTransferConfig) (*dnsfern.EnumerateDnsZoneTransferReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}
	details := []*dnsfern.DnsZoneTransferDetails{}

	resolver := net.DefaultResolver
	if len(config.DnsResolvers) > 0 {
		resolver = utils.GetResolver(config.DnsResolvers[0], log)
	}

	for _, zone := range config.Zones {
		var zoneDetails *dnsfern.DnsZoneTransferDetails
		if len(config.TargetNameservers) > 0 {
			zoneDetails = testZoneDirect(ctx, zone, config.TargetNameservers, config.Timeout, log, &errors)
		} else {
			zoneDetails = testZone(ctx, zone, config.Timeout, resolver, log, &errors)
		}
		if len(zoneDetails.Applications) > 0 {
			details = append(details, zoneDetails)
		}
	}

	return &dnsfern.EnumerateDnsZoneTransferReport{
		Config: &config,
		Result: &dnsfern.EnumerateDnsZoneTransferResult{
			ZoneTransfers: details,
		},
		Errors: errors,
	}, nil
}

// testZoneDirect attempts AXFR against explicitly provided nameserver IPs,
// bypassing NS record lookup. Useful for internal DNS servers or when you know
// the nameserver IP directly.
func testZoneDirect(ctx context.Context, zone string, targetNameservers []string, timeout int, log svc1log.Logger, errors *[]string) *dnsfern.DnsZoneTransferDetails {
	applications := []*dnsfern.DnsZoneTransferApplication{}

	for _, ns := range targetNameservers {
		dnsServer := ns
		if _, _, err := net.SplitHostPort(ns); err != nil {
			dnsServer = net.JoinHostPort(ns, "53")
		}

		log.Info("Attempting direct zone transfer",
			svc1log.SafeParam("zone", zone),
			svc1log.SafeParam("dnsServer", dnsServer))

		records, success, errs := sendAXFRRequest(dnsServer, zone, timeout, log)
		for _, e := range errs {
			*errors = append(*errors, fmt.Sprintf("%s@%s: %s", zone, dnsServer, e))
		}

		if success {
			log.Info("Zone transfer succeeded",
				svc1log.SafeParam("zone", zone),
				svc1log.SafeParam("dnsServer", dnsServer),
				svc1log.SafeParam("records", len(records)))

			// Use the IP as the nameserver label since we don't have a hostname
			host, _, _ := net.SplitHostPort(dnsServer)
			applications = append(applications, &dnsfern.DnsZoneTransferApplication{
				Nameserver: host,
				DnsServer:  dnsServer,
				DnsRecords: records,
			})
		}
	}

	return &dnsfern.DnsZoneTransferDetails{
		Zone:         zone,
		Applications: applications,
	}
}

// testZone looks up NS records for the zone, resolves each NS hostname to an IP,
// and attempts an AXFR against each resolved DNS application.
func testZone(ctx context.Context, zone string, timeout int, resolver *net.Resolver, log svc1log.Logger, errors *[]string) *dnsfern.DnsZoneTransferDetails {
	applications := []*dnsfern.DnsZoneTransferApplication{}

	log.Info("Looking up NS records", svc1log.SafeParam("zone", zone))

	nsRecords, err := resolver.LookupNS(ctx, zone)
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("NS lookup failed for %s: %v", zone, err))
		return &dnsfern.DnsZoneTransferDetails{
			Zone:         zone,
			Applications: applications,
		}
	}

	log.Info("Found NS records", svc1log.SafeParam("zone", zone), svc1log.SafeParam("count", len(nsRecords)))

	seen := make(map[string]bool)
	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		if seen[nsHost] {
			continue
		}
		seen[nsHost] = true

		log.Info("Resolving NS hostname", svc1log.SafeParam("nameserver", nsHost))

		addrs, err := resolver.LookupHost(ctx, nsHost)
		if err != nil {
			*errors = append(*errors, fmt.Sprintf("failed to resolve NS %s for zone %s: %v", nsHost, zone, err))
			continue
		}

		for _, addr := range addrs {
			dnsServer := net.JoinHostPort(addr, "53")

			log.Info("Attempting zone transfer",
				svc1log.SafeParam("zone", zone),
				svc1log.SafeParam("nameserver", nsHost),
				svc1log.SafeParam("dnsServer", dnsServer))

			records, success, errs := sendAXFRRequest(dnsServer, zone, timeout, log)
			for _, e := range errs {
				*errors = append(*errors, fmt.Sprintf("%s@%s(%s): %s", zone, nsHost, dnsServer, e))
			}

			if success {
				log.Info("Zone transfer succeeded",
					svc1log.SafeParam("zone", zone),
					svc1log.SafeParam("nameserver", nsHost),
					svc1log.SafeParam("dnsServer", dnsServer),
					svc1log.SafeParam("records", len(records)))

				applications = append(applications, &dnsfern.DnsZoneTransferApplication{
					Nameserver: nsHost,
					DnsServer:  dnsServer,
					DnsRecords: records,
				})
			}
		}
	}

	return &dnsfern.DnsZoneTransferDetails{
		Zone:         zone,
		Applications: applications,
	}
}
