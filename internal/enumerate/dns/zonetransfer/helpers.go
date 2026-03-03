package zonetransfer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	common "github.com/Method-Security/osintscan/generated/go/common"
	"github.com/miekg/dns"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// sendAXFRRequest attempts a DNS zone transfer (AXFR) from the given nameserver for the specified domain.
// Returns the records, whether the transfer was successful, and any errors encountered.
func sendAXFRRequest(ns, domain string, timeout int, resolver *net.Resolver, log svc1log.Logger) ([]*common.DnsRecord, bool, []string) {
	errors := []string{}

	// Check if ns is already an IP
	if net.ParseIP(ns) == nil {
		// It's a hostname, resolve it
		addrs, err := resolver.LookupHost(context.Background(), ns)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to resolve nameserver %s: %v", ns, err))
			return nil, false, errors
		}
		if len(addrs) == 0 {
			errors = append(errors, fmt.Sprintf("no addresses found for nameserver %s", ns))
			return nil, false, errors
		}
		ns = addrs[0] // Use first resolved IP
	}

	addr := fmt.Sprintf("%s:53", ns)
	log.Info("[Debug] Attempting AXFR transfer from", svc1log.SafeParam("addr", addr))

	fullDomain := domain
	if !strings.HasSuffix(fullDomain, ".") {
		fullDomain += "."
	}

	msg := new(dns.Msg)
	msg.SetAxfr(fullDomain)

	transfer := new(dns.Transfer)
	transfer.DialTimeout = time.Duration(timeout) * time.Second

	// Initiate the AXFR transfer
	conn, err := transfer.In(msg, addr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to initiate AXFR transfer: %v", err))
		return nil, false, errors
	}

	var records []*common.DnsRecord
	axfrSuccessful := false

	// Read all responses from the transfer
	for response := range conn {
		if response.Error != nil {
			errors = append(errors, fmt.Sprintf("error during AXFR transfer: %v", response.Error))
			return records, len(records) > 0, errors
		}
		for _, rr := range response.RR {
			record := convertRecord(rr)
			if record != nil {
				records = append(records, record)
				axfrSuccessful = true
			}
		}
	}

	if axfrSuccessful {
		log.Info("[Debug] Zone transfer successful from", svc1log.SafeParam("ns", ns), svc1log.SafeParam("records", len(records)))
		return records, true, errors
	}

	errors = append(errors, "zone transfer failed or no records received")
	return records, false, errors
}

// convertRecord converts a DNS resource record to a DnsZoneTransferRecord, if supported.
func convertRecord(rr dns.RR) *common.DnsRecord {
	switch r := rr.(type) {
	case *dns.A:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeA, Value: r.A.String()}
	case *dns.AAAA:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeAaaa, Value: r.AAAA.String()}
	case *dns.CNAME:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeCname, Value: r.Target}
	case *dns.MX:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeMx, Value: fmt.Sprintf("%d %s", r.Preference, r.Mx)}
	case *dns.NS:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeNs, Value: r.Ns}
	case *dns.SOA:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeSoa, Value: fmt.Sprintf("%s %s %d", r.Ns, r.Mbox, r.Serial)}
	case *dns.TXT:
		return &common.DnsRecord{Name: r.Hdr.Name, Ttl: int(r.Hdr.Ttl), Type: common.DnsRecordTypeTxt, Value: fmt.Sprintf("%s", r.Txt)}
	default:
		return nil
	}
}
