package zonetransfer

import (
	"fmt"
	"strings"
	"time"

	dnsfern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	"github.com/miekg/dns"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// sendAXFRRequest attempts a DNS zone transfer (AXFR) from the given nameserver for the specified domain.
// Returns the records, whether the transfer was successful, and any errors encountered.
func sendAXFRRequest(ns, domain string, timeout int, log svc1log.Logger) ([]*dnsfern.DnsZoneTransferRecord, bool, []string) {
	errors := []string{}
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

	var records []*dnsfern.DnsZoneTransferRecord
	axfrSuccessful := false

	// Read all responses from the transfer
	for response := range conn {
		if response.Error != nil {
			errors = append(errors, fmt.Sprintf("error during AXFR transfer: %v", response.Error))
			return nil, false, errors
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
func convertRecord(rr dns.RR) *dnsfern.DnsZoneTransferRecord {
	switch r := rr.(type) {
	case *dns.A:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeA, Value: r.A.String()}
	case *dns.AAAA:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeAaaa, Value: r.AAAA.String()}
	case *dns.CNAME:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeCname, Value: r.Target}
	case *dns.MX:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeMx, Value: fmt.Sprintf("%d %s", r.Preference, r.Mx)}
	case *dns.NS:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeNs, Value: r.Ns}
	case *dns.SOA:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeSoa, Value: fmt.Sprintf("%s %s %d", r.Ns, r.Mbox, r.Serial)}
	case *dns.TXT:
		return &dnsfern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsfern.DnsRecordTypeTxt, Value: fmt.Sprintf("%s", r.Txt)}
	default:
		return nil
	}
}
