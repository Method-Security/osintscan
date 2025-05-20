package zonetransfer

import (
	"fmt"
	"strings"
	"time"

	dnsFern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	"github.com/miekg/dns"
)

func sendAXFRRequest(ns, domain string, timeout int) ([]*dnsFern.DnsZoneTransferRecord, bool, []string) {
	errors := []string{}
	addr := fmt.Sprintf("%s:53", ns)
	fmt.Printf("[Debug] Attempting AXFR transfer from %s\n", addr)

	fullDomain := domain
	if !strings.HasSuffix(fullDomain, ".") {
		fullDomain += "."
	}

	msg := new(dns.Msg)
	msg.SetAxfr(fullDomain)

	transfer := new(dns.Transfer)
	transfer.DialTimeout = time.Duration(timeout) * time.Second

	conn, err := transfer.In(msg, addr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to initiate AXFR transfer: %v", err))
		return nil, false, errors
	}

	var records []*dnsFern.DnsZoneTransferRecord
	axfrSuccessful := false

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
		fmt.Printf("[Debug] Zone transfer successful from %s with %d records\n", ns, len(records))
		return records, true, errors
	}

	errors = append(errors, "zone transfer failed or no records received")
	return records, false, errors
}

func convertRecord(rr dns.RR) *dnsFern.DnsZoneTransferRecord {
	switch r := rr.(type) {
	case *dns.A:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeA, Value: r.A.String()}
	case *dns.AAAA:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeAaaa, Value: r.AAAA.String()}
	case *dns.CNAME:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeCname, Value: r.Target}
	case *dns.MX:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeMx, Value: fmt.Sprintf("%d %s", r.Preference, r.Mx)}
	case *dns.NS:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeNs, Value: r.Ns}
	case *dns.SOA:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeSoa, Value: fmt.Sprintf("%s %s %d", r.Ns, r.Mbox, r.Serial)}
	case *dns.TXT:
		return &dnsFern.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: dnsFern.DnsRecordTypeTxt, Value: fmt.Sprintf("%s", r.Txt)}
	default:
		return nil
	}
}
