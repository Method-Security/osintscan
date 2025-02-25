package dns

import (
	"fmt"
	"strings"
	"time"

	osintscan "github.com/Method-Security/osintscan/generated/go"
	"github.com/miekg/dns"
)

func sendAXFRRequest(ns, domain string, timeout int) ([]*osintscan.DnsZoneTransferRecord, bool, []string) {
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

	var records []*osintscan.DnsZoneTransferRecord
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

func convertRecord(rr dns.RR) *osintscan.DnsZoneTransferRecord {
	switch r := rr.(type) {
	case *dns.A:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumA, Value: r.A.String()}
	case *dns.AAAA:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumAaaa, Value: r.AAAA.String()}
	case *dns.CNAME:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumCname, Value: r.Target}
	case *dns.MX:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumMx, Value: fmt.Sprintf("%d %s", r.Preference, r.Mx)}
	case *dns.NS:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumNs, Value: r.Ns}
	case *dns.SOA:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumSoa, Value: fmt.Sprintf("%s %s %d", r.Ns, r.Mbox, r.Serial)}
	case *dns.TXT:
		return &osintscan.DnsZoneTransferRecord{Name: r.Hdr.Name, Type: osintscan.DnsRecordEnumTxt, Value: fmt.Sprintf("%s", r.Txt)}
	default:
		return nil
	}
}
