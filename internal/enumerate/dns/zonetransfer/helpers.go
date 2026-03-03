package zonetransfer

import (
	"fmt"
	"net"
	"strings"
	"time"

	common "github.com/Method-Security/osintscan/generated/go/common"
	"github.com/miekg/dns"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// sendAXFRRequest attempts a DNS zone transfer (AXFR) against the given nameserver (ip:port or ip)
// for the specified zone. Returns the records, whether the transfer was successful, and any errors.
func sendAXFRRequest(ns, zone string, timeout int, log svc1log.Logger) ([]*common.DnsRecord, bool, []string) {
	errors := []string{}

	// If ns has no port, default to 53
	addr := ns
	if _, _, err := net.SplitHostPort(ns); err != nil {
		addr = fmt.Sprintf("%s:53", ns)
	}

	log.Info("Attempting AXFR transfer", svc1log.SafeParam("addr", addr), svc1log.SafeParam("zone", zone))

	fullZone := zone
	if !strings.HasSuffix(fullZone, ".") {
		fullZone += "."
	}

	msg := new(dns.Msg)
	msg.SetAxfr(fullZone)

	transfer := new(dns.Transfer)
	transfer.DialTimeout = time.Duration(timeout) * time.Second

	conn, err := transfer.In(msg, addr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to initiate AXFR transfer: %v", err))
		return nil, false, errors
	}

	var records []*common.DnsRecord
	axfrSuccessful := false

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
		log.Info("Zone transfer successful", svc1log.SafeParam("addr", addr), svc1log.SafeParam("records", len(records)))
		return records, true, errors
	}

	errors = append(errors, "zone transfer failed or no records received")
	return records, false, errors
}

// convertRecord converts a DNS resource record to a DnsRecord, if supported.
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
