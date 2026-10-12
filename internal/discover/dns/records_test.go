package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Method-Security/osintscan/generated/go/common"
	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

func TestNormalizeDnsxResolversTrimsAndNormalizesAddresses(t *testing.T) {
	input := []string{" 8.8.8.8 ", " tcp:1.1.1.1 ", "udp:9.9.9.9:5353 "}
	expected := []string{"udp:8.8.8.8:53", "tcp:1.1.1.1:53", "udp:9.9.9.9:5353"}

	actual := normalizeDnsxResolvers(input, false)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestNormalizeDnsxResolversForcesTCP(t *testing.T) {
	input := []string{"udp:8.8.8.8", "tcp:1.1.1.1", "9.9.9.9"}
	expected := []string{"tcp:8.8.8.8:53", "tcp:1.1.1.1:53", "tcp:9.9.9.9:53"}

	actual := normalizeDnsxResolvers(input, true)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestGetDNSRecordsPreservesTypedAnswersGolden(t *testing.T) {
	resolver := startAuthoritativeDNSFixture(t)
	records, err := getDNSRecords(
		context.Background(),
		"example.test",
		[]uint16{dns.TypeA, dns.TypeMX, dns.TypeSRV, dns.TypeCAA, dns.TypeTXT},
		[]string{"udp:" + resolver},
		5,
	)
	if err != nil {
		t.Fatalf("query local DNS fixture: %v", err)
	}

	actual, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatalf("marshal DNS records: %v", err)
	}
	const expected = `[
  {
    "name": "example.test",
    "ttl": 60,
    "type": "A",
    "value": "192.0.2.10"
  },
  {
    "name": "example.test",
    "ttl": 120,
    "type": "A",
    "value": "192.0.2.11"
  },
  {
    "name": "example.test",
    "ttl": 300,
    "type": "MX",
    "value": "10 mail.example.test."
  },
  {
    "name": "_https._tcp.example.test",
    "ttl": 45,
    "type": "SRV",
    "value": "5 20 443 service.example.test."
  },
  {
    "name": "example.test",
    "ttl": 600,
    "type": "CAA",
    "value": "0 issue \"letsencrypt.org\""
  },
  {
    "name": "example.test",
    "ttl": 90,
    "type": "TXT",
    "value": "\"segment-one\" \"segment-two\""
  }
]`
	if string(actual) != expected {
		t.Fatalf("DNS record golden mismatch\nexpected:\n%s\nactual:\n%s", expected, actual)
	}
}

func TestDiscoverDomainDNSRecordsPreservesFullResultGolden(t *testing.T) {
	resolver := startAuthoritativeDNSFixture(t)
	useTCP := false
	timeout := 5
	report := DiscoverDomainDNSRecords(context.Background(), dnsfern.DiscoverDnsRecordsConfig{
		Domain:       "example.test",
		RecordTypes:  []string{"A", "MX", "SRV", "CAA", "TXT"},
		DnsResolvers: []string{resolver},
		UseTcp:       &useTCP,
		Timeout:      &timeout,
	})
	if len(report.Errors) != 0 {
		t.Fatalf("expected no report errors, got %v", report.Errors)
	}
	if report.Config == nil || report.Config.Domain != "example.test" {
		t.Fatalf("expected the input config to be retained, got %#v", report.Config)
	}

	actual, err := json.MarshalIndent(report.Result, "", "  ")
	if err != nil {
		t.Fatalf("marshal full DNS result: %v", err)
	}
	const expected = `{
  "dnsRecords": [
    {
      "name": "example.test",
      "ttl": 60,
      "type": "A",
      "value": "192.0.2.10"
    },
    {
      "name": "example.test",
      "ttl": 120,
      "type": "A",
      "value": "192.0.2.11"
    },
    {
      "name": "example.test",
      "ttl": 600,
      "type": "CAA",
      "value": "0 issue \"letsencrypt.org\""
    },
    {
      "name": "example.test",
      "ttl": 300,
      "type": "MX",
      "value": "10 mail.example.test."
    },
    {
      "name": "_https._tcp.example.test",
      "ttl": 45,
      "type": "SRV",
      "value": "5 20 443 service.example.test."
    },
    {
      "name": "example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    }
  ],
  "dmarcRecords": [
    {
      "name": "_dmarc.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    }
  ],
  "dkimRecords": [
    {
      "name": "default._domainkey.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    },
    {
      "name": "selector1._domainkey.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    },
    {
      "name": "selector2._domainkey.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    },
    {
      "name": "google._domainkey.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    },
    {
      "name": "amazonses._domainkey.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    },
    {
      "name": "microsoft._domainkey.example.test",
      "ttl": 90,
      "type": "TXT",
      "value": "\"segment-one\" \"segment-two\""
    }
  ]
}`
	if string(actual) != expected {
		t.Fatalf("full DNS result golden mismatch\nexpected:\n%s\nactual:\n%s", expected, actual)
	}
}

func TestGetDNSRecordsDoesNotRetryValidEmptyAnswers(t *testing.T) {
	var queryCount atomic.Int32
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		queryCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		_ = writer.WriteMsg(response)
	}))

	records, err := getDNSRecords(
		context.Background(),
		"empty.example.test",
		[]uint16{dns.TypeA, dns.TypeMX},
		[]string{"udp:" + resolver},
		5,
	)
	if err != nil {
		t.Fatalf("query valid empty answers: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records, got %v", records)
	}
	if queryCount.Load() != 2 {
		t.Fatalf("expected one query per record type, got %d", queryCount.Load())
	}
}

func TestGetDNSRecordsRetainsRetriesForResolverFailures(t *testing.T) {
	var queryCount atomic.Int32
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		queryCount.Add(1)
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = writer.WriteMsg(response)
	}))

	records, err := getDNSRecords(
		context.Background(),
		"failure.example.test",
		[]uint16{dns.TypeA},
		[]string{"udp:" + resolver},
		5,
	)
	if err != nil {
		t.Fatalf("query resolver failures: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records, got %v", records)
	}
	if queryCount.Load() != int32(dnsx.DefaultOptions.MaxRetries) {
		t.Fatalf("expected %d resolver attempts, got %d", dnsx.DefaultOptions.MaxRetries, queryCount.Load())
	}
}

func TestGetDNSRecordsKeepsRecordsAndContinuesAfterTypeTimeout(t *testing.T) {
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		question := request.Question[0]
		if question.Qtype == dns.TypeMX {
			return
		}
		response := new(dns.Msg)
		response.SetReply(request)
		switch question.Qtype {
		case dns.TypeA:
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.25"),
			}}
		case dns.TypeTXT:
			response.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 90},
				Txt: []string{"after-timeout"},
			}}
		}
		_ = writer.WriteMsg(response)
	}))

	records, err := getDNSRecords(
		context.Background(),
		"partial.example.test",
		[]uint16{dns.TypeA, dns.TypeMX, dns.TypeTXT},
		[]string{"udp:" + resolver},
		1,
	)
	if err == nil || !strings.Contains(err.Error(), "MX query failed") || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected an MX timeout, got %v", err)
	}
	if len(records) != 2 || records[0].Value != "192.0.2.25" || records[1].Value != `"after-timeout"` {
		t.Fatalf("expected records before and after the MX timeout, got %v", records)
	}
}

func TestCollectDNSRecordsStopsTimedOutClientBeforeNextType(t *testing.T) {
	var mxQueries atomic.Int32
	var txtQueries atomic.Int32
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		question := request.Question[0]
		response := new(dns.Msg)
		response.SetReply(request)
		switch question.Qtype {
		case dns.TypeMX:
			mxQueries.Add(1)
			return
		case dns.TypeTXT:
			txtQueries.Add(1)
			response.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 90},
				Txt: []string{"after-timeout"},
			}}
			_ = writer.WriteMsg(response)
		}
	}))

	options := dnsx.DefaultOptions
	options.BaseResolvers = []string{"udp:" + resolver}
	options.MaxRetries = 1
	options.Timeout = 80 * time.Millisecond
	client, err := dnsx.New(options)
	if err != nil {
		t.Fatalf("create DNS client: %v", err)
	}

	records, err := collectDNSRecords(
		context.Background(),
		client,
		"isolated.example.test",
		[]uint16{dns.TypeMX, dns.TypeTXT},
		10*time.Millisecond,
		2,
	)
	if err == nil || !strings.Contains(err.Error(), "MX query failed") {
		t.Fatalf("expected an MX timeout, got %v", err)
	}
	if len(records) != 1 || records[0].Type != "TXT" || records[0].Value != `"after-timeout"` {
		t.Fatalf("expected the TXT record after the MX timeout, got %v", records)
	}

	// Let the first client's blocked resolver call finish. Before client
	// isolation, its next retry observed the shared TXT QuestionTypes mutation
	// and issued a second TXT query after this function had reported the MX
	// timeout.
	time.Sleep(120 * time.Millisecond)
	if mxQueries.Load() != 1 || txtQueries.Load() != 1 {
		t.Fatalf("expected one isolated query per type, got MX=%d TXT=%d", mxQueries.Load(), txtQueries.Load())
	}
}

func startAuthoritativeDNSFixture(t *testing.T) string {
	t.Helper()
	return startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		if len(request.Question) == 0 {
			_ = writer.WriteMsg(response)
			return
		}
		var recordStrings []string
		switch request.Question[0].Qtype {
		case dns.TypeA:
			recordStrings = []string{
				"example.test. 60 IN A 192.0.2.10",
				"example.test. 120 IN A 192.0.2.11",
			}
		case dns.TypeMX:
			recordStrings = []string{"example.test. 300 IN MX 10 mail.example.test."}
		case dns.TypeSRV:
			recordStrings = []string{"_https._tcp.example.test. 45 IN SRV 5 20 443 service.example.test."}
		case dns.TypeCAA:
			recordStrings = []string{`example.test. 600 IN CAA 0 issue "letsencrypt.org"`}
		case dns.TypeTXT:
			recordStrings = []string{fmt.Sprintf(`%s 90 IN TXT "segment-one" "segment-two"`, request.Question[0].Name)}
		}
		for _, value := range recordStrings {
			record, parseErr := dns.NewRR(value)
			if parseErr != nil {
				t.Errorf("parse DNS fixture record %q: %v", value, parseErr)
				continue
			}
			response.Answer = append(response.Answer, record)
		}
		_ = writer.WriteMsg(response)
	}))
}

func startDNSTestServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DNS fixture: %v", err)
	}

	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		if serveErr := <-serveErrors; serveErr != nil && !strings.Contains(serveErr.Error(), "closed") {
			t.Errorf("DNS fixture server: %v", serveErr)
		}
	})
	return packetConn.LocalAddr().String()
}

// TestMiekgDNSQueryTypeConstants guards the miekg/dns type constants that
// DiscoverDomainDNSRecords queries with. These are wire-format values fixed by
// IANA, so a dependency bump that changes one would silently send the wrong
// question type rather than fail to compile.
func TestMiekgDNSQueryTypeConstants(t *testing.T) {
	expected := map[string]uint16{
		"A":     1,
		"NS":    2,
		"CNAME": 5,
		"SOA":   6,
		"PTR":   12,
		"MX":    15,
		"TXT":   16,
		"AAAA":  28,
		"SRV":   33,
		"CAA":   257,
	}
	actual := map[string]uint16{
		"A":     dns.TypeA,
		"NS":    dns.TypeNS,
		"CNAME": dns.TypeCNAME,
		"SOA":   dns.TypeSOA,
		"PTR":   dns.TypePTR,
		"MX":    dns.TypeMX,
		"TXT":   dns.TypeTXT,
		"AAAA":  dns.TypeAAAA,
		"SRV":   dns.TypeSRV,
		"CAA":   dns.TypeCAA,
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestSplitDnsxResolverProtoSeparatesKnownPrefixes(t *testing.T) {
	for _, tc := range []struct {
		input     string
		wantProto string
		wantHost  string
	}{
		{"tcp:1.1.1.1", "tcp:", "1.1.1.1"},
		{"udp:8.8.8.8:5353", "udp:", "8.8.8.8:5353"},
		{"9.9.9.9", "", "9.9.9.9"},
		{"9.9.9.9:53", "", "9.9.9.9:53"},
	} {
		proto, host := splitDnsxResolverProto(tc.input)
		if proto != tc.wantProto || host != tc.wantHost {
			t.Fatalf("splitDnsxResolverProto(%q) = (%q, %q), want (%q, %q)",
				tc.input, proto, host, tc.wantProto, tc.wantHost)
		}
	}
}

func TestFilterDNSRecordsByType(t *testing.T) {
	records := []*common.DnsRecord{
		{Name: "example.com", Type: common.DnsRecordTypeA, Value: "1.2.3.4"},
		{Name: "example.com", Type: common.DnsRecordTypeMx, Value: "mail.example.com"},
		{Name: "example.com", Type: common.DnsRecordTypeTxt, Value: "v=spf1 -all"},
	}

	values := func(in []*common.DnsRecord) []string {
		out := []string{}
		for _, record := range in {
			out = append(out, string(record.Type))
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		types []common.DnsRecordType
		want  []string
	}{
		{"no types returns everything", nil, []string{"A", "MX", "TXT"}},
		{"ALL returns everything", []common.DnsRecordType{common.DnsRecordTypeAll}, []string{"A", "MX", "TXT"}},
		{"ALL alongside a narrower type still returns everything",
			[]common.DnsRecordType{common.DnsRecordTypeMx, common.DnsRecordTypeAll}, []string{"A", "MX", "TXT"}},
		{"single type filters", []common.DnsRecordType{common.DnsRecordTypeMx}, []string{"MX"}},
		{"multiple types filter", []common.DnsRecordType{common.DnsRecordTypeA, common.DnsRecordTypeTxt}, []string{"A", "TXT"}},
		{"unmatched type yields nothing", []common.DnsRecordType{common.DnsRecordTypeSrv}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := values(filterDNSRecordsByType(records, tc.types))
			if !reflect.DeepEqual(actual, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, actual)
			}
		})
	}
}
