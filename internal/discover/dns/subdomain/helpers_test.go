package subdomain

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDetectWildcardDNSProfileWithResolversReturnsPositiveAfterUnknownResolver(t *testing.T) {
	unknownResolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, nil)
	})
	positiveResolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(req)
		response.RecursionAvailable = true
		if req.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.10"),
			}}
		}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write DNS response: %v", err)
		}
	})

	profile, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{unknownResolver, positiveResolver})
	if err != nil {
		t.Fatalf("expected positive wildcard response to win, got %v", err)
	}
	if !profile.HasAddresses() {
		t.Fatalf("expected wildcard A response, got %+v", profile)
	}
}

func TestDetectWildcardDNSProfileWithResolversTreatsNOERROREmptyAsUnknown(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, nil)
	})

	_, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{resolver})
	if err == nil {
		t.Fatal("expected NOERROR with empty answers to be inconclusive")
	}
	if !strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("expected inconclusive wildcard error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown_responses=3") {
		t.Fatalf("expected unknown response count in error, got %v", err)
	}
}

func TestDetectWildcardDNSProfileWithResolversTreatsSERVFAILAsUnknown(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeServerFailure, nil)
	})

	_, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{resolver})
	if err == nil {
		t.Fatal("expected SERVFAIL to be inconclusive")
	}
	if !strings.Contains(err.Error(), "resolver_failures=3") {
		t.Fatalf("expected resolver failure count in error, got %v", err)
	}
}

func TestDetectWildcardDNSProfileWithResolversAllowsSOABackedNXDOMAINWithSERVFAILResolver(t *testing.T) {
	negativeResolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil, wildcardTestSOA())
	})
	servfailResolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeServerFailure, nil)
	})

	profile, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{negativeResolver, servfailResolver})
	if err != nil {
		t.Fatalf("expected clean NXDOMAIN evidence to override SERVFAIL-only resolver noise, got %v", err)
	}
	if profile.HasAddresses() || profile.HasCNAMETargets() {
		t.Fatalf("expected empty wildcard profile, got %+v", profile)
	}
}

func TestDetectWildcardDNSProfileWithResolversAllowsSingleSOABackedNXDOMAINWithSERVFAILRecords(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype == dns.TypeA {
			writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil, wildcardTestSOA())
			return
		}
		writeWildcardTestResponse(t, w, req, dns.RcodeServerFailure, nil)
	})

	profile, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{resolver})
	if err != nil {
		t.Fatalf("expected one clean NXDOMAIN record response to override SERVFAIL-only record noise, got %v", err)
	}
	if profile.HasAddresses() || profile.HasCNAMETargets() {
		t.Fatalf("expected empty wildcard profile, got %+v", profile)
	}
}

func TestQueryWildcardDNSRecordTreatsREFUSEDAsUnknown(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeRefused, nil)
	})

	status, _, resolverFailure, unprovenNegative, err := queryWildcardDNSRecord(context.Background(), "random.example.test", resolver, dns.TypeA)
	if status != wildcardProbeUnknown {
		t.Fatalf("expected REFUSED to be unknown, got %s", status)
	}
	if !resolverFailure {
		t.Fatal("expected REFUSED to count as a resolver failure")
	}
	if unprovenNegative {
		t.Fatal("expected REFUSED not to count as an unproven negative")
	}
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("expected REFUSED error, got %v", err)
	}
}

func TestQueryWildcardDNSRecordTreatsTruncatedWithoutTCPRetryAsUnknown(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(req)
		response.Truncated = true
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write DNS response: %v", err)
		}
	})

	status, _, resolverFailure, unprovenNegative, err := queryWildcardDNSRecord(context.Background(), "random.example.test", resolver, dns.TypeA)
	if status != wildcardProbeUnknown {
		t.Fatalf("expected unrecoverable truncation to be unknown, got %s", status)
	}
	if !resolverFailure {
		t.Fatal("expected unrecoverable truncation to count as a resolver failure")
	}
	if unprovenNegative {
		t.Fatal("expected unrecoverable truncation not to count as an unproven negative")
	}
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

func TestQueryWildcardDNSRecordTreatsNetworkErrorAsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status, _, resolverFailure, unprovenNegative, err := queryWildcardDNSRecord(ctx, "random.example.test", "127.0.0.1:1", dns.TypeA)
	if status != wildcardProbeUnknown {
		t.Fatalf("expected network error to be unknown, got %s", status)
	}
	if !resolverFailure {
		t.Fatal("expected network error to count as a resolver failure")
	}
	if unprovenNegative {
		t.Fatal("expected network error not to count as an unproven negative")
	}
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestDetectWildcardDNSProfileWithResolversRequiresAllSOABackedNXDOMAINForAbsent(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil, wildcardTestSOA())
	})

	profile, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{resolver})
	if err != nil {
		t.Fatalf("expected clean NXDOMAIN consensus to mean no wildcard, got %v", err)
	}
	if profile.HasAddresses() || profile.HasCNAMETargets() {
		t.Fatalf("expected empty wildcard profile, got %+v", profile)
	}
}

func TestDetectWildcardDNSProfileWithResolversTreatsNXDOMAINWithoutSOAAsUnknown(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil)
	})

	_, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{resolver})
	if err == nil {
		t.Fatal("expected NXDOMAIN without SOA authority proof to be inconclusive")
	}
	if !strings.Contains(err.Error(), "unproven_negative_responses=3") {
		t.Fatalf("expected unproven negative count in error, got %v", err)
	}
}

func TestDetectWildcardDNSProfileWithResolversTreatsMixedRecordResponsesAsUnknown(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype == dns.TypeCNAME {
			writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, nil)
			return
		}
		writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil, wildcardTestSOA())
	})

	_, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{resolver})
	if err == nil {
		t.Fatal("expected mixed NXDOMAIN and NOERROR responses to be inconclusive")
	}
	if !strings.Contains(err.Error(), "negative_responses=2") || !strings.Contains(err.Error(), "unknown_responses=1") {
		t.Fatalf("expected mixed response counts in error, got %v", err)
	}
}

func TestDetectWildcardDNSProfileWithResolversCountsResolverDisagreement(t *testing.T) {
	negativeResolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil, wildcardTestSOA())
	})
	unknownResolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, nil)
	})

	_, err := detectWildcardDNSProfileWithResolvers(context.Background(), "example.test", 1, []string{negativeResolver, unknownResolver})
	if err == nil {
		t.Fatal("expected disagreement to keep wildcard detection inconclusive")
	}
	if !strings.Contains(err.Error(), "resolver_disagreements=1") {
		t.Fatalf("expected resolver disagreement count in error, got %v", err)
	}
}

func TestAggregateWildcardProbeStatusTreatsEmptyStatusSetAsUnknown(t *testing.T) {
	if outcome := aggregateWildcardProbeOutcomes(nil); outcome.status != wildcardProbeUnknown {
		t.Fatalf("expected empty resolver status set to be unknown, got %s", outcome.status)
	}
}

func TestAggregateWildcardProbeOutcomesMarksPartialNegativeAsDegraded(t *testing.T) {
	outcome := aggregateWildcardProbeOutcomes([]wildcardProbeOutcome{
		{status: wildcardProbeNegative},
		{status: wildcardProbeUnknown, unknownDueOnlyToResolverFailure: true},
	})
	if outcome.status != wildcardProbeNegative {
		t.Fatalf("expected clean negative plus resolver failure to remain negative, got %s", outcome.status)
	}
	if !outcome.degradedByResolverFailures {
		t.Fatal("expected partial negative consensus to be marked degraded")
	}
}

func TestGetSubdomainsActiveSkipsBruteForceForCNAMEOnlyWildcard(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		var answers []dns.RR
		if req.Question[0].Qtype == dns.TypeCNAME {
			answers = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "wildcard.example.test.",
			}}
		}
		writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, answers)
	})

	subdomains, err := getSubdomainsActive(context.Background(), "example.test", []string{"www"}, 1, 1, 1, 0, 1, []string{resolver})
	if err != nil {
		t.Fatalf("expected CNAME-only wildcard to stop active discovery cleanly, got %v", err)
	}
	if len(subdomains) != 0 {
		t.Fatalf("expected no brute-force results for CNAME-only wildcard, got %v", subdomains)
	}
}

func TestGetSubdomainsActiveReportsRecursiveWildcardUncertainty(t *testing.T) {
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		name := req.Question[0].Name
		switch {
		case name == "www.example.test." && req.Question[0].Qtype == dns.TypeA:
			writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.20"),
			}})
		case strings.HasSuffix(name, ".www.example.test."):
			writeWildcardTestResponse(t, w, req, dns.RcodeSuccess, nil)
		default:
			writeWildcardTestResponse(t, w, req, dns.RcodeNameError, nil, wildcardTestSOA())
		}
	})

	subdomains, err := getSubdomainsActive(context.Background(), "example.test", []string{"www"}, 1, 2, 1, 0, 1, []string{resolver})
	if err == nil {
		t.Fatal("expected recursive wildcard uncertainty to be reported")
	}
	if !strings.Contains(err.Error(), "skipped 1 recursive subdomain branches") {
		t.Fatalf("expected recursive branch failure count, got %v", err)
	}
	if len(subdomains) != 1 || subdomains[0] != "www.example.test" {
		t.Fatalf("expected already discovered base subdomain to be retained, got %v", subdomains)
	}
}

func startWildcardTestDNSServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for test DNS server: %v", err)
	}

	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Errorf("serve test DNS: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return packetConn.LocalAddr().String()
}

func writeWildcardTestResponse(t *testing.T, w dns.ResponseWriter, req *dns.Msg, rcode int, answers []dns.RR, authority ...dns.RR) {
	t.Helper()

	response := new(dns.Msg)
	response.SetReply(req)
	response.RecursionAvailable = true
	response.Rcode = rcode
	response.Answer = answers
	response.Ns = authority
	if err := w.WriteMsg(response); err != nil {
		t.Errorf("write DNS response: %v", err)
	}
}

func wildcardTestSOA() dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns1.example.test.",
		Mbox:    "hostmaster.example.test.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}
