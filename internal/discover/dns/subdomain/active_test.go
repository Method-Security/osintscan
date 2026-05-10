package subdomain

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestGetSubdomainsActiveSkipsWildcardCNAMEMatchAfterAResolution(t *testing.T) {
	const zone = "wild.test."
	const wildcardTarget = "target.wild.test."
	const explicitName = "real.wild.test."
	const explicitTarget = "real-target.wild.test."

	allowWildcardTargetResolution := atomic.Bool{}
	resolver := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(resp)
			return
		}

		q := r.Question[0]
		name := strings.ToLower(q.Name)
		switch {
		case name == wildcardTarget:
			if !allowWildcardTargetResolution.Load() {
				resp.Rcode = dns.RcodeNameError
				break
			}
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.10"),
				})
			}
		case name == explicitTarget:
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.20"),
				})
			}
		case name == explicitName:
			resp.Answer = append(resp.Answer, cnameAnswer(q.Name, explicitTarget))
		case strings.HasSuffix(name, zone) && name != zone:
			if q.Qtype == dns.TypeCNAME {
				allowWildcardTargetResolution.Store(true)
			}
			resp.Answer = append(resp.Answer, cnameAnswer(q.Name, wildcardTarget))
		default:
			resp.Rcode = dns.RcodeNameError
		}

		_ = w.WriteMsg(resp)
	}))

	subdomains, err := getSubdomainsActive(context.Background(), "wild.test", []string{"www", "real"}, 1, 1, 0, 0, 1, []string{resolver})
	if err != nil {
		t.Fatalf("getSubdomainsActive returned error: %v", err)
	}

	expected := []string{"real.wild.test"}
	if !reflect.DeepEqual(subdomains, expected) {
		t.Fatalf("subdomains = %v, want %v", subdomains, expected)
	}
}

func startTestDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	server := &dns.Server{
		PacketConn: packetConn,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return packetConn.LocalAddr().String()
}

func cnameAnswer(name string, target string) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: target,
	}
}
