// internal/subnet/scanner.go
package subnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	subnetgenerated "github.com/Method-Security/osintscan/generated/go/subnet"

	lru "github.com/hashicorp/golang-lru/v2/expirable" // Reverted to expirable path
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
	"github.com/oschwald/geoip2-golang"
	libs "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/utils/env"
	sf "golang.org/x/sync/singleflight"
)

/* ─────────────────────────── PUBLIC CONFIG ──────────────────────────── */

// Default cache sizes
const (
	DefaultRDAPCacheSize = 2048
	DefaultPTRCacheSize  = 8192
	DefaultCacheTTL      = 1 * time.Hour // Default TTL for cache entries
)

type ScanConfig struct {
	Extended      bool
	Timeout       time.Duration
	Workers       int
	Resolver      string
	ASNAPIKey     string        // key for ProjectDiscovery (optional)
	MaxMindDB     string        // path to GeoLite2-ASN.mmdb (optional)
	PoliteWait    time.Duration // sleep between network ASN look-ups
	PTRTimeout    time.Duration // timeout for PTR lookups
	RDAPCacheSize int           // default 2048
	PTRCacheSize  int           // default 8192
	CacheTTL      time.Duration // Time-to-live for cache entries
}

// scannerContext holds shared resources for a single scan operation.
type scannerContext struct {
	cfg       ScanConfig
	asnLookup asnProvider
	ptrCache  *lru.LRU[netip.Addr, []string]                     // Use expirable LRU type
	rdapCache *lru.LRU[netip.Prefix, *subnetgenerated.WhoisData] // Use expirable LRU type
	ptrGroup  sf.Group                                           // singleflight for PTR lookups
	rdapGroup sf.Group                                           // singleflight for RDAP/WHOIS lookups
	// cacheTTL and ptrTimeout removed as TTL is in LRU and timeout in cfg
}

/* ──────────────────────── SCAN ENTRY POINT ──────────────────────────── */

func Scan(ctx context.Context, cidr string, cfg ScanConfig) (<-chan *subnetgenerated.IpReport, error) {
	// ─ CIDR sanity
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	if ip.To4() == nil {
		return nil, errors.New("IPv6 not supported")
	}
	if ones, _ := ipNet.Mask.Size(); ones < 16 {
		return nil, fmt.Errorf("/%d is larger than the permitted /16", ones)
	}
	prefix := netip.MustParsePrefix(cidr)

	// ─ Apply defaults
	if cfg.RDAPCacheSize <= 0 {
		cfg.RDAPCacheSize = DefaultRDAPCacheSize
	}
	if cfg.PTRCacheSize <= 0 {
		cfg.PTRCacheSize = DefaultPTRCacheSize
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultCacheTTL
	}
	ptrTimeout := cfg.PTRTimeout
	if ptrTimeout <= 0 {
		ptrTimeout = 500 * time.Millisecond // Default if not set
	}
	// Persist the effective timeout back into the config
	cfg.PTRTimeout = ptrTimeout

	// ─ ASN providers ------------------------------------------------------
	pdCli := initProjectDiscovery(cfg.ASNAPIKey)
	if pdCli != nil {
		// Perform a single test query to validate the API key early.
		// We only care about errors indicating an invalid key.
		_, testErr := pdCli.GetData("1.1.1.1") // Use a known public IP for the test
		if testErr != nil {
			// Check the error string for the known invalid key message from the library.
			// This is brittle, but necessary if the library doesn't return specific error types.
			if strings.Contains(testErr.Error(), "missing or invalid api key") {
				fmt.Fprintln(os.Stderr, "Warning: ProjectDiscovery API key is invalid or missing. Skipping ProjectDiscovery provider.")
				pdCli = nil // Disable the PD provider for this scan
			}
			// Note: We could handle other permanent errors here if needed.
		}
	}

	mmdb, _ := openMaxMind(cfg.MaxMindDB)

	lookupASN := chain(
		providerMM(mmdb),
		providerPD(pdCli, cfg.PoliteWait), // if you have the api key you get access to more data
		providerCymru(cfg.PoliteWait),     // final fallback
	)

	// ─ Caches and singleflight groups -------------------------------------
	// Use expirable LRU with correct constructor (size, onEvict, ttl)
	rdapCache := lru.NewLRU[netip.Prefix, *subnetgenerated.WhoisData](cfg.RDAPCacheSize, nil, cacheTTL)
	ptrCache := lru.NewLRU[netip.Addr, []string](cfg.PTRCacheSize, nil, cacheTTL)

	// ─ Scanner context ----------------------------------------------------
	sCtx := &scannerContext{
		cfg:       cfg, // Pass the potentially modified cfg
		asnLookup: lookupASN,
		ptrCache:  ptrCache,
		rdapCache: rdapCache,
		// sf.Group fields are zero-value ready
	}

	// ─ producer & worker channels ----------------------------------------
	buf := cfg.Workers * 128
	if buf > 4096 {
		buf = 4096
	}
	ipCh := make(chan netip.Addr, buf)
	out := make(chan *subnetgenerated.IpReport)

	go enumerate(ctx, prefix, ipCh)
	var wg sync.WaitGroup
	wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go func() {
			defer wg.Done()
			for ip := range ipCh {
				// Pass scanner context to scanOne
				out <- scanOne(ctx, ip, sCtx)
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	return out, nil
}

/* ──────────────────── ENUMERATOR ─────────────────────────────────────── */

func enumerate(ctx context.Context, pfx netip.Prefix, out chan<- netip.Addr) {
	defer close(out)
	for ip := pfx.Addr(); pfx.Contains(ip); ip = ip.Next() {
		select {
		case <-ctx.Done():
			return
		case out <- ip:
		}
	}
}

/* ──────────────────── PER-IP SCAN ─────────────────────────────────────── */

func scanOne(parent context.Context, ip netip.Addr, sCtx *scannerContext) *subnetgenerated.IpReport {
	rep := &subnetgenerated.IpReport{Ip: ip.String(), Errors: []string{}}

	ctx, cancel := context.WithTimeout(parent, sCtx.cfg.Timeout)
	defer cancel()

	// PTR - Use cached lookup
	if names, err := lookupPTRCached(ctx, ip, sCtx); err != nil {
		rep.Errors = append(rep.Errors, "PTR: "+err.Error())
	} else {
		rep.PtrRecords = names
	}

	// ASN - Use the provider from scannerContext
	if asn, err := sCtx.asnLookup(ctx, ip); err == nil && asn != nil {
		rep.Asn = asn
	} else if err != nil {
		rep.Errors = append(rep.Errors, "ASN: "+err.Error())
	}

	// RDAP / WHOIS - Use cached lookup
	if whois, err := lookupOwnershipCached(ctx, ip, sCtx); err != nil {
		rep.Errors = append(rep.Errors, "RDAP/WHOIS: "+err.Error())
	} else if whois != nil {
		rep.Ownership = whois
	}
	return rep
}

/* ──────────────────── DNS PTR ─────────────────────────────────────────── */

// lookupPTRCached wraps the actual PTR lookup with caching and singleflight.
func lookupPTRCached(ctx context.Context, ip netip.Addr, sCtx *scannerContext) ([]string, error) {
	// Check cache first
	if names, ok := sCtx.ptrCache.Get(ip); ok {
		return names, nil
	}

	// Use singleflight with string keys
	v, err, _ := sCtx.ptrGroup.Do(ip.String(), func() (any, error) { // Use ip.String() as key
		// Apply the effective timeout for the actual network call
		lookupCtx, cancel := context.WithTimeout(ctx, sCtx.cfg.PTRTimeout) // Use timeout from cfg
		defer cancel()

		names, fetchErr := doPTRLookup(lookupCtx, ip, sCtx.cfg.Resolver)
		if fetchErr == nil {
			// Add to cache on success (including empty slice for NXDOMAIN).
			sCtx.ptrCache.Add(ip, names)
		}
		// Return the result and the fetch error.
		return names, fetchErr
	})

	// Handle error returned by singleflight.Do
	if err != nil {
		return nil, fmt.Errorf("ptr lookup failed for %s: %w", ip, err)
	}
	// Type assertion is safe here because Do func returns ([]string, error).
	return v.([]string), nil
}

// doPTRLookup performs the actual DNS PTR lookup.
// (Renamed from original lookupPTR)
func doPTRLookup(ctx context.Context, ip netip.Addr, resolver string) ([]string, error) {
	r := net.DefaultResolver
	if resolver != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				// Use the timeout from the already time-limited context passed in
				return (&net.Dialer{}).DialContext(ctx, "udp", resolver)
			},
		}
	}
	names, err := r.LookupAddr(ctx, ip.String())
	if err != nil {
		// Handle NXDOMAIN specifically - return empty slice, no error
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return []string{}, nil // Cacheable result for "not found"
		}
		return nil, err // Return other errors
	}
	return names, nil
}

/* ──────────────────── ASN PROVIDERS ───────────────────────────────────── */

type asnProvider func(ctx context.Context, ip netip.Addr) (*subnetgenerated.AsnInfo, error)

func chain(providers ...asnProvider) asnProvider {
	return func(ctx context.Context, ip netip.Addr) (*subnetgenerated.AsnInfo, error) {
		for _, p := range providers {
			if info, err := p(ctx, ip); err == nil && info != nil {
				return info, nil
			}
		}
		return nil, errors.New("no ASN data")
	}
}

/* ProjectDiscovery ------------------------------------------------------- */

func initProjectDiscovery(key string) *libs.Client {
	if key == "" {
		key = env.GetEnvOrDefault("PDCP_API_KEY", "")
	}
	if key == "" {
		return nil
	}
	libs.PDCPApiKey = key
	cli, _ := libs.NewClient()
	return cli
}

func providerPD(cli *libs.Client, wait time.Duration) asnProvider {
	return func(ctx context.Context, ip netip.Addr) (*subnetgenerated.AsnInfo, error) {
		if cli == nil {
			return nil, nil
		}
		data, err := cli.GetData(ip.String())
		if err != nil || len(data) == 0 {
			return nil, err
		}
		d := data[0]
		// Sleep *before* returning, only on success
		time.Sleep(wait)
		return &subnetgenerated.AsnInfo{
			Number:  d.ASN,
			Org:     strPtr(d.Org),
			Country: strPtr(d.Country),
			Source:  "projectdiscovery",
		}, nil
	}
}

/* MaxMind GeoLite2-ASN --------------------------------------------------- */

func openMaxMind(path string) (*geoip2.Reader, error) {
	if path == "" {
		return nil, nil
	}
	return geoip2.Open(path)
}

func providerMM(db *geoip2.Reader) asnProvider {
	return func(_ context.Context, ip netip.Addr) (*subnetgenerated.AsnInfo, error) {
		if db == nil {
			return nil, nil
		}
		// Convert netip.Addr bytes to net.IP for geoip2
		ipBytes := ip.AsSlice()
		rec, err := db.ASN(net.IP(ipBytes))
		if err != nil {
			// Don't treat geoip lookup errors as fatal for the whole ASN process
			return nil, nil // Return nil, nil to allow fallback to next provider
		}
		return &subnetgenerated.AsnInfo{
			Number: int(rec.AutonomousSystemNumber),
			Org:    strPtr(rec.AutonomousSystemOrganization),
			Source: "maxmind",
		}, nil
	}
}

/* Team Cymru WHOIS ------------------------------------------------------- */

func providerCymru(wait time.Duration) asnProvider {
	return func(ctx context.Context, ip netip.Addr) (*subnetgenerated.AsnInfo, error) {
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", "whois.cymru.com:43")
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		io.WriteString(conn, "begin\nverbose\n"+ip.String()+"\nend\n")
		r := bufio.NewReader(conn)
		r.ReadString('\n') // header
		line, _ := r.ReadString('\n')
		f := strings.Split(line, "|")
		if len(f) < 8 {
			return nil, errors.New("cymru: unexpected response")
		}
		asn, _ := strconv.Atoi(strings.TrimSpace(f[0]))
		country := strings.TrimSpace(f[3])
		org := strings.TrimSpace(f[7])

		time.Sleep(wait)
		return &subnetgenerated.AsnInfo{
			Number:  asn,
			Org:     strPtr(org),
			Country: strPtr(country),
			Source:  "cymru",
		}, nil
	}
}

/* ──────────────────── OWNERSHIP (RDAP → WHOIS) ────────────────────────── */

// lookupOwnershipCached wraps the ownership lookup with caching and singleflight.
func lookupOwnershipCached(ctx context.Context, ip netip.Addr, sCtx *scannerContext) (*subnetgenerated.WhoisData, error) {
	// Key cache by /24 prefix
	// We assume IPv4 based on initial Scan checks.
	netPrefix := netip.PrefixFrom(ip, 24) // Create prefix, implicitly masks

	// Check cache first
	if data, ok := sCtx.rdapCache.Get(netPrefix); ok {
		return data, nil
	}

	// Use singleflight with string keys
	v, err, _ := sCtx.rdapGroup.Do(netPrefix.String(), func() (any, error) { // Use netPrefix.String() as key
		// Note: The context passed to fetchOwnership uses the overall scanOne timeout.
		data, fetchErr := fetchOwnership(ctx, ip)
		if fetchErr == nil && data != nil {
			// Add to cache on success
			sCtx.rdapCache.Add(netPrefix, data)
		}
		// Return result and fetch error
		return data, fetchErr
	})

	// Handle error returned by singleflight.Do
	if err != nil {
		return nil, fmt.Errorf("ownership lookup failed for %s: %w", ip, err)
	}
	// Type assertion is safe here.
	return v.(*subnetgenerated.WhoisData), nil
}

// fetchOwnership performs the actual RDAP/WHOIS lookup.
// (Renamed from original lookupOwnership)
func fetchOwnership(ctx context.Context, ip netip.Addr) (*subnetgenerated.WhoisData, error) {
	// Attempt RDAP lookup first
	cli := &rdap.Client{}
	// RDAP client doesn't seem to directly support context cancellation easily in QueryIP.
	// We rely on the overall scanOne timeout.
	if ipNet, err := cli.QueryIP(ip.String()); err == nil && ipNet != nil {
		return parseRDAP(ipNet), nil
	}
	// Fallback to WHOIS

	// Apply context timeout to WHOIS connection attempt (if possible, likexian/whois doesn't directly support context)
	// We can use a custom transport/dialer if needed, but let's rely on the higher-level timeout for now.
	raw, err := whois.Whois(ip.String()) // Consider adding timeout wrapper if needed
	if err != nil {
		return nil, err
	}
	return parseWHOIS(raw), nil
}

// ---- RDAP -----------------------------------------------------------------

func parseRDAP(net *rdap.IPNetwork) *subnetgenerated.WhoisData {
	wd := &subnetgenerated.WhoisData{}

	// helper to extract first simple string value from the VCard
	property := func(vc *rdap.VCard, key string) string {
		if vc == nil {
			return ""
		}
		if p := vc.GetFirst(key); p != nil {
			if v, ok := p.Value.(string); ok {
				return v
			}
			if vs, ok := p.Value.([]interface{}); ok { // adr is []interface{}
				var parts []string
				for _, x := range vs {
					if s, ok := x.(string); ok && s != "" {
						parts = append(parts, s)
					}
				}
				return strings.Join(parts, ", ")
			}
		}
		return ""
	}

	// entities --------------------------------------------------------------
	walkEntities(net.Entities, func(e rdap.Entity) {
		if e.VCard == nil {
			return
		}
		switch {
		case hasRole(e, "registrant") && wd.OrgName == nil:
			wd.OrgName = strPtr(property(e.VCard, "org"))
			wd.ContactName = strPtr(property(e.VCard, "fn"))
			wd.Address = strPtr(property(e.VCard, "adr"))
			wd.Country = strPtr(property(e.VCard, "country"))
		case hasRole(e, "administrative") && wd.ContactEmail == nil:
			wd.ContactEmail = strPtr(property(e.VCard, "email"))
			wd.Phone = strPtr(property(e.VCard, "tel"))
		}
	})

	// dates -----------------------------------------------------------------
	for _, ev := range net.Events {
		switch ev.Action {
		case "registration":
			wd.CreatedDate = parseTime(ev.Date)
		case "last changed":
			wd.UpdatedDate = parseTime(ev.Date)
		}
	}
	return wd
}

func walkEntities(list []rdap.Entity, f func(rdap.Entity)) {
	for _, e := range list {
		f(e)
		walkEntities(e.Entities, f)
	}
}
func hasRole(e rdap.Entity, role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// ---- WHOIS (likexian) -----------------------------------------------------

func parseWHOIS(raw string) *subnetgenerated.WhoisData {
	wd := &subnetgenerated.WhoisData{Raw: &raw}
	p, err := whoisparser.Parse(raw)
	if err != nil {
		return wd
	}
	// registrar & dates
	wd.Registrar = strPtr(p.Registrar.Name)
	wd.CreatedDate = parseTime(p.Domain.CreatedDate)
	wd.UpdatedDate = parseTime(p.Domain.UpdatedDate)

	// registrant block
	r := p.Registrant
	wd.OrgName = strPtr(r.Organization)
	wd.ContactName = strPtr(r.Name)
	wd.ContactEmail = strPtr(r.Email)
	wd.Phone = strPtr(r.Phone)
	wd.Country = strPtr(r.Country)

	var adrParts []string
	if r.Street != "" {
		adrParts = append(adrParts, r.Street)
	}
	if r.City != "" {
		adrParts = append(adrParts, r.City)
	}
	if r.Province != "" {
		adrParts = append(adrParts, r.Province)
	}
	if r.PostalCode != "" {
		adrParts = append(adrParts, r.PostalCode)
	}
	if r.Country != "" {
		adrParts = append(adrParts, r.Country)
	}
	if len(adrParts) > 0 {
		addr := strings.Join(adrParts, ", ")
		wd.Address = &addr
	}
	return wd
}

// ---- helpers --------------------------------------------------------------

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"02-Jan-2006",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return &t
		}
	}
	return nil
}
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
