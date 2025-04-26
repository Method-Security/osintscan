// internal/subnet/scanner.go
package subnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	subnetgenerated "github.com/Method-Security/osintscan/generated/go/subnet"

	ristretto "github.com/dgraph-io/ristretto/v2"
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
	ASNAPIKey     string                      // key for ProjectDiscovery (optional)
	MaxMindDB     string                      // path to GeoLite2-ASN.mmdb (optional)
	PoliteWait    time.Duration               // sleep between network ASN look-ups
	PTRTimeout    time.Duration               // timeout for PTR lookups
	RDAPCacheSize int                         // default 2048
	PTRCacheSize  int                         // default 8192
	CacheTTL      time.Duration               // Time-to-live for cache entries
	Metrics       *subnetgenerated.RunMetrics // Pointer to store collected metrics
}

// scannerContext holds shared resources for a single scan operation.
type scannerContext struct {
	cfg       ScanConfig
	asnLookup asnProvider
	rdapCache *ristretto.Cache[uint32, *subnetgenerated.WhoisData] // Use Ristretto type (pointer) with uint32 key
	rdapGroup sf.Group                                             // singleflight for RDAP/WHOIS lookups
	metrics   *scanMetrics                                         // Internal metrics holder
}

// scanMetrics holds the atomic counters and timing information.
type scanMetrics struct {
	ipTotal     atomic.Int64
	opStatsPTR  *OpStats
	opStatsASN  *OpStats
	opStatsRDAP *OpStats
	startTime   time.Time
}

// OpStats holds atomic counters for a specific operation type (PTR, ASN, RDAP).
type OpStats struct {
	calls     atomic.Int64
	succeeded atomic.Int64
	failed    atomic.Int64
	timeouts  atomic.Int64
}

// NewOpStats creates a new OpStats with initialized counters.
func NewOpStats() *OpStats {
	return &OpStats{} // Atomics are zero-initialized
}

func (o *OpStats) IncCalls()     { o.calls.Add(1) }
func (o *OpStats) IncSucceeded() { o.succeeded.Add(1) }
func (o *OpStats) IncFailed()    { o.failed.Add(1) }
func (o *OpStats) IncTimeouts()  { o.timeouts.Add(1) }

// Get returns the current values as a generated OpStats struct.
func (o *OpStats) Get() *subnetgenerated.OpStats {
	calls := o.calls.Load()
	succeeded := o.succeeded.Load()
	failed := o.failed.Load()
	timeouts := o.timeouts.Load()
	// Use helper to convert int64 to *int, handling zero
	return &subnetgenerated.OpStats{
		Calls:     int64PtrToIntPtr(calls),
		Succeeded: int64PtrToIntPtr(succeeded),
		Failed:    int64PtrToIntPtr(failed),
		Timeouts:  int64PtrToIntPtr(timeouts),
	}
}

/* ──────────────────── HELPERS ─────────────────────────────────────── */

// Helper to convert int64 to *int, returning nil if the value is 0.
func int64PtrToIntPtr(val int64) *int {
	if val == 0 {
		return nil
	}
	intVal := int(val)
	return &intVal
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

	if cfg.Metrics == nil {
		return nil, errors.New("ScanConfig.Metrics cannot be nil")
	}

	// Initialize internal metrics struct
	scanMetrics := &scanMetrics{
		startTime:   time.Now(),
		opStatsPTR:  NewOpStats(),
		opStatsASN:  NewOpStats(),
		opStatsRDAP: NewOpStats(),
		// ipTotal is initialized to 0 by default
	}

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

	mmdb, err := openMaxMind(cfg.MaxMindDB)
	if err != nil {
		return nil, fmt.Errorf("opening MaxMind DB at %q: %w", cfg.MaxMindDB, err)
	}

	lookupASN := chain(
		providerMM(mmdb),
		// providerPD(pdCli, cfg.PoliteWait), // if you have the api key you get access to more data
		// providerCymru(cfg.PoliteWait),     // final fallback
	)

	// ─ Caches and singleflight groups -------------------------------------
	rdapCache, err := ristretto.NewCache(&ristretto.Config[uint32, *subnetgenerated.WhoisData]{
		NumCounters: 1 << 18, // ~260 K counters (tuned for /16)
		MaxCost:     1 << 17, // 131 072 items (tuned for /16)
		BufferItems: 256,     // match Workers concurrency
		Metrics:     true,
		// OnEvict:     func(item *ristretto.Item[uint32, *subnetgenerated.WhoisData]) { /* TODO: Atomic counter increment */ },
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create RDAP cache: %w", err)
	}

	// ─ Scanner context ----------------------------------------------------
	sCtx := &scannerContext{
		cfg:       cfg, // Pass the potentially modified cfg
		asnLookup: lookupASN,
		rdapCache: rdapCache,
		metrics:   scanMetrics, // Assign initialized metrics
		// rdapGroup is zero-value ready
	}

	// ─ producer & worker channels ----------------------------------------
	buf := cfg.Workers * 128
	if buf > 4096 {
		buf = 4096
	}
	ipCh := make(chan netip.Addr, buf)
	out := make(chan *subnetgenerated.IpReport)

	go enumerate(ctx, prefix, ipCh, sCtx)
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
	go func() {
		wg.Wait()
		finishTime := time.Now()

		// --- Populate Final Metrics ---
		cfg.Metrics.StartedAt = &scanMetrics.startTime
		cfg.Metrics.FinishedAt = &finishTime
		runtimeMs := finishTime.Sub(scanMetrics.startTime).Milliseconds()
		cfg.Metrics.RuntimeMs = int64PtrToIntPtr(runtimeMs) // Use helper

		ipTotal := scanMetrics.ipTotal.Load()
		cfg.Metrics.IpTotal = int64PtrToIntPtr(ipTotal) // Use helper

		if ipTotal > 0 && runtimeMs > 0 {
			avgIpMs := runtimeMs / ipTotal
			cfg.Metrics.AvgIpMs = int64PtrToIntPtr(avgIpMs) // Use helper
		}

		// Op Stats
		cfg.Metrics.Ptr = scanMetrics.opStatsPTR.Get()
		cfg.Metrics.Asn = scanMetrics.opStatsASN.Get()
		cfg.Metrics.Rdap = scanMetrics.opStatsRDAP.Get()

		// Cache Stats (Requires ptrCache and rdapCache to be accessible here)
		rdapMetrics := rdapCache.Metrics
		cacheStats := &subnetgenerated.CacheStats{}
		if rdapMetrics != nil {
			rdapHits := rdapMetrics.Hits()
			rdapMisses := rdapMetrics.Misses()
			rdapEvicted := rdapMetrics.CostEvicted() // Assumes cost=1 per item
			cacheStats.RdapHits = uint64PtrToIntPtr(rdapHits)
			cacheStats.RdapMisses = uint64PtrToIntPtr(rdapMisses)
			cacheStats.RdapEvictions = uint64PtrToIntPtr(rdapEvicted)
		}
		cfg.Metrics.Cache = cacheStats

		// TODO: Populate ip_success and ip_failed if needed, potentially derived from OpStats
		// Example derivation:
		if cfg.Metrics.Ptr != nil && cfg.Metrics.Asn != nil && cfg.Metrics.Rdap != nil {
			success := int64(0)
			failed := int64(0)
			if cfg.Metrics.Ptr.Succeeded != nil {
				success += int64(*cfg.Metrics.Ptr.Succeeded)
			}
			if cfg.Metrics.Asn.Succeeded != nil {
				success += int64(*cfg.Metrics.Asn.Succeeded)
			}
			if cfg.Metrics.Rdap.Succeeded != nil {
				success += int64(*cfg.Metrics.Rdap.Succeeded)
			}
			if cfg.Metrics.Ptr.Failed != nil {
				failed += int64(*cfg.Metrics.Ptr.Failed)
			}
			if cfg.Metrics.Asn.Failed != nil {
				failed += int64(*cfg.Metrics.Asn.Failed)
			}
			if cfg.Metrics.Rdap.Failed != nil {
				failed += int64(*cfg.Metrics.Rdap.Failed)
			}
			// Note: This sums *operations*, not IPs. A single IP could have multiple successes/failures.
			// A better 'ip_success' might be ipTotal - 'ips with any failure'. This requires tracking failures per IP.
			// For now, let's leave IpSuccess/IpFailed nil as their definition is ambiguous.
		}

		// Close caches after metrics are collected
		rdapCache.Close()
		close(out)
	}()
	return out, nil
}

/* ──────────────────── ENUMERATOR ─────────────────────────────────────── */

func enumerate(ctx context.Context, pfx netip.Prefix, out chan<- netip.Addr, sCtx *scannerContext) {
	defer close(out)
	for ip := pfx.Addr(); pfx.Contains(ip); ip = ip.Next() {
		sCtx.metrics.ipTotal.Add(1) // Increment total IP count
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

	// PTR - Direct lookup
	if names, err := doPTRLookup(ctx, ip, sCtx); err != nil { // Pass scanner context
		rep.Errors = append(rep.Errors, "PTR: "+err.Error())
	} else {
		rep.PtrRecords = names
	}

	// ASN - Use the provider from scannerContext
	sCtx.metrics.opStatsASN.IncCalls()
	if asn, err := sCtx.asnLookup(ctx, ip); err == nil && asn != nil {
		rep.Asn = asn
		sCtx.metrics.opStatsASN.IncSucceeded()
	} else if err != nil {
		rep.Errors = append(rep.Errors, "ASN: "+err.Error())
		sCtx.metrics.opStatsASN.IncFailed()
		// TODO: Check if err is a timeout error if more granular ASN timeout tracking is needed
	} else {
		// Case where asn is nil but error is also nil (e.g., provider skipped or returned no data)
		sCtx.metrics.opStatsASN.IncSucceeded() // Count as success if no error occurred
	}

	// RDAP / WHOIS - Use cached lookup
	if whois, err := lookupOwnershipCached(ctx, ip, sCtx); err != nil {
		rep.Errors = append(rep.Errors, "RDAP/WHOIS: "+err.Error())
		// Note: We don't increment failure count here, it's done in lookupOwnershipCached
	} else if whois != nil {
		rep.Ownership = whois
	}
	return rep
}

/* ──────────────────── DNS PTR ─────────────────────────────────────────── */

// doPTRLookup performs the actual DNS PTR lookup and updates metrics.
func doPTRLookup(ctx context.Context, ip netip.Addr, sCtx *scannerContext) ([]string, error) {
	sCtx.metrics.opStatsPTR.IncCalls() // Increment calls

	// Apply the effective timeout for the actual network call
	lookupCtx, cancel := context.WithTimeout(ctx, sCtx.cfg.PTRTimeout) // Use timeout from cfg
	defer cancel()

	resolver := sCtx.cfg.Resolver // Get resolver from context
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
	names, err := r.LookupAddr(lookupCtx, ip.String())
	if err != nil {
		// NXDOMAIN / not-found is not a real "failure" for us
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			sCtx.metrics.opStatsPTR.IncSucceeded() // 1 negative success
			return []string{}, nil
		}
		// only now count it as a failure
		sCtx.metrics.opStatsPTR.IncFailed()
		if errors.Is(err, context.DeadlineExceeded) {
			sCtx.metrics.opStatsPTR.IncTimeouts()
		}
		return nil, err
	}

	// on real success
	sCtx.metrics.opStatsPTR.IncSucceeded()
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

/* ──────────────────── OWNERSHIP (RDAP → WHOIS) ────────────────────────── */

// lookupOwnershipCached wraps the ownership lookup with caching and singleflight.
func lookupOwnershipCached(ctx context.Context, ip netip.Addr, sCtx *scannerContext) (*subnetgenerated.WhoisData, error) {
	// Define a sentinel for negative caching
	var rdapNegative = &subnetgenerated.WhoisData{}

	// Pack the /24 network into a uint32 key (host bits zeroed)
	network24Key := func(ip netip.Addr) uint32 {
		b := ip.As4() // 4-byte IPv4
		return uint32(b[0])<<24 |
			uint32(b[1])<<16 |
			uint32(b[2])<<8 // host byte = 0
	}

	k := network24Key(ip)

	// Check cache first
	if data, ok := sCtx.rdapCache.Get(k); ok {
		return data, nil
	}

	// Use singleflight with uint32 keys
	v, err, _ := sCtx.rdapGroup.Do(fmt.Sprintf("rdap-%d", k), func() (any, error) { // Key needs to be string for singleflight
		sCtx.metrics.opStatsRDAP.IncCalls() // Increment calls

		// Note: The context passed to fetchOwnership uses the overall scanOne timeout.
		data, fetchErr := fetchOwnership(ctx, ip)

		// Use the pre-defined sentinel for negative caching
		// var rdapNegative = &subnetgenerated.WhoisData{} // No longer needed here

		if fetchErr != nil {
			// Cache the failure for 1 minute to back off
			sCtx.rdapCache.SetWithTTL(k, rdapNegative, 1, time.Minute)

			// Track failure/timeout (original logic moved here)
			sCtx.metrics.opStatsRDAP.IncFailed()
			// RDAP/WHOIS clients might not wrap context errors nicely.
			// Check the main context passed to fetchOwnership as a proxy for timeout.
			if ctx.Err() == context.DeadlineExceeded {
				sCtx.metrics.opStatsRDAP.IncTimeouts()
			}
			// Return the error to singleflight
			return nil, fetchErr
		}

		// Add to cache on success
		if data != nil {
			// Cost is 1, TTL comes from config.
			sCtx.rdapCache.SetWithTTL(k, data, 1, sCtx.cfg.CacheTTL)
		} else {
			// If fetchOwnership succeeded but returned nil data (shouldn't happen often?),
			// cache the negative sentinel as well to avoid re-fetching immediately.
			negTTL := 10 * time.Second
			sCtx.rdapCache.SetWithTTL(k, rdapNegative, 1, negTTL)
		}

		// Track success (only if fetchErr is nil)
		sCtx.metrics.opStatsRDAP.IncSucceeded()

		// Return result and nil fetch error
		return data, nil
	})

	// Handle error returned by singleflight.Do
	if err != nil {
		// Don't return the negative cache sentinel on error
		return nil, fmt.Errorf("ownership lookup failed for %s: %w", ip, err)
	}

	// Check if the result is the negative cache sentinel
	resultData := v.(*subnetgenerated.WhoisData)
	if resultData == rdapNegative { // Compare pointers
		// It was a cached failure, return nil data and no error
		return nil, nil
	}

	// Type assertion is safe here, return the actual data.
	return resultData, nil
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

// Add a helper function to convert uint64 to *int
func uint64PtrToIntPtr(val uint64) *int {
	if val == 0 {
		return nil
	}
	intVal := int(val)
	return &intVal
}
