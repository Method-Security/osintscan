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

	"encoding/binary"
	"math/bits"

	ristretto "github.com/dgraph-io/ristretto/v2"
	cidranger "github.com/libp2p/go-cidranger"
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
	DefaultRDAPCacheSize    = 2048
	DefaultCacheTTL         = 1 * time.Hour    // Default TTL for cache entries
	DefaultNegativeCacheTTL = 10 * time.Second // TTL for negative cache entries
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
	CacheTTL      time.Duration               // Time-to-live for cache entries
	Metrics       *subnetgenerated.RunMetrics // Pointer to store collected metrics
}

// Global sentinel value for negative caching
var rdapNegative = &subnetgenerated.WhoisData{}

// scannerContext holds shared resources for a single scan operation.
type scannerContext struct {
	cfg       ScanConfig
	asnLookup asnProvider
	// Primary cache: Stores WhoisData. Key is dynamic CIDR string or IP string.
	rdapCache *ristretto.Cache[string, *subnetgenerated.WhoisData]
	// Ranger: Maps IPs to known network blocks for faster cache lookups.
	ranger     cidranger.Ranger // Use the non-generic interface type
	rangerLock sync.RWMutex     // Protects the ranger
	rdapGroup  sf.Group         // singleflight for RDAP/WHOIS lookups (keyed by IP string)
	metrics    *scanMetrics     // Internal metrics holder
}

// scanMetrics holds the atomic counters and timing information.
type scanMetrics struct {
	ipTotal     atomic.Int64
	opStatsPTR  *OpStats
	opStatsASN  *OpStats
	opStatsRDAP *OpStats
	startTime   time.Time
}

// rangerMapEntry stores the network and the associated Ristretto cache key.
type rangerMapEntry struct {
	network  net.IPNet // Use standard net.IPNet for cidranger
	cacheKey string    // The key used in Ristretto (dynamic CIDR string)
}

func (r *rangerMapEntry) Network() net.IPNet {
	return r.network
}

// newRangerMapEntry creates a new entry for the cidranger.
func newRangerMapEntry(prefix netip.Prefix, key string) cidranger.RangerEntry {
	// Convert netip.Prefix to net.IPNet
	ip := prefix.Addr().AsSlice()
	mask := net.CIDRMask(prefix.Bits(), len(ip)*8)
	return &rangerMapEntry{
		network:  net.IPNet{IP: ip, Mask: mask},
		cacheKey: key,
	}
}

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

	scanMetrics := &scanMetrics{
		startTime:   time.Now(),
		opStatsPTR:  NewOpStats(),
		opStatsASN:  NewOpStats(),
		opStatsRDAP: NewOpStats(),
	}

	// ─ ASN providers ------------------------------------------------------
	pdCli := initProjectDiscovery(cfg.ASNAPIKey)
	if pdCli != nil {
		_, testErr := pdCli.GetData("1.1.1.1")
		if testErr != nil {
			errMsg := testErr.Error()
			// this check should be done better probably
			if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "missing") {
				fmt.Fprintln(os.Stderr, "Warning: ProjectDiscovery API key is invalid or missing. Skipping ProjectDiscovery provider.")
				pdCli = nil // dont use project discovery
			}
		}
	}

	mmdb, err := openMaxMind(cfg.MaxMindDB)
	if err != nil {
		return nil, fmt.Errorf("opening MaxMind DB at %q: %w", cfg.MaxMindDB, err)
	}

	lookupASN := chain(
		providerMM(mmdb),
		providerPD(pdCli, cfg.PoliteWait), // if you have the api key you get access to more data
		// add a final fallback, maybe cymru?
	)

	// ─ Caches and singleflight groups -------------------------------------
	rdapCache, err := ristretto.NewCache(&ristretto.Config[string, *subnetgenerated.WhoisData]{
		NumCounters: 1 << 18, // ~260 K counters (tuned for /16)
		MaxCost:     1 << 17, // 131 072 items (tuned for /16)
		BufferItems: 256,     // match Workers concurrency
		Metrics:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create RDAP cache: %w", err)
	}

	ranger := cidranger.NewPCTrieRanger()

	// ─ Scanner context ----------------------------------------------------
	sCtx := &scannerContext{
		cfg:       cfg,
		asnLookup: lookupASN,
		rdapCache: rdapCache,
		ranger:    ranger,
		metrics:   scanMetrics,
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
		cfg.Metrics.RuntimeMs = int64PtrToIntPtr(runtimeMs)

		ipTotal := scanMetrics.ipTotal.Load()
		cfg.Metrics.IpTotal = int64PtrToIntPtr(ipTotal)

		if ipTotal > 0 && runtimeMs > 0 {
			avgIpMs := runtimeMs / ipTotal
			cfg.Metrics.AvgIpMs = int64PtrToIntPtr(avgIpMs)
		}

		// Op Stats
		cfg.Metrics.Ptr = scanMetrics.opStatsPTR.Get()
		cfg.Metrics.Asn = scanMetrics.opStatsASN.Get()
		cfg.Metrics.Rdap = scanMetrics.opStatsRDAP.Get()

		rdapMetrics := rdapCache.Metrics
		cacheStats := &subnetgenerated.CacheStats{}
		if rdapMetrics != nil {
			rdapHits := rdapMetrics.Hits()
			rdapMisses := rdapMetrics.Misses()
			cacheStats.RdapHits = uint64PtrToIntPtr(rdapHits)
			cacheStats.RdapMisses = uint64PtrToIntPtr(rdapMisses)
		}
		cfg.Metrics.Cache = cacheStats

		rdapCache.Close()
		close(out)
	}()
	return out, nil
}

/* ──────────────────── ENUMERATOR ─────────────────────────────────────── */

func enumerate(ctx context.Context, pfx netip.Prefix, out chan<- netip.Addr, sCtx *scannerContext) {
	defer close(out)
	for ip := pfx.Addr(); pfx.Contains(ip); ip = ip.Next() {
		sCtx.metrics.ipTotal.Add(1)
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
	if names, err := doPTRLookup(ctx, ip, sCtx); err != nil {
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
	} else {
		// Case where asn is nil but error is also nil (e.g., provider skipped or returned no data)
		sCtx.metrics.opStatsASN.IncSucceeded() // count as success if no error occurred?
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
func doPTRLookup(ctx context.Context, ip netip.Addr, sCtx *scannerContext) ([]string, error) {
	sCtx.metrics.opStatsPTR.IncCalls()

	lookupCtx, cancel := context.WithTimeout(ctx, sCtx.cfg.PTRTimeout)
	defer cancel()

	resolver := sCtx.cfg.Resolver
	r := net.DefaultResolver
	if resolver != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", resolver)
			},
		}
	}
	names, err := r.LookupAddr(lookupCtx, ip.String())
	if err != nil {
		// NXDOMAIN / not-found is not a real "failure" for us
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			sCtx.metrics.opStatsPTR.IncSucceeded()
			return []string{}, nil
		}
		sCtx.metrics.opStatsPTR.IncFailed()
		if errors.Is(err, context.DeadlineExceeded) {
			sCtx.metrics.opStatsPTR.IncTimeouts()
		}
		return nil, err
	}

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
		ipBytes := ip.AsSlice()
		rec, err := db.ASN(net.IP(ipBytes))
		if err != nil {
			return nil, nil
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

	ipKey := ip.String() // Key for specific IP lookups/failures

	// check if the ip is in the ranger
	sCtx.rangerLock.RLock()
	containingNetworks, err := sCtx.ranger.ContainingNetworks(net.IP(ip.AsSlice()))
	sCtx.rangerLock.RUnlock()

	if err == nil && len(containingNetworks) > 0 {
		// Found potential containing block(s) in the ranger
		if entry, ok := containingNetworks[0].(*rangerMapEntry); ok {
			dynamicKey := entry.cacheKey
			// Check Ristretto cache using the key found in the ranger
			if data, hit := sCtx.rdapCache.Get(dynamicKey); hit {
				// Data found via ranger -> dynamicKey
				// We assume only positive results are stored with dynamic keys
				if data != rdapNegative { // Double check it's not the negative sentinel
					return data, nil // Cache HIT via Ranger
				}
			}
		}
	}

	// check if the ip is in the ristretto cache
	if cachedVal, hit := sCtx.rdapCache.Get(ipKey); hit {
		if cachedVal == rdapNegative {
			return nil, nil // Cached failure specific to this IP
		}
		return cachedVal, nil // Cache HIT via direct IP key
	}

	// Use singleflight keyed by the specific IP address string
	v, err, _ := sCtx.rdapGroup.Do(ipKey, func() (any, error) {
		sCtx.metrics.opStatsRDAP.IncCalls()

		data, keyToUse, fetchErr := fetchOwnership(ctx, ip)

		// Handle Negative Caching on Error
		if fetchErr != nil {
			// Cache the failure under the specific IP key
			sCtx.rdapCache.SetWithTTL(ipKey, rdapNegative, 1, DefaultNegativeCacheTTL)

			sCtx.metrics.opStatsRDAP.IncFailed()
			if ctx.Err() == context.DeadlineExceeded {
				sCtx.metrics.opStatsRDAP.IncTimeouts()
			}
			return nil, fetchErr
		}

		// cache success
		sCtx.rdapCache.SetWithTTL(keyToUse, data, 1, sCtx.cfg.CacheTTL)
		// also cache under the specific IP to guarantee a hit next time
		if keyToUse != ipKey {
			sCtx.rdapCache.SetWithTTL(ipKey, data, 1, sCtx.cfg.CacheTTL)
		}

		// if the key used was a dynamic CIDR, update the ranger
		if keyToUse != ipKey { // Check if it's not the fallback IP key
			prefix, pErr := netip.ParsePrefix(keyToUse)
			if pErr == nil {
				entry := newRangerMapEntry(prefix, keyToUse) // Create custom entry
				sCtx.rangerLock.Lock()
				insertErr := sCtx.ranger.Insert(entry) // Insert custom entry
				sCtx.rangerLock.Unlock()
				if insertErr != nil {
					// we should probably log this
				}
			} else {
				// we should probably log this
			}
		}

		// Track success
		sCtx.metrics.opStatsRDAP.IncSucceeded()

		// Return result and nil error to singleflight
		return data, nil
	})

	// --- Process Singleflight Result ---
	if err != nil {
		return nil, fmt.Errorf("ownership lookup failed for %s: %w", ip, err)
	}

	// Check if the result is the negative cache sentinel
	resultData, ok := v.(*subnetgenerated.WhoisData)
	if !ok {
		// Should not happen if singleflight function returns correct types
		return nil, fmt.Errorf("internal error: unexpected type from singleflight for %s", ip)
	}

	if resultData == rdapNegative { // Compare pointers
		// It was a cached failure (or lookup returned negative sentinel), return nil data and no error
		return nil, nil
	}

	// Type assertion is safe here, return the actual data.
	return resultData, nil
}

// fetchOwnership performs the actual RDAP/WHOIS lookup and determines the appropriate cache key.
// Returns: WhoisData, cacheKey string, error
func fetchOwnership(ctx context.Context, ip netip.Addr) (*subnetgenerated.WhoisData, string, error) {
	// Attempt RDAP lookup first
	cli := &rdap.Client{}
	ipStr := ip.String() // Use consistent string representation

	// RDAP client doesn't seem to directly support context cancellation easily in QueryIP.
	// We rely on the overall scanOne timeout.
	if ipNet, err := cli.QueryIP(ipStr); err == nil && ipNet != nil {
		// RDAP Success
		data := parseRDAP(ipNet)
		cacheKey := ipStr // fallback

		if pfx, ok := deriveRDAPPrefix(ipNet); ok {
			// Ensure the derived prefix actually contains the queried IP (safety check)
			if prefix, err := netip.ParsePrefix(pfx); err == nil && prefix.Contains(ip) {
				cacheKey = pfx
			}
		}

		return data, cacheKey, nil
	}

	// fallback to whois
	raw, err := whois.Whois(ipStr)
	if err != nil {
		return nil, ipStr, err
	}

	// whois success
	whoisData := parseWHOIS(raw)
	return whoisData, ipStr, nil
}

// deriveRDAPPrefix attempts to compute the smallest covering prefix from the
// RDAP StartAddress and EndAddress fields. It returns the prefix string and
// true on success, or "", false if it cannot derive a sensible prefix.
func deriveRDAPPrefix(ipNet *rdap.IPNetwork) (string, bool) {
	if ipNet == nil || ipNet.StartAddress == "" || ipNet.EndAddress == "" {
		return "", false
	}

	start, sErr := netip.ParseAddr(ipNet.StartAddress)
	end, eErr := netip.ParseAddr(ipNet.EndAddress)
	if sErr != nil || eErr != nil || start.Is4() != end.Is4() {
		return "", false
	}

	if !start.Is4() {
		return "", false
	}

	// Convert to uint32 for bit operations.
	startArr := start.As4()
	endArr := end.As4()
	sb := binary.BigEndian.Uint32(startArr[:])
	eb := binary.BigEndian.Uint32(endArr[:])

	xor := sb ^ eb
	if xor == 0 {
		// Identical start/end -> /32, not useful for grouping
		return "", false
	}

	prefixLen := bits.LeadingZeros32(xor)
	if prefixLen < 8 { // avoid extremely large networks like 0/0
		return "", false
	}

	// Mask the start address to the prefix.
	masked := sb &^ ((1 << (32 - prefixLen)) - 1)
	var maskedBytes [4]byte
	binary.BigEndian.PutUint32(maskedBytes[:], masked)
	addr, ok := netip.AddrFromSlice(maskedBytes[:])
	if !ok {
		return "", false
	}

	pfx := netip.PrefixFrom(addr, prefixLen)
	return pfx.String(), true
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

// use likexian/whois-parser to parse the raw whois data, this can extract domain but not ip information (which is why rdap is preferred)
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
