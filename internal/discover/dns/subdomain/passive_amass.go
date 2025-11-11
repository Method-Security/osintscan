package subdomain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetDomainSubdomainsPassiveAmass queries amass for all subdomains for a given domain using passive sources.
// Returns a report containing all discovered subdomains and any errors encountered.
func GetDomainSubdomainsPassiveAmass(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainConfig) (dnsfern.DiscoverDnsSubdomainReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting passive subdomain discovery with amass",
		svc1log.SafeParam("domain", cfg.Passive.Domain))

	// Get all valid subdomains using passive enumeration with amass
	subdomains, err := getSubdomainsPassiveAmass(ctx, *cfg.Passive)
	if err != nil {
		log.Warn("Passive subdomain discovery (amass) encountered errors",
			svc1log.SafeParam("domain", cfg.Passive.Domain),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}

	result := dnsfern.DiscoverDnsSubdomainResult{
		Subdomains: subdomains,
	}

	report := dnsfern.DiscoverDnsSubdomainReport{
		Config: &cfg,
		Result: &result,
		Errors: errors,
	}

	log.Info("Completed passive subdomain discovery with amass",
		svc1log.SafeParam("domain", cfg.Passive.Domain),
		svc1log.SafeParam("subdomains_found", len(subdomains)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}

// getSubdomainsPassiveAmass runs amass in passive mode for a single domain and returns the discovered subdomains.
func getSubdomainsPassiveAmass(ctx context.Context, cfg dnsfern.DiscoverDnsSubdomainPassiveConfig) ([]string, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Configuring amass for passive discovery",
		svc1log.SafeParam("domain", cfg.Domain),
		svc1log.SafeParam("threads", cfg.Threads),
		svc1log.SafeParam("rate_limit", cfg.RequestsPerSecond))

	// Use the amass CLI if available; run passive enum and capture output
	// Flags: -passive -d <domain> -silent -nocolor -nolocaldb
	args := []string{"enum", "-passive", "-d", cfg.Domain, "-silent", "-nocolor", "-nolocaldb"}
	cmd := exec.CommandContext(ctx, "amass", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Debug("Executing amass CLI",
		svc1log.SafeParam("command", strings.Join(append([]string{"amass"}, args...), " ")))

	if err := cmd.Run(); err != nil {
		return []string{}, fmt.Errorf("amass CLI execution failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}

	// Parse output lines into unique subdomains
	unique := map[string]struct{}{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		unique[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return []string{}, fmt.Errorf("failed reading amass output: %w", err)
	}

	subdomains := make([]string, 0, len(unique))
	for s := range unique {
		subdomains = append(subdomains, s)
	}
	return subdomains, nil
}


