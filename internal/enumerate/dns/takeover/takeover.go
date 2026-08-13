package takeover

import (
	"context"
	"io"
	"net/http"
	"strings"

	dnsfern "github.com/Method-Security/osintscan/generated/go/enumerate/dns"
	osintConfig "github.com/Method-Security/osintscan/internal/config"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// DetectDomainTakeover checks a list of targets for potential subdomain takeover vulnerabilities.
// Returns a report containing the results for each target and any errors encountered.
func DetectDomainTakeover(ctx context.Context, config dnsfern.EnumerateDomainTakeoverConfig, fingerprints []*dnsfern.DomainTakeoverFingerprint) (*dnsfern.EnumerateDomainTakeoverReport, error) {
	log := svc1log.FromContext(ctx)
	errs := []string{}

	log.Info("Starting domain takeover detection",
		svc1log.SafeParam("target_count", len(config.Targets)),
		svc1log.SafeParam("fingerprint_count", len(fingerprints)),
		svc1log.SafeParam("successful_only", config.SuccessfulOnly))

	proxyConfig := osintConfig.ProxyConfigFromContext(ctx)
	if proxyConfig.HttpProxy != "" {
		config.HttpProxy = &proxyConfig.HttpProxy
	}
	if proxyConfig.SocksProxy != "" {
		config.SocksProxy = &proxyConfig.SocksProxy
	}

	// Create HTTP client
	httpClient, err := createHTTPClient(ctx, config.VerifyTls, config.Timeout)
	if err != nil {
		errs = append(errs, err.Error())
		return &dnsfern.EnumerateDomainTakeoverReport{
			Config: &config,
			Result: &dnsfern.EnumerateDomainTakeoverResult{},
			Errors: errs,
		}, nil
	}

	var takeoverResults []*dnsfern.DomainTakeover
	for _, target := range config.Targets {
		var urlTargets []string

		// Add scheme if missing
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			urlTargets = append(urlTargets, "http://"+target, "https://"+target)
		} else {
			urlTargets = append(urlTargets, target)
		}

		// Loop through targets with schemes
		for _, url := range urlTargets {
			log.Debug("Testing target for takeover", svc1log.SafeParam("target", url))

			// Retrieve CNAME record
			domain, cname, returnsNXDomain, err := retrieveCNAMERecord(url)
			if err != nil {
				log.Warn("Failed to retrieve CNAME record",
					svc1log.SafeParam("target", url),
					svc1log.SafeParam("error", err.Error()))
				errs = append(errs, err.Error())
				continue
			}

			// Send request to target
			response, serviceResults, successful := sendRequest(url, httpClient, fingerprints, cname, returnsNXDomain, config.SuccessfulOnly)
			if !config.SuccessfulOnly || successful {
				if successful {
					log.Info("Potential takeover vulnerability found",
						svc1log.SafeParam("target", url),
						svc1log.SafeParam("cname", cname))
				}
				takeoverResult := dnsfern.DomainTakeover{
					Target:          url,
					Domain:          domain,
					Cname:           cname,
					ReturnsNxDomain: returnsNXDomain,
					Response:        response,
					HostingServices: serviceResults,
				}
				takeoverResults = append(takeoverResults, &takeoverResult)
			}
		}
	}

	report := dnsfern.EnumerateDomainTakeoverReport{
		Config: &config,
		Result: &dnsfern.EnumerateDomainTakeoverResult{
			DomainTakeovers: takeoverResults,
		},
		Errors: errs,
	}

	vulnerableCount := 0
	for _, result := range takeoverResults {
		for _, service := range result.HostingServices {
			if service.Vulnerable {
				vulnerableCount++
				break
			}
		}
	}

	log.Info("Completed domain takeover detection",
		svc1log.SafeParam("targets_tested", len(config.Targets)),
		svc1log.SafeParam("results_found", len(takeoverResults)),
		svc1log.SafeParam("vulnerable_targets", vulnerableCount),
		svc1log.SafeParam("error_count", len(errs)))

	return &report, nil
}

// sendRequest sends a request to the target and analyzes the response for domain takeovers.
// Returns the response, detected services, and whether a successful takeover was found.
func sendRequest(url string, client *http.Client, fingerprints []*dnsfern.DomainTakeoverFingerprint, cname string, returnsNXDomain bool, onlySuccessful bool) (*dnsfern.DomainTakeoverResponse, []*dnsfern.HostingService, bool) {
	response := dnsfern.DomainTakeoverResponse{}

	if !returnsNXDomain {
		resp, err := client.Get(url)
		if err != nil {
			// Error during HTTP request
			errString := err.Error()
			response.Error = &errString
			return &response, nil, false
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			// Error reading response body
			errString := err.Error()
			response.Error = &errString
			return &response, nil, false
		}

		// Set Response Data
		response.StatusCode = &resp.StatusCode
		response.ResponseHeaders = make(map[string]string)
		for key, value := range resp.Header {
			response.ResponseHeaders[key] = strings.Join(value, ",")
		}
		body := string(bodyBytes)
		response.ResponseBody = &body
	}

	// Analyze Response
	serviceInfo, successful := analyzeResponse(fingerprints, cname, response.ResponseBody, returnsNXDomain, onlySuccessful)
	return &response, serviceInfo, successful
}

// analyzeResponse analyzes the response for domain takeovers using the helper function isVulnerable.
// Returns a list of detected services and whether a successful takeover was found.
func analyzeResponse(fingerprints []*dnsfern.DomainTakeoverFingerprint, cname string, body *string, returnsNXDomain bool, onlySuccessful bool) ([]*dnsfern.HostingService, bool) {
	var serviceResults []*dnsfern.HostingService
	successful := false
	for _, fp := range fingerprints {
		isVulnerable := isVulnerable(cname, body, returnsNXDomain, *fp)
		if onlySuccessful && !isVulnerable {
			continue
		}
		hostingServiceResult := dnsfern.HostingService{
			Name:        fp.Service,
			Vulnerable:  isVulnerable,
			Fingerprint: &fp.Fingerprint,
		}
		serviceResults = append(serviceResults, &hostingServiceResult)
		successful = successful || isVulnerable
	}
	return serviceResults, successful
}
