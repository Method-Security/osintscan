package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	saasFern "github.com/Method-Security/osintscan/generated/go/saas"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

func Discovery(ctx context.Context, saasFingerprints saasFern.SaasFingerprintFile, ssoFingerprints saasFern.SaasFingerprintFile, config saasFern.SaasDiscoveryConfig) (*saasFern.SaasDiscoveryReport, error) {
	// Initialize report
	report := saasFern.SaasDiscoveryReport{
		Config: &config,
	}
	errors := []string{}

	// Gather fingerprints
	selectedSaasFingerprints, errs := selectFingerprints(saasFingerprints, config.SaasCompanies)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}
	selectedSsoFingerprints, errs := selectFingerprints(ssoFingerprints, config.SsoCompanies)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}
	if len(selectedSaasFingerprints.Fingerprints) == 0 {
		errors = append(errors, "no SaaS fingerprints found")
		report.Errors = errors
		return &report, nil
	}
	if len(selectedSsoFingerprints.Fingerprints) == 0 {
		errors = append(errors, "no SSO fingerprints found")
		report.Errors = errors
		return &report, nil
	}

	// Loop through each organization and fingerprint
	attempts := []*saasFern.SaasDiscoveryAttempt{}
	for _, org := range config.Orgs {
		attempt := saasFern.SaasDiscoveryAttempt{Org: org}
		companies := []*saasFern.SaasDiscoveryCompany{}
		for company, fingerprint := range selectedSaasFingerprints.Fingerprints {
			company := saasFern.SaasDiscoveryCompany{Company: company}
			requests := []*saasFern.SaasDiscoveryRequest{}
			for _, domainSlug := range fingerprint.DomainSlugs {
				// Determine the schemas to use for the request
				schemas := []string{"https"}
				if !config.HttpsOnly {
					schemas = append(schemas, "http")
				}

				// Send the request to the domain slug
				for _, schema := range schemas {
					// First try without redirect
					request, errs := handleSaasRequest(ctx, org, domainSlug, schema, &config, fingerprint, selectedSsoFingerprints)
					if len(errs) > 0 {
						errors = append(errors, errs...)
					}

					// Add request if it meets our criteria
					if shouldAddRequest(request, config.SuccessfulOnly) {
						requests = append(requests, request)
					}

				}
			}
			company.Requests = requests
			companies = append(companies, &company)
		}
		attempt.Companies = companies
		attempts = append(attempts, &attempt)
	}
	report.Orgs = attempts
	report.Errors = errors
	return &report, nil
}

// handleSaasRequest is a helper function to handle the request and analysis of the response
func handleSaasRequest(
	ctx context.Context,
	org string,
	domainSlug string,
	schema string,
	config *saasFern.SaasDiscoveryConfig,
	fingerprint *saasFern.SaasFingerprintEntry,
	selectedSsoFingerprints saasFern.SaasFingerprintFile,
) (*saasFern.SaasDiscoveryRequest, []string) {
	request, errs := sendSaasRequest(ctx, org, domainSlug, schema, config.Timeout, config.SkipTls)

	// Check if the page was redirected
	redirectedPage := false
	if len(request.RedirectChain) > 1 {
		redirectedPage = true
	}

	// Analyze the request
	finding := analyzeSaasRequest(request, fingerprint, selectedSsoFingerprints, redirectedPage)
	request.Findings = finding
	return request, errs
}

func sendSaasRequest(ctx context.Context, org string, domainSlug string, schema string, timeout int, skipTLS bool) (*saasFern.SaasDiscoveryRequest, []string) {
	// Initialize variables
	var redirectChain []string
	var errors []string

	slug := strings.Replace(domainSlug, "INPUT_ORG", org, 1)
	fullURL := fmt.Sprintf("%s://%s", schema, slug)

	request := &saasFern.SaasDiscoveryRequest{Url: fullURL}
	log.Printf("Sending request to %s", fullURL)

	// Setup browser launch options
	launch := launcher.New()
	if skipTLS {
		launch.Set("ignore-certificate-errors")
	}

	// Launch the browser
	browserURL := launch.MustLaunch()

	// Connect to browser
	browser := rod.New().ControlURL(browserURL).MustConnect()
	defer browser.MustClose()

	// Create page with context
	page := browser.MustPage()
	if timeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
		page = page.Context(timeoutCtx)
	} else {
		page = page.Context(ctx)
	}

	// Store response information
	var statusCode int
	responseHeaders := make(map[string]string)

	// Enable network events to capture responses
	page.MustEval(`() => {
        window.__redirectHistory = [];
        const originalPushState = history.pushState;
        const originalReplaceState = history.replaceState;
        
        history.pushState = function() {
            window.__redirectHistory.push(arguments[2]);
            return originalPushState.apply(this, arguments);
        };
        
        history.replaceState = function() {
            window.__redirectHistory.push(arguments[2]);
            return originalReplaceState.apply(this, arguments);
        };
    }`)

	// Setup network event capturing
	wait := page.WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)

	// Intercept requests for tracking
	router := page.HijackRequests()

	// Add this to your router's hijack function
	router.MustAdd("*", func(hijack *rod.Hijack) {
		// Record URL in redirect chain
		currentURL := hijack.Request.URL().String()

		if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != currentURL {
			redirectChain = append(redirectChain, currentURL)
		}

		hijack.ContinueRequest(&proto.FetchContinueRequest{})
	})

	go router.Run()

	// Enable network monitoring
	err := proto.NetworkEnable{}.Call(page)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error enabling network monitoring: %v", err))
		return request, errors
	}

	// Capture response received
	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		// Only capture main document response
		if e.Type == proto.NetworkResourceTypeDocument {
			statusCode = e.Response.Status

			// Process headers - assuming v is gson.JSON
			for k, v := range e.Response.Headers {
				// Use String() method on gson.JSON objects
				responseHeaders[k] = v.String()
			}

			// Check for redirect status codes
			if statusCode >= 300 && statusCode < 400 {

				// Try both "Location" and "location" keys
				locationHeader := ""

				if loc, exists := e.Response.Headers["Location"]; exists {
					locationHeader = loc.String()
				} else if loc, exists := e.Response.Headers["location"]; exists {
					locationHeader = loc.String()
				}

				// If we found a location header, add it to the redirect chain
				if locationHeader != "" && locationHeader != "null" {
					if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != locationHeader {
						redirectChain = append(redirectChain, locationHeader)
					}
				}
			}
		}
	})()

	// Navigate to URL
	err = page.Navigate(request.Url)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Navigation error: %v", err))
		return request, errors
	}

	// Wait for navigation to complete
	wait()

	// Get the final URL
	finalURL := page.MustInfo().URL
	redirectChain = append(redirectChain, finalURL)

	// Capture JavaScript-based redirects
	jsRedirectsScript := `
    const history = window.__redirectHistory || [];
    if (Array.isArray(history)) {
        const result = [];
        for (let i = 0; i < history.length; i++) {
            if (history[i]) {
                result.push(String(history[i]));
            }
        }
        return JSON.stringify(result);
    } else {
        return "[]";
    }
`

	jsRedirectsResult, err := page.Eval(jsRedirectsScript)
	if err == nil && jsRedirectsResult != nil {
		// Parse the JSON array of strings
		redirectsJSON := jsRedirectsResult.Value.String()
		if redirectsJSON != "" && redirectsJSON != "[]" {
			var redirectURLs []string
			err = json.Unmarshal([]byte(redirectsJSON), &redirectURLs)
			if err == nil {
				for _, redirectURL := range redirectURLs {
					if redirectURL != "" {
						if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != redirectURL {
							redirectChain = append(redirectChain, redirectURL)
						}
					}
				}
			}
		}
	}

	// Populate the SaasDiscoveryRequest
	request.RedirectChain = redirectChain
	request.StatusCode = &statusCode
	request.ResponseHeaders = responseHeaders

	// Get page content
	html, err := page.HTML()
	if err == nil {
		request.ResponseBody = &html
	}

	return request, errors
}
