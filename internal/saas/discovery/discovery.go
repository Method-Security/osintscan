package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
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

// handleSaasRequest handles a single SaaS request
func handleSaasRequest(
	ctx context.Context,
	org string,
	domainSlug string,
	schema string,
	config *saasFern.SaasDiscoveryConfig,
	fingerprint *saasFern.SaasFingerprintEntry,
	selectedSsoFingerprints saasFern.SaasFingerprintFile,
) (*saasFern.SaasDiscoveryRequest, []string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()

	// Use channels to communicate results and errors
	requestCh := make(chan *saasFern.SaasDiscoveryRequest, 1)
	errsCh := make(chan []string, 1)
	panicCh := make(chan interface{}, 1)

	// Run the request in a goroutine with panic recovery
	go func() {
		// Recover from any panics
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()

		// Execute the request
		req, errs := sendSaasRequest(timeoutCtx, org, domainSlug, schema, config.Timeout, config.BrowserPath, config.SkipTls)

		// Check if the context has already expired before we try to process further
		if timeoutCtx.Err() != nil {
			errsCh <- []string{"request processing interrupted: " + timeoutCtx.Err().Error()}
			requestCh <- nil
			return
		}

		// If we have a successful request, process it
		if req != nil {
			redirectedPage := false
			if len(req.RedirectChain) > 1 {
				redirectedPage = true
			}

			// Analyze the request (with timeout context to ensure this can be interrupted)
			finding := analyzeSaasRequest(req, fingerprint, selectedSsoFingerprints, redirectedPage)
			req.Findings = finding
		}

		// Send results to channels
		requestCh <- req
		errsCh <- errs
	}()

	// Wait for either completion, timeout, or panic
	select {
	case <-timeoutCtx.Done():
		log.Printf("[ERROR] Request timed out after %v seconds", config.Timeout)
		return nil, []string{"request timed out after " + strconv.Itoa(config.Timeout) + " seconds"}
	case p := <-panicCh:
		log.Printf("[ERROR] Request panicked with: %v", p)
		return nil, []string{"request failed with internal error"}
	case request := <-requestCh:
		errs := <-errsCh
		return request, errs
	}
}

func sendSaasRequest(ctx context.Context, org string, domainSlug string, schema string, timeout int, browserPath *string, skipTLS bool) (*saasFern.SaasDiscoveryRequest, []string) {
	// Initialize variables
	var redirectChain []string
	var errors []string

	slug := strings.Replace(domainSlug, "INPUT_ORG", org, 1)
	fullURL := fmt.Sprintf("%s://%s", schema, slug)

	request := &saasFern.SaasDiscoveryRequest{Url: fullURL}
	log.Printf("Sending request to %s", fullURL)

	// Setup browser launch options
	var launch *launcher.Launcher
	if browserPath != nil && *browserPath != "" {
		launch = launcher.New().Headless(true).Bin(*browserPath)
	} else {
		launch = launcher.New().Headless(true)
	}
	if skipTLS {
		launch.Set("ignore-certificate-errors")
	}

	// Launch the browser with timeout
	browserURL, err := launch.Launch()
	if err != nil {
		log.Printf("[ERROR] Failed to launch browser: %v", err)
		errors = append(errors, fmt.Sprintf("Failed to launch browser: %v", err))
		return request, errors
	}

	// Connect to browser with timeout
	browser := rod.New().ControlURL(browserURL)
	if err := browser.Connect(); err != nil {
		log.Printf("[ERROR] Failed to connect to browser: %v", err)
		errors = append(errors, fmt.Sprintf("Failed to connect to browser: %v", err))
		return request, errors
	}
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

	// Setup network event capturing with timeout
	wait := page.WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
	waitCtx, waitCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer waitCancel()

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
	err = proto.NetworkEnable{}.Call(page)
	if err != nil {
		log.Printf("[ERROR] Error enabling network monitoring: %v", err)
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

	// Navigate to URL with timeout
	err = page.Navigate(request.Url)
	if err != nil {
		log.Printf("[ERROR] Navigation error: %v", err)
		errors = append(errors, fmt.Sprintf("Navigation error: %v", err))
		return request, errors
	}

	// Wait for navigation to complete with timeout
	select {
	case <-waitCtx.Done():
		log.Printf("[ERROR] Navigation timeout reached")
		errors = append(errors, "Navigation timeout reached")
		return request, errors
	default:
		wait()
	}

	// Get the final URL
	finalURL := page.MustInfo().URL
	redirectChain = append(redirectChain, finalURL)

	// Capture JavaScript-based redirects with timeout
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
