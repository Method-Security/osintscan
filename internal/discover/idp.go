// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package discover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	idpfern "github.com/Method-Security/osintscan/generated/go/discover/idp"
	"github.com/Method-Security/pkg/httpclient"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	openIDConfigURLTemplate    = "https://login.microsoftonline.com/%s/.well-known/openid-configuration"
	userRealmURLTemplate       = "https://login.microsoftonline.com/common/userrealm/%s?api-version=2.1"
	getCredentialTypeURLString = "https://login.microsoftonline.com/common/GetCredentialType"
)

// ── Orchestrator ────────────────────────────────────────────────────────────

// DiscoverIdp probes public endpoints to identify identity providers for a domain.
func DiscoverIdp(ctx context.Context, config *idpfern.DiscoverIdpConfig) (*idpfern.DiscoverIdpReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting IdP discovery", svc1log.SafeParam("domain", config.Domain))

	timeout := 30 * time.Second
	if config.Timeout != nil {
		timeout = time.Duration(*config.Timeout) * time.Second
	}

	client := httpclient.New(httpclient.WithTimeout(timeout))

	var providers []*idpfern.DiscoveredIdp

	// Fetch UserRealm once — used by both Azure and Okta detection
	userRealmURL := fmt.Sprintf(userRealmURLTemplate, "user@"+config.Domain)
	var realmInfo azureUserRealmResponse
	var realmFetched bool
	if _, err := client.GetJSON(ctx, userRealmURL, &realmInfo); err == nil {
		realmFetched = true
	}

	// Detect Azure/Entra ID
	log.Info("Checking for Azure/Entra ID", svc1log.SafeParam("domain", config.Domain))
	azureResult, azureErrors := detectAzure(ctx, client, config.Domain, timeout, &realmInfo, realmFetched)
	errors = append(errors, azureErrors...)
	if azureResult != nil {
		providers = append(providers, azureResult)
	}

	// Detect Okta
	log.Info("Checking for Okta", svc1log.SafeParam("domain", config.Domain))
	oktaResult, oktaErrors := detectOkta(ctx, client, config.Domain, &realmInfo, realmFetched)
	errors = append(errors, oktaErrors...)
	if oktaResult != nil {
		providers = append(providers, oktaResult)
	}

	report := &idpfern.DiscoverIdpReport{
		Config: config,
		Result: &idpfern.DiscoverIdpResult{
			Providers: providers,
		},
	}

	if len(errors) > 0 {
		report.Errors = errors
	}

	log.Info("Completed IdP discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("providers_found", len(providers)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}

// ── Azure Detection ─────────────────────────────────────────────────────────

type azureOpenIDConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	TenantRegionScope     string `json:"tenant_region_scope"`
	CloudInstanceName     string `json:"cloud_instance_name"`
}

type azureUserRealmResponse struct {
	NameSpaceType       string `json:"NameSpaceType"`
	DomainName          string `json:"DomainName"`
	FederationBrandName string `json:"FederationBrandName"`
	CloudInstanceName   string `json:"CloudInstanceName"`
	AuthURL             string `json:"AuthURL"`
}

type azureGetCredentialTypeRequest struct {
	Username string `json:"username"`
}

type azureGetCredentialTypeResponse struct {
	IfExistsResult int `json:"IfExistsResult"`
	EstsProperties struct {
		DesktopSsoEnabled  *bool `json:"DesktopSsoEnabled"`
		UserTenantBranding []any `json:"UserTenantBranding"`
		IsSignupDisallowed *bool `json:"IsSignupDisallowed"`
	} `json:"EstsProperties"`
	Credentials struct {
		PrefCredential int  `json:"PrefCredential"`
		HasPassword    bool `json:"HasPassword"`
	} `json:"Credentials"`
}

func detectAzure(ctx context.Context, client *httpclient.Client, domain string, timeout time.Duration, realmInfo *azureUserRealmResponse, realmFetched bool) (*idpfern.DiscoveredIdp, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}
	details := &idpfern.AzureIdpDetails{}
	found := false

	// Step 1: Query OpenID Configuration
	openIDURL := fmt.Sprintf(openIDConfigURLTemplate, domain)
	var oidcConfig azureOpenIDConfig
	if _, err := client.GetJSON(ctx, openIDURL, &oidcConfig); err != nil {
		errors = append(errors, fmt.Sprintf("Azure OpenID query failed: %s", err.Error()))
	} else {
		found = true
		tenantID := extractAzureTenantID(oidcConfig.Issuer)
		if tenantID != "" {
			details.TenantId = &tenantID
		}
		if oidcConfig.AuthorizationEndpoint != "" {
			details.AuthorizationEndpoint = &oidcConfig.AuthorizationEndpoint
		}
		if oidcConfig.TokenEndpoint != "" {
			details.TokenEndpoint = &oidcConfig.TokenEndpoint
		}
		if oidcConfig.CloudInstanceName != "" {
			details.CloudInstanceName = &oidcConfig.CloudInstanceName
		}
		details.OpenidConfigurationUrl = &openIDURL
	}

	// Step 2: Use pre-fetched User Realm data
	// Only mark as found if NameSpaceType indicates an actual Azure tenant
	// (Microsoft returns 200 with NameSpaceType="Unknown" for non-Azure domains)
	realmIsAzure := realmFetched && (strings.EqualFold(realmInfo.NameSpaceType, "Managed") || strings.EqualFold(realmInfo.NameSpaceType, "Federated"))
	if realmIsAzure {
		found = true
		details.NamespaceType = &realmInfo.NameSpaceType
		fedStatus := mapAzureFederationStatus(realmInfo.NameSpaceType)
		details.FederationStatus = &fedStatus
		if realmInfo.FederationBrandName != "" {
			details.TenantBrandName = &realmInfo.FederationBrandName
		}
		if realmInfo.AuthURL != "" {
			details.FederationAuthUrl = &realmInfo.AuthURL
		}
	}

	if !found {
		return nil, errors
	}

	// Step 3: Query GetCredentialType (only if Azure was detected)
	credTypeInfo, err := queryAzureGetCredentialType(ctx, client, domain)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Azure GetCredentialType query failed: %s", err.Error()))
	} else {
		details.CredentialTypeInfo = credTypeInfo
	}

	// Step 4: Detect M365 services
	log.Info("Detecting M365 services", svc1log.SafeParam("domain", domain))
	details.DetectedServices = detectM365Services(ctx, domain, timeout)

	return &idpfern.DiscoveredIdp{
		Domain:   domain,
		Provider: idpfern.IdpProviderAzure,
		Azure:    details,
	}, errors
}

func queryAzureGetCredentialType(ctx context.Context, client *httpclient.Client, domain string) (*idpfern.AzureCredentialTypeInfo, error) {
	reqBody := azureGetCredentialTypeRequest{Username: "user@" + domain}

	var credType azureGetCredentialTypeResponse
	if _, err := client.PostJSON(ctx, getCredentialTypeURLString, reqBody, &credType); err != nil {
		return nil, err
	}

	prefCredType := mapPreferredCredentialType(credType.Credentials.PrefCredential)
	info := &idpfern.AzureCredentialTypeInfo{
		HasPassword:             &credType.Credentials.HasPassword,
		PreferredCredentialType: &prefCredType,
	}
	if credType.EstsProperties.DesktopSsoEnabled != nil {
		info.DesktopSsoEnabled = credType.EstsProperties.DesktopSsoEnabled
	}
	if credType.EstsProperties.IsSignupDisallowed != nil {
		info.IsSignupDisallowed = credType.EstsProperties.IsSignupDisallowed
	}
	brandingConfigured := len(credType.EstsProperties.UserTenantBranding) > 0
	info.TenantBrandingConfigured = &brandingConfigured

	return info, nil
}

func detectM365Services(ctx context.Context, domain string, timeout time.Duration) []*idpfern.DetectedM365Service {
	// Use a no-redirect client for service checks to avoid false positives
	// from generic Microsoft login redirects returning 200.
	noRedirectClient := httpclient.New(httpclient.WithTimeout(timeout), httpclient.WithMaxRedirects(0))
	var services []*idpfern.DetectedM365Service

	exchangeURL := fmt.Sprintf("https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/%s?Protocol=ActiveSync", "user@"+domain)
	if noRedirectClient.IsAlive(ctx, exchangeURL) {
		svcType := idpfern.M365ServiceTypeExchangeOnline
		services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: &exchangeURL})
	}

	for _, prefix := range extractSharePointPrefixes(domain) {
		sharePointURL := fmt.Sprintf("https://%s.sharepoint.com", prefix)
		if noRedirectClient.IsAlive(ctx, sharePointURL) {
			svcType := idpfern.M365ServiceTypeSharepointOnline
			services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: &sharePointURL})
			break
		}
	}

	teamsDetected, teamsEndpoint := checkTeamsSRV(ctx, domain, timeout)
	if teamsDetected {
		svcType := idpfern.M365ServiceTypeTeams
		services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: teamsEndpoint})
	}

	ssfbURL := fmt.Sprintf("https://lyncdiscover.%s", domain)
	if noRedirectClient.IsAlive(ctx, ssfbURL) {
		svcType := idpfern.M365ServiceTypeSsfb
		services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: &ssfbURL})
	}

	return services
}

func extractAzureTenantID(issuer string) string {
	parts := strings.Split(strings.TrimSuffix(issuer, "/"), "/")
	if len(parts) > 0 {
		candidate := parts[len(parts)-1]
		if len(candidate) == 36 && strings.Count(candidate, "-") == 4 {
			return candidate
		}
	}
	return ""
}

func mapPreferredCredentialType(prefCredential int) idpfern.PreferredCredentialType {
	switch prefCredential {
	case 1:
		return idpfern.PreferredCredentialTypePassword
	case 3:
		return idpfern.PreferredCredentialTypeFederation
	case 4:
		return idpfern.PreferredCredentialTypeFido2
	case 6:
		return idpfern.PreferredCredentialTypeWindowsHello
	case 7:
		return idpfern.PreferredCredentialTypePhoneSignIn
	default:
		return idpfern.PreferredCredentialTypeUnknown
	}
}

func mapAzureFederationStatus(namespaceType string) idpfern.FederationStatus {
	switch strings.ToLower(namespaceType) {
	case "managed":
		return idpfern.FederationStatusManaged
	case "federated":
		return idpfern.FederationStatusFederated
	default:
		return idpfern.FederationStatusUnknown
	}
}

func checkTeamsSRV(ctx context.Context, domain string, timeout time.Duration) (bool, *string) {
	resolver := &net.Resolver{}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, addrs, err := resolver.LookupSRV(dctx, "sipfederationtls", "tcp", domain)
	if err != nil || len(addrs) == 0 {
		return false, nil
	}

	target := strings.TrimSuffix(addrs[0].Target, ".")
	if strings.HasSuffix(target, "online.lync.com") {
		endpoint := fmt.Sprintf("%s:%d", target, addrs[0].Port)
		return true, &endpoint
	}

	return false, nil
}

func extractSharePointPrefixes(domain string) []string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return []string{parts[0]}
	}
	first := parts[0]
	secondToLast := parts[len(parts)-2]
	if first == secondToLast {
		return []string{first}
	}
	return []string{first, secondToLast}
}

// ── Okta Detection ──────────────────────────────────────────────────────────

type oktaOIDCResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

var oktaSubdomainPrefixes = []string{"login", "sso", "id", "auth"}

func detectOkta(ctx context.Context, client *httpclient.Client, domain string, realmInfo *azureUserRealmResponse, realmFetched bool) (*idpfern.DiscoveredIdp, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}
	details := &idpfern.OktaIdpDetails{}
	found := false

	// Method 1: Check DNS CNAMEs for common SSO subdomains pointing to Okta
	for _, prefix := range oktaSubdomainPrefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		cname, err := net.LookupCNAME(subdomain)
		if err != nil {
			continue
		}
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if strings.Contains(cname, "okta.com") || strings.Contains(cname, "oktapreview.com") {
			found = true
			customDomain := subdomain
			details.CustomDomain = &customDomain
			detectionMethod := idpfern.OktaDetectionMethodDnsCname
			details.DetectionMethod = &detectionMethod
			orgURL := fmt.Sprintf("https://%s", cname)
			details.OrgUrl = &orgURL
			log.Info("Okta detected via DNS CNAME",
				svc1log.SafeParam("subdomain", subdomain),
				svc1log.SafeParam("cname", cname))
			break
		}
	}

	// Method 2: Check OpenID Configuration on common subdomains
	if !found {
		for _, prefix := range oktaSubdomainPrefixes {
			subdomain := fmt.Sprintf("%s.%s", prefix, domain)
			oidcURL := fmt.Sprintf("https://%s/.well-known/openid-configuration", subdomain)
			var oidc oktaOIDCResponse
			if _, err := client.GetJSON(ctx, oidcURL, &oidc); err != nil {
				continue
			}
			issuer := strings.ToLower(oidc.Issuer)
			if strings.Contains(issuer, "okta.com") || strings.Contains(issuer, "oktapreview.com") {
				found = true
				details.Issuer = &oidc.Issuer
				customDomain := subdomain
				details.CustomDomain = &customDomain
				if oidc.AuthorizationEndpoint != "" {
					details.AuthorizationEndpoint = &oidc.AuthorizationEndpoint
				}
				if oidc.TokenEndpoint != "" {
					details.TokenEndpoint = &oidc.TokenEndpoint
				}
				detectionMethod := idpfern.OktaDetectionMethodOpenidConfig
				details.DetectionMethod = &detectionMethod
				orgURL := fmt.Sprintf("https://%s", subdomain)
				details.OrgUrl = &orgURL
				log.Info("Okta detected via OpenID Configuration",
					svc1log.SafeParam("subdomain", subdomain),
					svc1log.SafeParam("issuer", oidc.Issuer))
				break
			}
		}
	}

	// Method 3: Check pre-fetched Azure UserRealm federation URL for Okta
	if !found && realmFetched && realmInfo.AuthURL != "" {
		authURLLower := strings.ToLower(realmInfo.AuthURL)
		if strings.Contains(authURLLower, "okta.com") || strings.Contains(authURLLower, "oktapreview.com") {
			found = true
			details.OrgUrl = &realmInfo.AuthURL
			detectionMethod := idpfern.OktaDetectionMethodAzureUserrealmFederation
			details.DetectionMethod = &detectionMethod
			log.Info("Okta detected via Azure UserRealm federation",
				svc1log.SafeParam("auth_url", realmInfo.AuthURL))
		}
	}

	// Method 4: Reverse lookup — try {slug}.okta.com OIDC endpoint
	if !found {
		for _, slug := range generateOktaOrgSlugs(domain) {
			oktaOrgHost := fmt.Sprintf("%s.okta.com", slug)
			oidcURL := fmt.Sprintf("https://%s/.well-known/openid-configuration", oktaOrgHost)
			var oidc oktaOIDCResponse
			if _, err := client.GetJSON(ctx, oidcURL, &oidc); err != nil {
				continue
			}
			if oidc.Issuer != "" {
				found = true
				details.Issuer = &oidc.Issuer
				orgURL := fmt.Sprintf("https://%s", oktaOrgHost)
				details.OrgUrl = &orgURL
				if oidc.AuthorizationEndpoint != "" {
					details.AuthorizationEndpoint = &oidc.AuthorizationEndpoint
				}
				if oidc.TokenEndpoint != "" {
					details.TokenEndpoint = &oidc.TokenEndpoint
				}
				detectionMethod := idpfern.OktaDetectionMethodOrgSlugLookup
				details.DetectionMethod = &detectionMethod
				log.Info("Okta detected via org slug lookup",
					svc1log.SafeParam("okta_org", oktaOrgHost),
					svc1log.SafeParam("issuer", oidc.Issuer))
				break
			}
		}
	}

	if !found {
		return nil, errors
	}

	return &idpfern.DiscoveredIdp{
		Domain:   domain,
		Provider: idpfern.IdpProviderOkta,
		Okta:     details,
	}, errors
}

// generateOktaOrgSlugs produces candidate Okta org slugs from a domain.
// For "method.security" it yields: ["method-security", "methodsecurity", "method"].
// For "example.com" it yields: ["example"].
func generateOktaOrgSlugs(domain string) []string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return []string{strings.ToLower(domain)}
	}
	name := strings.ToLower(parts[0])
	tld := strings.ToLower(parts[len(parts)-1])

	seen := map[string]bool{}
	var slugs []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			slugs = append(slugs, s)
		}
	}

	// For non-traditional TLDs (not com/net/org/edu/gov/io), the TLD
	// may be part of the brand name (e.g., method.security → method-security)
	commonTLDs := map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true,
		"io": true, "co": true, "us": true, "uk": true, "ca": true,
		"au": true, "de": true, "fr": true, "jp": true, "in": true,
	}
	if !commonTLDs[tld] {
		add(name + "-" + tld)
		add(name + tld)
	}
	add(name)

	return slugs
}
