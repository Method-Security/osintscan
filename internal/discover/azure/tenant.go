package azure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	azurefern "github.com/Method-Security/osintscan/generated/go/discover/azure"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	openIDConfigURLTemplate    = "https://login.microsoftonline.com/%s/.well-known/openid-configuration"
	userRealmURLTemplate       = "https://login.microsoftonline.com/common/userrealm/%s?api-version=2.1"
	getCredentialTypeURLString = "https://login.microsoftonline.com/common/GetCredentialType"
)

type openIDConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	TenantRegionScope     string `json:"tenant_region_scope"`
	CloudInstanceName     string `json:"cloud_instance_name"`
}

type userRealmResponse struct {
	NameSpaceType       string `json:"NameSpaceType"`
	DomainName          string `json:"DomainName"`
	FederationBrandName string `json:"FederationBrandName"`
	CloudInstanceName   string `json:"CloudInstanceName"`
	AuthURL             string `json:"AuthURL"`
}

type getCredentialTypeRequest struct {
	Username string `json:"username"`
}

type getCredentialTypeResponse struct {
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

func DiscoverAzureTenant(ctx context.Context, config *azurefern.DiscoverAzureTenantConfig) (*azurefern.DiscoverAzureTenantReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting Azure tenant discovery", svc1log.SafeParam("domain", config.Domain))

	timeout := 30 * time.Second
	if config.Timeout != nil {
		timeout = time.Duration(*config.Timeout) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	tenantInfo := &azurefern.AzureTenantInfo{
		Domain: config.Domain,
	}

	// Step 1: Query OpenID Configuration to get tenant ID and endpoints
	openIDURL := fmt.Sprintf(openIDConfigURLTemplate, config.Domain)
	log.Info("Querying OpenID configuration", svc1log.SafeParam("url", openIDURL))

	oidcConfig, err := queryOpenIDConfig(ctx, client, openIDURL)
	if err != nil {
		log.Warn("Failed to query OpenID configuration", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, fmt.Sprintf("OpenID configuration query failed: %s", err.Error()))
	} else {
		// Extract tenant ID from issuer URL
		tenantID := extractTenantID(oidcConfig.Issuer)
		if tenantID != "" {
			tenantInfo.TenantId = &tenantID
		}
		if oidcConfig.AuthorizationEndpoint != "" {
			tenantInfo.AuthorizationEndpoint = &oidcConfig.AuthorizationEndpoint
		}
		if oidcConfig.TokenEndpoint != "" {
			tenantInfo.TokenEndpoint = &oidcConfig.TokenEndpoint
		}
		if oidcConfig.CloudInstanceName != "" {
			tenantInfo.CloudInstanceName = &oidcConfig.CloudInstanceName
		}
		tenantInfo.OpenidConfigurationUrl = &openIDURL
	}

	// Step 2: Query User Realm to get federation status and brand name
	userRealmURL := fmt.Sprintf(userRealmURLTemplate, "user@"+config.Domain)
	log.Info("Querying user realm", svc1log.SafeParam("url", userRealmURL))

	realmInfo, err := queryUserRealm(ctx, client, userRealmURL)
	if err != nil {
		log.Warn("Failed to query user realm", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, fmt.Sprintf("User realm query failed: %s", err.Error()))
	} else {
		if realmInfo.NameSpaceType != "" {
			tenantInfo.NamespaceType = &realmInfo.NameSpaceType
			fedStatus := mapFederationStatus(realmInfo.NameSpaceType)
			tenantInfo.FederationStatus = &fedStatus
		}
		if realmInfo.FederationBrandName != "" {
			tenantInfo.TenantBrandName = &realmInfo.FederationBrandName
		}
		if realmInfo.AuthURL != "" {
			tenantInfo.FederationAuthUrl = &realmInfo.AuthURL
		}
	}

	// Step 3: Query GetCredentialType for auth configuration
	log.Info("Querying GetCredentialType", svc1log.SafeParam("domain", config.Domain))

	credTypeInfo, err := queryGetCredentialType(ctx, client, config.Domain)
	if err != nil {
		log.Warn("Failed to query GetCredentialType", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, fmt.Sprintf("GetCredentialType query failed: %s", err.Error()))
	} else {
		tenantInfo.CredentialTypeInfo = credTypeInfo
	}

	// Step 4: Detect M365 services
	log.Info("Detecting M365 services", svc1log.SafeParam("domain", config.Domain))
	tenantInfo.DetectedServices = detectM365Services(ctx, client, config.Domain, timeout)

	// Build report - only include tenant if we found meaningful data
	report := &azurefern.DiscoverAzureTenantReport{
		Config: config,
		Result: &azurefern.DiscoverAzureTenantResult{},
	}

	if tenantInfo.TenantId != nil || tenantInfo.FederationStatus != nil || tenantInfo.CredentialTypeInfo != nil || len(tenantInfo.DetectedServices) > 0 {
		report.Result.Tenant = tenantInfo
	}

	if len(errors) > 0 {
		report.Errors = errors
	}

	log.Info("Completed Azure tenant discovery",
		svc1log.SafeParam("domain", config.Domain),
		svc1log.SafeParam("has_tenant_id", tenantInfo.TenantId != nil),
		svc1log.SafeParam("services_detected", len(tenantInfo.DetectedServices)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}

func queryOpenIDConfig(ctx context.Context, client *http.Client, url string) (*openIDConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var config openIDConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &config, nil
}

func queryUserRealm(ctx context.Context, client *http.Client, url string) (*userRealmResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var realm userRealmResponse
	if err := json.Unmarshal(body, &realm); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &realm, nil
}

func queryGetCredentialType(ctx context.Context, client *http.Client, domain string) (*azurefern.CredentialTypeInfo, error) {
	reqBody := getCredentialTypeRequest{
		Username: "user@" + domain,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, getCredentialTypeURLString, strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var credType getCredentialTypeResponse
	if err := json.Unmarshal(body, &credType); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	info := &azurefern.CredentialTypeInfo{
		HasPassword:    &credType.Credentials.HasPassword,
		PrefCredential: &credType.Credentials.PrefCredential,
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

func extractTenantID(issuer string) string {
	// Issuer URL format: https://sts.windows.net/{tenant-id}/
	parts := strings.Split(strings.TrimSuffix(issuer, "/"), "/")
	if len(parts) > 0 {
		candidate := parts[len(parts)-1]
		// Basic UUID validation (8-4-4-4-12 format)
		if len(candidate) == 36 && strings.Count(candidate, "-") == 4 {
			return candidate
		}
	}
	return ""
}

func mapFederationStatus(namespaceType string) azurefern.FederationStatus {
	switch strings.ToLower(namespaceType) {
	case "managed":
		return azurefern.FederationStatusManaged
	case "federated":
		return azurefern.FederationStatusFederated
	default:
		return azurefern.FederationStatusUnknown
	}
}

func detectM365Services(ctx context.Context, client *http.Client, domain string, timeout time.Duration) []*azurefern.DetectedM365Service {
	var services []*azurefern.DetectedM365Service

	// Check Exchange Online via autodiscover
	exchangeURL := fmt.Sprintf("https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/%s?Protocol=ActiveSync", "user@"+domain)
	if checkEndpoint(ctx, client, exchangeURL) {
		svcType := azurefern.M365ServiceTypeExchangeOnline
		services = append(services, &azurefern.DetectedM365Service{
			ServiceType: svcType,
			Endpoint:    &exchangeURL,
		})
	}

	// Check SharePoint Online - try candidate prefixes
	for _, prefix := range extractSharePointPrefixes(domain) {
		sharePointURL := fmt.Sprintf("https://%s.sharepoint.com", prefix)
		if checkEndpoint(ctx, client, sharePointURL) {
			svcType := azurefern.M365ServiceTypeSharepointOnline
			services = append(services, &azurefern.DetectedM365Service{
				ServiceType: svcType,
				Endpoint:    &sharePointURL,
			})
			break
		}
	}

	// Check Teams/Skype for Business via DNS SRV
	teamsDetected, teamsEndpoint := checkTeamsSRV(ctx, domain, timeout)
	if teamsDetected {
		svcType := azurefern.M365ServiceTypeTeams
		services = append(services, &azurefern.DetectedM365Service{
			ServiceType: svcType,
			Endpoint:    teamsEndpoint,
		})
	}

	// Check Skype for Business via lyncdiscover
	ssfbURL := fmt.Sprintf("https://lyncdiscover.%s", domain)
	if checkEndpoint(ctx, client, ssfbURL) {
		svcType := azurefern.M365ServiceTypeSsfb
		services = append(services, &azurefern.DetectedM365Service{
			ServiceType: svcType,
			Endpoint:    &ssfbURL,
		})
	}

	return services
}

func checkEndpoint(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// A non-404 response generally indicates the service exists
	// 200, 301, 302, 401, 403 all indicate the endpoint is live
	return resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadGateway
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
	// Return candidate SharePoint tenant prefixes to try.
	// SharePoint URLs are typically https://<orgname>.sharepoint.com
	// For "contoso.com" -> ["contoso"]
	// For "mail.contoso.com" -> ["contoso", "mail"] (try org name first)
	// For "contoso.co.uk" -> ["contoso"]
	parts := strings.Split(domain, ".")
	if len(parts) <= 1 {
		return parts
	}
	if len(parts) == 2 {
		return []string{parts[0]}
	}
	// For 3+ parts, the second-to-last is likely the org name
	// (handles both "sub.example.com" and "example.co.uk")
	// Try it first, then fall back to the first label
	candidates := []string{parts[len(parts)-2]}
	if parts[0] != candidates[0] {
		candidates = append(candidates, parts[0])
	}
	return candidates
}
