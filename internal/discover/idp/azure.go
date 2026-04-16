// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	idpfern "github.com/Method-Security/osintscan/generated/go/discover/idp"
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

func detectAzure(ctx context.Context, client *http.Client, domain string, timeout time.Duration) (*idpfern.DiscoveredIdp, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}
	details := &idpfern.AzureIdpDetails{}
	found := false

	// Step 1: Query OpenID Configuration
	openIDURL := fmt.Sprintf(openIDConfigURLTemplate, domain)
	oidcConfig, err := httpGetJSON[openIDConfig](ctx, client, openIDURL)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Azure OpenID query failed: %s", err.Error()))
	} else {
		found = true
		tenantID := extractTenantID(oidcConfig.Issuer)
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

	// Step 2: Query User Realm
	userRealmURL := fmt.Sprintf(userRealmURLTemplate, "user@"+domain)
	realmInfo, err := httpGetJSON[userRealmResponse](ctx, client, userRealmURL)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Azure UserRealm query failed: %s", err.Error()))
	} else {
		found = true
		if realmInfo.NameSpaceType != "" {
			details.NamespaceType = &realmInfo.NameSpaceType
			fedStatus := mapFederationStatus(realmInfo.NameSpaceType)
			details.FederationStatus = &fedStatus
		}
		if realmInfo.FederationBrandName != "" {
			details.TenantBrandName = &realmInfo.FederationBrandName
		}
		if realmInfo.AuthURL != "" {
			details.FederationAuthUrl = &realmInfo.AuthURL
		}
	}

	// Step 3: Query GetCredentialType
	credTypeInfo, err := queryGetCredentialType(ctx, client, domain)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Azure GetCredentialType query failed: %s", err.Error()))
	} else {
		details.CredentialTypeInfo = credTypeInfo
	}

	// Step 4: Detect M365 services
	log.Info("Detecting M365 services", svc1log.SafeParam("domain", domain))
	details.DetectedServices = detectM365Services(ctx, client, domain, timeout)

	if !found {
		return nil, errors
	}

	return &idpfern.DiscoveredIdp{
		Domain:   domain,
		Provider: idpfern.IdpProviderAzure,
		Azure:    details,
	}, errors
}

func queryGetCredentialType(ctx context.Context, client *http.Client, domain string) (*idpfern.AzureCredentialTypeInfo, error) {
	reqBody := getCredentialTypeRequest{Username: "user@" + domain}
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
	defer func() { _ = resp.Body.Close() }()

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

	info := &idpfern.AzureCredentialTypeInfo{
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

func detectM365Services(ctx context.Context, client *http.Client, domain string, timeout time.Duration) []*idpfern.DetectedM365Service {
	var services []*idpfern.DetectedM365Service

	// Exchange Online
	exchangeURL := fmt.Sprintf("https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/%s?Protocol=ActiveSync", "user@"+domain)
	if checkEndpoint(ctx, client, exchangeURL) {
		svcType := idpfern.M365ServiceTypeExchangeOnline
		services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: &exchangeURL})
	}

	// SharePoint Online
	for _, prefix := range extractSharePointPrefixes(domain) {
		sharePointURL := fmt.Sprintf("https://%s.sharepoint.com", prefix)
		if checkEndpoint(ctx, client, sharePointURL) {
			svcType := idpfern.M365ServiceTypeSharepointOnline
			services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: &sharePointURL})
			break
		}
	}

	// Teams via SRV
	teamsDetected, teamsEndpoint := checkTeamsSRV(ctx, domain, timeout)
	if teamsDetected {
		svcType := idpfern.M365ServiceTypeTeams
		services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: teamsEndpoint})
	}

	// Skype for Business
	ssfbURL := fmt.Sprintf("https://lyncdiscover.%s", domain)
	if checkEndpoint(ctx, client, ssfbURL) {
		svcType := idpfern.M365ServiceTypeSsfb
		services = append(services, &idpfern.DetectedM365Service{ServiceType: svcType, Endpoint: &ssfbURL})
	}

	return services
}

func extractTenantID(issuer string) string {
	parts := strings.Split(strings.TrimSuffix(issuer, "/"), "/")
	if len(parts) > 0 {
		candidate := parts[len(parts)-1]
		if len(candidate) == 36 && strings.Count(candidate, "-") == 4 {
			return candidate
		}
	}
	return ""
}

func mapFederationStatus(namespaceType string) idpfern.FederationStatus {
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
	if len(parts) <= 1 {
		return parts
	}
	if len(parts) == 2 {
		return []string{parts[0]}
	}
	candidates := []string{parts[len(parts)-2]}
	if parts[0] != candidates[0] {
		candidates = append(candidates, parts[0])
	}
	return candidates
}
