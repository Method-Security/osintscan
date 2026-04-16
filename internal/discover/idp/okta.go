// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package idp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	idpfern "github.com/Method-Security/osintscan/generated/go/discover/idp"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// oktaOIDCResponse is the OpenID Connect discovery document from Okta.
type oktaOIDCResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// Common subdomains that organizations use for Okta custom domains.
var oktaSubdomainPrefixes = []string{"login", "sso", "id", "auth"}

func detectOkta(ctx context.Context, client *http.Client, domain string, _ time.Duration) (*idpfern.DiscoveredIdp, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}
	details := &idpfern.OktaIdpDetails{}
	found := false

	// Method 1: Check DNS CNAMEs for common SSO subdomains pointing to Okta
	for _, prefix := range oktaSubdomainPrefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		log.Debug("Checking DNS CNAME for Okta", svc1log.SafeParam("subdomain", subdomain))

		cname, err := net.LookupCNAME(subdomain)
		if err != nil {
			continue
		}
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")

		if strings.Contains(cname, "okta.com") || strings.Contains(cname, "oktapreview.com") {
			found = true
			customDomain := subdomain
			details.CustomDomain = &customDomain
			detectionMethod := fmt.Sprintf("dns_cname:%s->%s", subdomain, cname)
			details.DetectionMethod = &detectionMethod

			// Extract org URL from CNAME
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

			oidc, err := httpGetJSON[oktaOIDCResponse](ctx, client, oidcURL)
			if err != nil {
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
				detectionMethod := fmt.Sprintf("openid_config:%s", subdomain)
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

	// Method 3: Check Azure UserRealm federation URL for Okta
	if !found {
		userRealmURL := fmt.Sprintf(userRealmURLTemplate, "user@"+domain)
		realmInfo, err := httpGetJSON[userRealmResponse](ctx, client, userRealmURL)
		if err == nil && realmInfo.AuthURL != "" {
			authURLLower := strings.ToLower(realmInfo.AuthURL)
			if strings.Contains(authURLLower, "okta.com") || strings.Contains(authURLLower, "oktapreview.com") {
				found = true
				details.OrgUrl = &realmInfo.AuthURL
				detectionMethod := "azure_userrealm_federation"
				details.DetectionMethod = &detectionMethod

				log.Info("Okta detected via Azure UserRealm federation",
					svc1log.SafeParam("auth_url", realmInfo.AuthURL))
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
