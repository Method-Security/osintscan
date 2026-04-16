// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package idp

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	idpfern "github.com/Method-Security/osintscan/generated/go/discover/idp"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// DiscoverIdp probes public endpoints to identify identity providers for a domain.
func DiscoverIdp(ctx context.Context, config *idpfern.DiscoverIdpConfig) (*idpfern.DiscoverIdpReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting IdP discovery", svc1log.SafeParam("domain", config.Domain))

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

	var providers []*idpfern.DiscoveredIdp

	// Detect Azure/Entra ID
	log.Info("Checking for Azure/Entra ID", svc1log.SafeParam("domain", config.Domain))
	azureResult, azureErrors := detectAzure(ctx, client, config.Domain, timeout)
	errors = append(errors, azureErrors...)
	if azureResult != nil {
		providers = append(providers, azureResult)
	}

	// Detect Okta
	log.Info("Checking for Okta", svc1log.SafeParam("domain", config.Domain))
	oktaResult, oktaErrors := detectOkta(ctx, client, config.Domain, timeout)
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
