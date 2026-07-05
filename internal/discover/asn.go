package discover

import (
	"context"
	"time"

	asnfern "github.com/Method-Security/osintscan/generated/go/discover/asn"
	utilsfern "github.com/Method-Security/osintscan/generated/go/utils"
	osintConfig "github.com/Method-Security/osintscan/internal/config"
	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetASNInfo performs comprehensive ASN information lookup using only BGPView API
func GetASNInfo(ctx context.Context, config *asnfern.DiscoverAsnConfig) (*asnfern.DiscoverAsnReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting ASN information lookup via BGPView", svc1log.SafeParam("asn", config.Asn))

	proxyConfig := osintConfig.ProxyConfigFromContext(ctx)
	if proxyConfig.HttpProxy != "" {
		config.HttpProxy = &proxyConfig.HttpProxy
	}
	if proxyConfig.SocksProxy != "" {
		config.SocksProxy = &proxyConfig.SocksProxy
	}

	// Initialize lookup with the input ASN
	lookup := &asnfern.DiscoverAsnLookup{
		Asn: config.Asn,
	}

	// Determine timeout duration
	var timeout time.Duration
	if config.Timeout != nil {
		timeout = time.Duration(*config.Timeout) * time.Second
		log.Debug("Using timeout for ASN lookup", svc1log.SafeParam("timeout_seconds", *config.Timeout))
	}

	// Get comprehensive ASN information from BGPView API
	var bgpInfo *utilsfern.BgpViewResponse
	var err error

	if timeout > 0 {
		bgpInfo, err = utils.GetASNInfoWithTimeout(ctx, config.Asn, timeout)
	} else {
		bgpInfo, err = utils.GetASNInfo(ctx, config.Asn)
	}

	if err != nil {
		log.Warn("Failed to get ASN info from BGPView", svc1log.SafeParam("asn", config.Asn), svc1log.SafeParam("error", err.Error()))
		errors = append(errors, "Failed to get ASN information: "+err.Error())
	} else if bgpInfo != nil && bgpInfo.Data != nil {
		// Extract description from BGPView response
		if bgpInfo.Data.DescriptionShort != "" {
			lookup.Description = &bgpInfo.Data.DescriptionShort
			log.Debug("Retrieved ASN description from BGPView", svc1log.SafeParam("description", bgpInfo.Data.DescriptionShort))
		} else if bgpInfo.Data.Name != "" {
			// Fallback to name if description is empty
			lookup.Description = &bgpInfo.Data.Name
			log.Debug("Retrieved ASN name from BGPView", svc1log.SafeParam("name", bgpInfo.Data.Name))
		}

		// Extract country code from BGPView response
		if bgpInfo.Data.CountryCode != "" {
			lookup.Country = &bgpInfo.Data.CountryCode
		}

		// Extract registry and allocation information from RIR allocation
		if bgpInfo.Data.RirAllocation != nil {
			if bgpInfo.Data.RirAllocation.RirName != "" {
				lookup.Registry = &bgpInfo.Data.RirAllocation.RirName
			}
			if bgpInfo.Data.RirAllocation.DateAllocated != "" {
				lookup.AllocationDate = &bgpInfo.Data.RirAllocation.DateAllocated
			}
			if bgpInfo.Data.RirAllocation.AllocationStatus != "" {
				lookup.AllocationStatus = &bgpInfo.Data.RirAllocation.AllocationStatus
			}
		}

		log.Debug("Retrieved ASN metadata from BGPView",
			svc1log.SafeParam("country", bgpInfo.Data.CountryCode),
			svc1log.SafeParam("registry", func() string {
				if bgpInfo.Data.RirAllocation != nil {
					return bgpInfo.Data.RirAllocation.RirName
				}
				return ""
			}()))
	}

	// Get CIDR prefixes from BGPView API
	var cidrs []string
	if timeout > 0 {
		cidrs, err = utils.GetASNCIDRsWithTimeout(ctx, config.Asn, timeout)
	} else {
		cidrs, err = utils.GetASNCIDRs(ctx, config.Asn)
	}

	if err != nil {
		log.Warn("Failed to get ASN CIDRs from BGPView", svc1log.SafeParam("asn", config.Asn), svc1log.SafeParam("error", err.Error()))
		errors = append(errors, "Failed to get ASN CIDRs: "+err.Error())
	} else if len(cidrs) > 0 {
		lookup.Cidrs = cidrs
		log.Debug("Retrieved ASN CIDRs from BGPView", svc1log.SafeParam("cidr_count", len(cidrs)))
	}

	report := &asnfern.DiscoverAsnReport{
		Config: config,
		Result: &asnfern.DiscoverAsnResult{
			Lookup: lookup,
		},
	}

	if len(errors) > 0 {
		report.Errors = errors
	}

	log.Info("Completed ASN information lookup via BGPView",
		svc1log.SafeParam("asn", config.Asn),
		svc1log.SafeParam("has_description", lookup.Description != nil),
		svc1log.SafeParam("has_country", lookup.Country != nil),
		svc1log.SafeParam("has_registry", lookup.Registry != nil),
		svc1log.SafeParam("cidr_count", len(lookup.Cidrs)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}
