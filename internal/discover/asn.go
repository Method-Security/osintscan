package discover

import (
	"context"
	"time"

	asnfern "github.com/Method-Security/osintscan/generated/go/discover/asn"
	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetASNInfo performs comprehensive ASN information lookup using only BGPView API
func GetASNInfo(ctx context.Context, config *asnfern.DiscoverAsnConfig) (*asnfern.DiscoverAsnReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting ASN information lookup via BGPView", svc1log.SafeParam("asn", config.Asn))

	// Initialize result with the input ASN
	result := &asnfern.DiscoverAsnResult{
		Asn: config.Asn,
	}

	// Determine timeout duration
	var timeout time.Duration
	if config.Timeout != nil {
		timeout = time.Duration(*config.Timeout) * time.Second
		log.Debug("Using timeout for ASN lookup", svc1log.SafeParam("timeout_seconds", *config.Timeout))
	}

	// Get comprehensive ASN information from BGPView API
	var bgpInfo *utils.BGPViewResponse
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
		if bgpInfo.Data.Description != "" {
			result.Description = &bgpInfo.Data.Description
			log.Debug("Retrieved ASN description from BGPView", svc1log.SafeParam("description", bgpInfo.Data.Description))
		} else if bgpInfo.Data.Name != "" {
			// Fallback to name if description is empty
			result.Description = &bgpInfo.Data.Name
			log.Debug("Retrieved ASN name from BGPView", svc1log.SafeParam("name", bgpInfo.Data.Name))
		}

		// Extract country code from BGPView response
		if bgpInfo.Data.CountryCode != "" {
			result.Country = &bgpInfo.Data.CountryCode
		}

		// Extract registry and allocation information from RIR allocation
		if bgpInfo.Data.RIRAllocation != nil {
			if bgpInfo.Data.RIRAllocation.RIRName != "" {
				result.Registry = &bgpInfo.Data.RIRAllocation.RIRName
			}
			if bgpInfo.Data.RIRAllocation.DateAllocated != "" {
				result.AllocationDate = &bgpInfo.Data.RIRAllocation.DateAllocated
			}
			if bgpInfo.Data.RIRAllocation.AllocationStatus != "" {
				result.AllocationStatus = &bgpInfo.Data.RIRAllocation.AllocationStatus
			}
		}

		log.Debug("Retrieved ASN metadata from BGPView",
			svc1log.SafeParam("country", bgpInfo.Data.CountryCode),
			svc1log.SafeParam("registry", func() string {
				if bgpInfo.Data.RIRAllocation != nil {
					return bgpInfo.Data.RIRAllocation.RIRName
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
		result.Cidrs = cidrs
		log.Debug("Retrieved ASN CIDRs from BGPView", svc1log.SafeParam("cidr_count", len(cidrs)))
	}

	report := &asnfern.DiscoverAsnReport{
		Config: config,
		Result: result,
	}

	if len(errors) > 0 {
		report.Errors = errors
	}

	log.Info("Completed ASN information lookup via BGPView",
		svc1log.SafeParam("asn", config.Asn),
		svc1log.SafeParam("has_description", result.Description != nil),
		svc1log.SafeParam("has_country", result.Country != nil),
		svc1log.SafeParam("has_registry", result.Registry != nil),
		svc1log.SafeParam("cidr_count", len(result.Cidrs)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}
