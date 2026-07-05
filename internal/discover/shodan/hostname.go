package shodan

import (
	"context"
	"strings"

	osintConfig "github.com/Method-Security/osintscan/internal/config"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// filterShodanRecordsByHostname filters Shodan records to only those with a hostname ending in endString.
func filterShodanRecordsByHostname(records []Record, endString string) []Record {
	if endString == "" {
		return records
	}

	var filteredRecords []Record
	for _, record := range records {
		for _, hostname := range record.Hostnames {
			if strings.HasSuffix(hostname, endString) {
				filteredRecords = append(filteredRecords, record)
				break
			}
		}
	}
	return filteredRecords
}

// QueryShodanHostStrictHostnameMatch queries Shodan for a given query string and filters results to hostnames ending with the given string.
// Returns a report containing the filtered records and any errors encountered.
func QueryShodanHostStrictHostnameMatch(ctx context.Context, apiKey string, query string, hostname string) (Report, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Starting Shodan hostname query",
		svc1log.SafeParam("query", query),
		svc1log.SafeParam("hostname_filter", hostname))

	records, unmarshalErrors, err := queryShodanHost(ctx, apiKey, query)
	if err != nil {
		log.Warn("Shodan query failed",
			svc1log.SafeParam("query", query),
			svc1log.SafeParam("error", err.Error()))
		errors = append(errors, err.Error())
	}
	if len(unmarshalErrors) > 0 {
		errors = append(errors, unmarshalErrors...)
	}

	filteredRecords := filterShodanRecordsByHostname(records, hostname)

	proxyConfig := osintConfig.ProxyConfigFromContext(ctx)
	report := Report{
		Query:         query,
		QueryType:     "QueryShodanHostStrictHostnameMatch",
		ShodanRecords: filteredRecords,
		Errors:        errors,
	}
	if proxyConfig.HttpProxy != "" {
		report.HttpProxy = &proxyConfig.HttpProxy
	}
	if proxyConfig.SocksProxy != "" {
		report.SocksProxy = &proxyConfig.SocksProxy
	}

	log.Info("Completed Shodan hostname query",
		svc1log.SafeParam("query", query),
		svc1log.SafeParam("total_records", len(records)),
		svc1log.SafeParam("filtered_records", len(filteredRecords)),
		svc1log.SafeParam("error_count", len(errors)))

	return report, nil
}
