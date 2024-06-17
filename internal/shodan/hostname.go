package shodan

import (
	"context"
	"strings"
)

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

// QueryShodanHostStrictHostnameMatch queries Shodan for a given query string and ensures that the hostname contains the given hostname string.
func QueryShodanHostStrictHostnameMatch(ctx context.Context, apiKey string, query string, hostname string) (Report, error) {
	errors := []string{}

	records, err := queryShodanHost(apiKey, query)
	if err != nil {
		errors = append(errors, err.Error())
	}

	filteredRecords := filterShodanRecordsByHostname(records, hostname)

	report := Report{
		Query:         query,
		QueryType:     "QueryShodanHostStrictHostnameMatch",
		ShodanRecords: filteredRecords,
		Errors:        errors,
	}
	return report, nil
}
