package shodan

import (
	"context"
	"strings"
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
