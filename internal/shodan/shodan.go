package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// UnmarshalJSON customizes the time unmarshalling
func (ct *shodanTime) UnmarshalJSON(b []byte) (err error) {
	const layout = "2006-01-02T15:04:05.999999" // Custom layout matching the JSON format
	str := string(b)
	// Remove quotes
	if str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}
	ct.Time, err = time.Parse(layout, str)
	return
}

func queryShodanHost(apiKey string, query string) ([]Record, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, query)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Capture and log any error from Close
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to query Shodan API: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var shodanResponse Response
	err = json.Unmarshal(body, &shodanResponse)
	if err != nil {
		return nil, err
	}

	var records []Record
	for _, rawMessage := range shodanResponse.Matches {
		var record Record
		err = json.Unmarshal(rawMessage, &record)
		if err != nil {
			fmt.Printf("Error unmarshaling record: %v\n", err)
		} else {
			records = append(records, record)
		}
	}

	return records, nil
}
