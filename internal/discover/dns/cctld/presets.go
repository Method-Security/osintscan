package cctld

import (
	"encoding/json"
	"fmt"

	"github.com/Method-Security/osintscan/configs"
)

// presetPath maps preset names (uppercase) to their embedded config file paths.
var presetPath = map[string]string{
	"APT_RELEVANT": "discover/dns/cctld/apt-relevant.json",
	"TOP50":        "discover/dns/cctld/top50.json",
	"EU27":         "discover/dns/cctld/eu27.json",
	"ASEAN":        "discover/dns/cctld/asean.json",
	"ALL":          "discover/dns/cctld/all.json",
}

// TLDsForPreset returns the list of TLD labels for the named preset.
// presetName must be one of: APT_RELEVANT, TOP50, EU27, ASEAN, ALL (case-insensitive).
func TLDsForPreset(presetName string) ([]string, error) {
	path, ok := presetPath[presetName]
	if !ok {
		return nil, fmt.Errorf("unknown ccTLD preset %q; valid values: APT_RELEVANT, TOP50, EU27, ASEAN, ALL", presetName)
	}
	data, err := configs.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read preset %q: %w", presetName, err)
	}
	var tlds []string
	if err := json.Unmarshal(data, &tlds); err != nil {
		return nil, fmt.Errorf("malformed preset file %q: %w", presetName, err)
	}
	return tlds, nil
}
