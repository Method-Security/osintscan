package cctld

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLDsForPreset(t *testing.T) {
	for _, preset := range []string{"APT_RELEVANT", "TOP50", "EU27", "ASEAN", "ALL"} {
		t.Run(preset, func(t *testing.T) {
			tlds, err := TLDsForPreset(preset)
			require.NoError(t, err, "preset %s should load without error", preset)
			assert.NotEmpty(t, tlds, "preset %s should have at least one TLD", preset)
		})
	}
}

func TestTLDsForPresetUnknown(t *testing.T) {
	_, err := TLDsForPreset("NONEXISTENT")
	assert.Error(t, err)
}

func TestGenerateRandomLabel(t *testing.T) {
	label, err := generateRandomLabel("example.com")
	require.NoError(t, err)
	assert.Contains(t, label, ".example.com")
	assert.Greater(t, len(label), len(".example.com"))
}
