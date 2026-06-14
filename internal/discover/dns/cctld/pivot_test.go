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

func TestSimilarityScore(t *testing.T) {
	a := "Welcome to Acme Corporation — your trusted partner for all things widgets"
	b := "Welcome to Acme Corporation — your trusted partner for all things widgets"
	score := SimilarityScore(a, b)
	assert.InDelta(t, 1.0, score, 0.001, "identical texts should score 1.0")

	c := "Buy cheap pharmaceuticals online click here now"
	scoreLow := SimilarityScore(a, c)
	assert.Less(t, scoreLow, 0.3, "unrelated texts should score low")
}

func TestClassify_LikelyLegitAltRegion_WithBaseline(t *testing.T) {
	in := ClassificationInput{
		RegistrableLabel:     "acme",
		CertSubject:          "CN=acme.de",
		CertSANs:             []string{"acme.de", "www.acme.de"},
		SimilarityToBaseline: 0.85,
		HasBaseline:          true,
		Title:                "Acme GmbH",
		HTTPStatus:           200,
		BodyLen:              5000,
	}
	assert.Equal(t, "LIKELY_LEGIT_ALT_REGION", Classify(in))
}

func TestClassify_CertMatchBeatsLowSimilarity(t *testing.T) {
	// Cert match should classify as LIKELY_LEGIT_ALT_REGION even when the
	// content is region-localized enough that similarity to the global
	// baseline is below the old 0.7 threshold.
	in := ClassificationInput{
		RegistrableLabel:     "acme",
		CertSubject:          "CN=acme.de",
		CertSANs:             []string{"acme.de"},
		SimilarityToBaseline: 0.2,
		HasBaseline:          true,
		Title:                "Acme Deutschland",
		HTTPStatus:           200,
		BodyLen:              30000,
	}
	assert.Equal(t, "LIKELY_LEGIT_ALT_REGION", Classify(in))
}

func TestClassify_CertMatchBeatsTinyBody(t *testing.T) {
	// A short legitimate landing page (no marker title, body < 2048)
	// should NOT be PARKED if the cert matches the input brand.
	in := ClassificationInput{
		RegistrableLabel: "acme",
		CertSubject:      "CN=acme.sg",
		CertSANs:         []string{"acme.sg"},
		HTTPStatus:       200,
		BodyLen:          800,
		Title:            "",
		HasBaseline:      false,
	}
	assert.Equal(t, "LIKELY_LEGIT_ALT_REGION", Classify(in))
}

func TestClassify_LikelyImpersonation_WithBaseline(t *testing.T) {
	in := ClassificationInput{
		RegistrableLabel:     "acme",
		CertSubject:          "CN=someotherdomain.ru",
		CertSANs:             []string{"someotherdomain.ru"},
		SimilarityToBaseline: 0.72,
		HasBaseline:          true,
		Title:                "Acme Products",
		HTTPStatus:           200,
		BodyLen:              20000,
	}
	assert.Equal(t, "LIKELY_IMPERSONATION", Classify(in))
}

func TestClassify_Parked_TitleMarker(t *testing.T) {
	in := ClassificationInput{
		RegistrableLabel: "acme",
		Title:            "Domain for Sale - acme.ru",
		HTTPStatus:       200,
		BodyLen:          50000,
		HasBaseline:      false,
	}
	assert.Equal(t, "PARKED", Classify(in))
}

func TestClassify_Parked_TinyBody(t *testing.T) {
	in := ClassificationInput{
		RegistrableLabel: "acme",
		Title:            "",
		HTTPStatus:       200,
		BodyLen:          512,
		HasBaseline:      false,
	}
	assert.Equal(t, "PARKED", Classify(in))
}

func TestClassify_TinyBodyWithTitleIsNotParked(t *testing.T) {
	// Small body but a non-parking title — should NOT classify as PARKED.
	// Many regional landing pages return < 2 KB with a real title.
	in := ClassificationInput{
		RegistrableLabel: "acme",
		Title:            "Welcome to Foo",
		HTTPStatus:       200,
		BodyLen:          1500,
		HasBaseline:      false,
	}
	assert.NotEqual(t, "PARKED", Classify(in))
}

func TestClassify_Parked_NSNameserver(t *testing.T) {
	in := ClassificationInput{
		RegistrableLabel: "acme",
		Title:            "Welcome",
		HTTPStatus:       200,
		BodyLen:          50000,
		NSRecords:        []string{"ns1.sedoparking.com", "ns2.sedoparking.com"},
		HasBaseline:      false,
	}
	assert.Equal(t, "PARKED", Classify(in))
}

func TestClassify_Unrelated(t *testing.T) {
	in := ClassificationInput{
		RegistrableLabel:     "acme",
		CertSubject:          "CN=randomshop.cn",
		CertSANs:             []string{"randomshop.cn"},
		SimilarityToBaseline: 0.1,
		HasBaseline:          true,
		Title:                "Random Shop",
		HTTPStatus:           200,
		BodyLen:              50000,
	}
	assert.Equal(t, "UNRELATED", Classify(in))
}

func TestGenerateRandomLabel(t *testing.T) {
	label, err := generateRandomLabel("example.com")
	require.NoError(t, err)
	assert.Contains(t, label, ".example.com")
	assert.Greater(t, len(label), len(".example.com"))
}
