package dns

import (
	"testing"
)

func TestParseCrtShCertificateRecordsAllowsMissingResultCount(t *testing.T) {
	t.Parallel()

	records, err := parseCrtShCertificateRecords([]byte(`[
		{
			"issuer_ca_id": 123,
			"issuer_name": "Test CA",
			"common_name": "example.test",
			"name_value": "example.test",
			"id": 456,
			"entry_timestamp": "2026-09-10T00:00:00",
			"not_before": "2026-09-10T00:00:00",
			"not_after": "2026-12-09T00:00:00",
			"serial_number": "01"
		}
	]`))
	if err != nil {
		t.Fatalf("parse crt.sh response: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if records[0].ResultCount != 0 {
		t.Fatalf("result count = %d, want zero for an omitted field", records[0].ResultCount)
	}
	if records[0].CommonName != "example.test" {
		t.Fatalf("common name = %q, want example.test", records[0].CommonName)
	}
}

func TestParseCrtShCertificateRecordsRejectsWrongFieldTypes(t *testing.T) {
	t.Parallel()

	_, err := parseCrtShCertificateRecords([]byte(`[{"issuer_ca_id":"not-a-number"}]`))
	if err == nil {
		t.Fatal("expected a type error")
	}
}
