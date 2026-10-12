package dns

import (
	"testing"
)

func TestParseCrtShCertificateRecordsAllowsMissingOptionalFieldsAcrossRecords(t *testing.T) {
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
			"serial_number": "01",
			"result_count": 2
		},
		{
			"issuer_ca_id": 124,
			"issuer_name": "Test CA 2",
			"common_name": "www.example.test",
			"name_value": "example.test\nwww.example.test",
			"id": 457,
			"not_before": "2026-09-11T00:00:00",
			"not_after": "2026-12-10T00:00:00",
			"serial_number": "02",
			"result_count": 2
		},
		{
			"issuer_ca_id": -1,
			"issuer_name": "Issuer Not Found",
			"common_name": "legacy.example.test",
			"name_value": "legacy.example.test",
			"id": 458,
			"entry_timestamp": "2026-09-12T00:00:00",
			"not_before": "2026-09-12T00:00:00",
			"not_after": "2026-12-11T00:00:00",
			"serial_number": "03"
		}
	]`))
	if err != nil {
		t.Fatalf("parse crt.sh response: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("record count = %d, want 3", len(records))
	}
	if records[0].ResultCount != 2 || records[0].EntryTimestamp != "2026-09-10T00:00:00" {
		t.Fatalf("full record was not preserved: %#v", records[0])
	}
	if records[1].EntryTimestamp != "" {
		t.Fatalf("entry timestamp = %q, want zero value for an omitted field", records[1].EntryTimestamp)
	}
	if records[1].NameValue != "example.test\nwww.example.test" {
		t.Fatalf("name value = %q, want multiline SAN value", records[1].NameValue)
	}
	if records[2].ResultCount != 0 {
		t.Fatalf("result count = %d, want zero value for an omitted field", records[2].ResultCount)
	}
	if records[2].IssuerCaid != -1 {
		t.Fatalf("issuer CA ID = %d, want -1", records[2].IssuerCaid)
	}
}

func TestParseCrtShCertificateRecordsRejectsWrongFieldTypes(t *testing.T) {
	t.Parallel()

	_, err := parseCrtShCertificateRecords([]byte(`[{"issuer_ca_id":"not-a-number"}]`))
	if err == nil {
		t.Fatal("expected a type error")
	}
}
