package cctld

import (
	"strings"
	"testing"
)

func TestRegistrableLabelAndApex(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantLabel string
		wantApex  string
		wantErr   bool
	}{
		{"apex domain", "acme.com", "acme", "acme.com", false},
		{"subdomain", "mail.acme.com", "acme", "acme.com", false},
		{"deep subdomain", "shop.eu.acme.com", "acme", "acme.com", false},
		{"multi-label suffix", "acme.co.uk", "acme", "acme.co.uk", false},
		{"deep multi-label suffix", "shop.acme.co.uk", "acme", "acme.co.uk", false},
		{"ccTLD apex", "acme.ru", "acme", "acme.ru", false},
		{"subdomain under ccTLD", "mail.acme.ru", "acme", "acme.ru", false},
		{"uppercase", "ACME.COM", "acme", "acme.com", false},
		{"trailing dot", "acme.com.", "acme", "acme.com", false},
		{"bare label", "acme", "acme", "", false},
		{"with whitespace", "  acme.com  ", "acme", "acme.com", false},
		{"empty", "", "", "", true},
		{"whitespace only", "   ", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label, apex, err := registrableLabelAndApex(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("registrableLabelAndApex(%q) err = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if label != tc.wantLabel {
				t.Fatalf("registrableLabelAndApex(%q) label = %q, want %q", tc.input, label, tc.wantLabel)
			}
			if apex != tc.wantApex {
				t.Fatalf("registrableLabelAndApex(%q) apex = %q, want %q", tc.input, apex, tc.wantApex)
			}
		})
	}
}

func TestNormalizeCctldList(t *testing.T) {
	t.Run("dedupes and lowercases", func(t *testing.T) {
		got := normalizeCctldList([]string{"RU", "ru", "CN", "cn", "ir"})
		want := []string{"ru", "cn", "ir"}
		if !sliceEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("strips leading dot", func(t *testing.T) {
		got := normalizeCctldList([]string{".ru", ".cn"})
		want := []string{"ru", "cn"}
		if !sliceEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		got := normalizeCctldList([]string{"  ru  ", "\tcn\n"})
		want := []string{"ru", "cn"}
		if !sliceEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("skips empty entries", func(t *testing.T) {
		got := normalizeCctldList([]string{"ru", "", "cn", "   "})
		want := []string{"ru", "cn"}
		if !sliceEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("empty input falls back to defaults", func(t *testing.T) {
		got := normalizeCctldList(nil)
		if len(got) == 0 {
			t.Fatalf("expected default list, got empty")
		}
		// Default list should contain the APT-relevant baseline.
		seen := map[string]bool{}
		for _, cc := range got {
			seen[cc] = true
		}
		for _, mustHave := range []string{"ru", "cn", "ir", "kp", "by", "su"} {
			if !seen[mustHave] {
				t.Errorf("default ccTLD list missing %q", mustHave)
			}
		}
		// Default list must also contain the IDN punycode siblings.
		for _, mustHave := range []string{"xn--p1ai", "xn--fiqs8s", "xn--mgba3a4f16a"} {
			if !seen[mustHave] {
				t.Errorf("default ccTLD list missing IDN punycode %q", mustHave)
			}
		}
	})

	t.Run("all-empty input falls back to defaults", func(t *testing.T) {
		got := normalizeCctldList([]string{"", "   ", "\t"})
		if len(got) == 0 {
			t.Fatalf("expected default list, got empty")
		}
	})
}

func TestDefaultCcTldsIsValid(t *testing.T) {
	if len(DefaultCcTlds) == 0 {
		t.Fatal("DefaultCcTlds must not be empty")
	}
	seen := map[string]bool{}
	for _, cc := range DefaultCcTlds {
		if cc == "" {
			t.Errorf("DefaultCcTlds contains empty string")
		}
		if strings.HasPrefix(cc, ".") {
			t.Errorf("DefaultCcTlds entry %q has leading dot", cc)
		}
		if strings.ToLower(cc) != cc {
			t.Errorf("DefaultCcTlds entry %q is not lowercase", cc)
		}
		if seen[cc] {
			t.Errorf("DefaultCcTlds contains duplicate %q", cc)
		}
		seen[cc] = true
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
