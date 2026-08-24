package utils

import (
	"testing"
)

func TestNormalizeDNSAddressTrimsWhitespace(t *testing.T) {
	expected := "8.8.8.8:53"
	actual := NormalizeDNSAddress(" 8.8.8.8 ")
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
