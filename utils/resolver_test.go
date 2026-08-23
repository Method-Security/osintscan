package utils

import (
	"reflect"
	"testing"
)

func TestTrimDNSServerAddresses(t *testing.T) {
	input := []string{" 8.8.8.8", "1.1.1.1 ", " 9.9.9.9:53 ", ""}
	expected := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9:53", ""}

	actual := TrimDNSServerAddresses(input)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestNormalizeDNSAddressTrimsWhitespace(t *testing.T) {
	expected := "8.8.8.8:53"
	actual := NormalizeDNSAddress(" 8.8.8.8 ")
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
