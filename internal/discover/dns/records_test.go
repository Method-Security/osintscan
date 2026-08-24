package dns

import (
	"reflect"
	"testing"
)

func TestNormalizeDnsxResolversTrimsAndNormalizesAddresses(t *testing.T) {
	input := []string{" 8.8.8.8 ", " tcp:1.1.1.1 ", "udp:9.9.9.9:5353 "}
	expected := []string{"udp:8.8.8.8:53", "tcp:1.1.1.1:53", "udp:9.9.9.9:5353"}

	actual := normalizeDnsxResolvers(input, false)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestNormalizeDnsxResolversForcesTCP(t *testing.T) {
	input := []string{"udp:8.8.8.8", "tcp:1.1.1.1", "9.9.9.9"}
	expected := []string{"tcp:8.8.8.8:53", "tcp:1.1.1.1:53", "tcp:9.9.9.9:53"}

	actual := normalizeDnsxResolvers(input, true)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}
