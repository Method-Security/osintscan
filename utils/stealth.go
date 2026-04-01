package utils

import (
	"math/rand"
	"time"
)

// CalculateDelayWithJitter calculates sleep duration with optional jitter.
// baseDelaySeconds: base delay in seconds
// jitterPercent: jitter percentage (0-100) to apply random variance
// Returns: final delay duration with jitter applied
func CalculateDelayWithJitter(baseDelaySeconds int, jitterPercent int) time.Duration {
	if baseDelaySeconds <= 0 {
		return 0
	}

	baseDelay := time.Duration(baseDelaySeconds) * time.Second

	// Apply jitter if specified and valid
	if jitterPercent > 0 && jitterPercent <= 100 {
		// Calculate jitter amount (percentage of base delay)
		jitterAmount := float64(baseDelay.Nanoseconds()) * (float64(jitterPercent) / 100.0)

		// Generate random jitter between -jitterAmount and +jitterAmount
		randomJitter := (rand.Float64()*2 - 1) * jitterAmount

		// Apply jitter to base delay
		finalDelay := time.Duration(float64(baseDelay.Nanoseconds()) + randomJitter)

		// Ensure delay is not negative
		if finalDelay < 0 {
			finalDelay = 0
		}

		return finalDelay
	}

	return baseDelay
}

// CalculateStealthDelay calculates a delay with jitter from optional sleep and jitter parameters.
// This is a convenience function that handles nil pointer checks.
// sleepPtr: optional pointer to sleep delay in seconds (can be nil)
// jitterPtr: optional pointer to jitter percentage 0-100 (can be nil)
// Returns: final delay duration with jitter applied, or 0 if no sleep specified
func CalculateStealthDelay(sleepPtr *int, jitterPtr *int) time.Duration {
	// If no sleep specified, return no delay
	if sleepPtr == nil || *sleepPtr <= 0 {
		return 0
	}

	// Extract jitter value (0 if nil)
	jitterPercent := 0
	if jitterPtr != nil {
		jitterPercent = *jitterPtr
	}

	return CalculateDelayWithJitter(*sleepPtr, jitterPercent)
}
