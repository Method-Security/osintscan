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
	return CalculateDelayWithJitterDuration(time.Duration(baseDelaySeconds)*time.Second, jitterPercent)
}

func CalculateDelayWithJitterDuration(baseDelay time.Duration, jitterPercent int) time.Duration {
	if baseDelay <= 0 {
		return 0
	}

	if jitterPercent > 0 && jitterPercent <= 100 {
		jitterAmount := float64(baseDelay.Nanoseconds()) * (float64(jitterPercent) / 100.0)
		randomJitter := (rand.Float64()*2 - 1) * jitterAmount
		finalDelay := time.Duration(float64(baseDelay.Nanoseconds()) + randomJitter)
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
