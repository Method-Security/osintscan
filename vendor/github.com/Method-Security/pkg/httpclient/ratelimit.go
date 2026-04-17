// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package httpclient

import (
	"math/rand/v2"
	"time"
)

// DelayWithJitter returns a duration with random jitter applied.
// The result is between baseDelay and baseDelay + jitter.
func DelayWithJitter(baseDelay, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return baseDelay
	}
	return baseDelay + time.Duration(rand.Int64N(int64(jitter)))
}

// Sleep pauses execution for the base delay plus random jitter.
func Sleep(baseDelay, jitter time.Duration) {
	time.Sleep(DelayWithJitter(baseDelay, jitter))
}
