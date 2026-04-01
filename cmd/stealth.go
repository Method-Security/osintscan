package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// addStealthFlags adds --sleep and --jitter flags to a cobra command.
func addStealthFlags(cmd *cobra.Command) {
	cmd.Flags().Int("sleep", 0, "Base delay in seconds between requests for stealth (0 = no delay)")
	cmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to randomize sleep delay")
}

// getStealthFlags extracts and validates sleep and jitter flag values from a command.
// Returns sleep, jitter values and any error encountered.
func getStealthFlags(cmd *cobra.Command) (int, int, error) {
	sleep, err := cmd.Flags().GetInt("sleep")
	if err != nil {
		return 0, 0, err
	}
	jitter, err := cmd.Flags().GetInt("jitter")
	if err != nil {
		return 0, 0, err
	}
	if jitter < 0 || jitter > 100 {
		return 0, 0, fmt.Errorf("--jitter must be between 0 and 100, got %d", jitter)
	}
	if jitter > 0 && sleep <= 0 {
		return 0, 0, fmt.Errorf("--jitter requires --sleep to be greater than 0")
	}
	return sleep, jitter, nil
}

// intPtr returns a pointer to the given int value.
// Returns nil if the value is 0 (used for optional Fern fields).
func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}
