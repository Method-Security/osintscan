// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package writer

type OutputConfig struct {
	FilePath *string
	Output   Format
}

func NewOutputConfig(filePath *string, output Format) OutputConfig {
	return OutputConfig{
		FilePath: filePath,
		Output:   output,
	}
}
