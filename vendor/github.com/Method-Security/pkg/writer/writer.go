// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package writer

import (
	"fmt"
	"os"

	sig "github.com/Method-Security/pkg/signal"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/pkg/safejson"
	"github.com/palantir/pkg/safeyaml"
)

func Write(
	report any,
	config OutputConfig,
	startedAt datetime.DateTime,
	completedAt *datetime.DateTime,
	status int,
	errorMessage *string,
) error {
	var data []byte
	var err error
	switch config.Output.val {
	case JSON:
		signal := sig.NewSignal(report, startedAt, completedAt, status, errorMessage)
		data, err = safejson.Marshal(signal)
	case YAML:
		signal := sig.NewSignal(report, startedAt, completedAt, status, errorMessage)
		data, err = safeyaml.Marshal(signal)
	case SIGNAL:
		signal := sig.NewSignal(report, startedAt, completedAt, status, errorMessage)
		err = signal.EncodeContent()
		if err != nil {
			return err
		}
		data, err = safejson.Marshal(signal)
	default:
		err = fmt.Errorf("unknown output format: %s", config.Output)
	}
	if err != nil {
		return err
	}
	return writeToFileOrStdout(data, config.FilePath)
}

func writeToFileOrStdout(data []byte, filePath *string) error {
	if filePath == nil {
		_, err := os.Stdout.Write(data)
		if err != nil {
			return err
		}
	} else {
		err := os.WriteFile(*filePath, data, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}
