// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package writer

import (
	"strings"
)

type Format struct {
	val FormatValue
}

type FormatValue string

const (
	JSON    FormatValue = "json"
	YAML    FormatValue = "yaml"
	SIGNAL  FormatValue = "signal"
	UNKNOWN FormatValue = "unknown"
)

func FormatValues() []FormatValue {
	return []FormatValue{
		JSON,
		YAML,
		SIGNAL,
	}
}

func NewFormat(value FormatValue) Format {
	return Format{val: value}
}

func (f Format) IsUnknown() bool {
	switch f.val {
	case JSON, YAML, SIGNAL:
		return false
	}
	return true
}

func (f Format) String() string {
	return string(f.val)
}

func (f *Format) UnmarshalText(text []byte) error {
	switch v := strings.ToUpper(string(text)); v {
	default:
		*f = NewFormat(FormatValue(v))
	case "JSON":
		*f = NewFormat(JSON)
	case "YAML":
		*f = NewFormat(YAML)
	case "SIGNAL":
		*f = NewFormat(SIGNAL)
	case "UNKNOWN":
		*f = NewFormat(UNKNOWN)
	}
	return nil
}

func (f Format) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}
