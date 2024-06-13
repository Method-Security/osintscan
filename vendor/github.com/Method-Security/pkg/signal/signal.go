// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package signal

import (
	"encoding/base64"

	"github.com/palantir/pkg/datetime"
	"github.com/palantir/pkg/safejson"
)

type Signal struct {
	Content      any                `json:"content" yaml:"content"`
	StartedAt    datetime.DateTime  `json:"started_at" yaml:"started_at"`
	CompletedAt  *datetime.DateTime `json:"completed_at,omitempty" yaml:"completed_at,omitempty"`
	Status       int                `json:"status" yaml:"status"`
	ErrorMessage *string            `json:"error_message,omitempty" yaml:"error_message,omitempty"`
}

func NewSignal(content any, startedAt datetime.DateTime, completedAt *datetime.DateTime, status int, errorMessage *string) Signal {
	return Signal{
		Content:      content,
		StartedAt:    startedAt,
		CompletedAt:  completedAt,
		Status:       status,
		ErrorMessage: errorMessage,
	}
}

func (s *Signal) EncodeContent() error {
	data, err := safejson.Marshal(s.Content)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	s.Content = encoded
	return nil
}
