// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build windows

package main

import (
	"errors"
	"io"
)

// openSyslogWriter is unsupported on Windows; log/syslog is not available.
func openSyslogWriter() (io.Writer, error) {
	return nil, errors.New("syslog not supported on Windows")
}
