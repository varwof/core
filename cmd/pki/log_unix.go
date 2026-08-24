// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build !windows

package main

import (
	"io"
	"log/syslog"
)

// openSyslogWriter returns a syslog writer on platforms that support it.
func openSyslogWriter() (io.Writer, error) {
	return syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "varwof-core")
}
