// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"runtime"
)

// Set via -ldflags -X main.version=x.y.z (CI/CD) or hardcoded default.
var version = "1.1.1"

// Set via -ldflags -X main.commit=<git/svn rev> -X main.buildTime=<ISO8601>.
var commit = "unknown"
var buildTime = "unknown"

func versionString() string {
	return fmt.Sprintf("varwof %s %s/%s %s (rev %s, %s)",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), commit, buildTime)
}
