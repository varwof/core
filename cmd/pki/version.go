// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// version is the release version.
//
// When built from a tagged git checkout it resolves automatically from module
// build info (e.g. v0.2.0); otherwise it falls back to the compile-time default
// below. It can be overridden via -ldflags -X main.version=x.y.z (CI/CD), which
// takes precedence over the build-info resolution.
var version = "0.2.0"

// commit and buildTime are populated automatically from module build info
// (vcs.revision / vcs.time), or overridden via
// -ldflags -X main.commit=<rev> -X main.buildTime=<ISO8601>.
var commit = "unknown"
var buildTime = "unknown"

func init() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if bi.Main.Version != "" && bi.Main.Version != "(devel)" && version == "0.2.0" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 && commit == "unknown" {
				commit = s.Value[:7]
			}
		case "vcs.time":
			if buildTime == "unknown" && s.Value != "" {
				buildTime = s.Value
			}
		}
	}
}

func versionString() string {
	return fmt.Sprintf("varwof %s %s/%s %s (rev %s, %s)",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), commit, buildTime)
}
