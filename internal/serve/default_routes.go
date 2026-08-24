// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"embed"
	"log/slog"

	"github.com/varwof/core/internal/routing"
)

//go:embed routes_default.json
var defaultRoutesFS embed.FS

func LoadDefaultRouteRules() *routing.RouteRules {
	data, err := defaultRoutesFS.ReadFile("routes_default.json")
	if err != nil {
		slog.Error("serve: failed to read embedded default routes", "error", err)
		return nil
	}
	rr, err := routing.LoadData(data)
	if err != nil {
		slog.Error("serve: failed to parse embedded default routes", "error", err)
		return nil
	}
	slog.Info("serve: loaded embedded default route rules", "rules", rr.Count())
	return rr
}
