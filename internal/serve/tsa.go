// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

// TSA handler is used directly via s.tsaH.ServeHTTP in mux.go.
// No additional adapter needed — the tsa.Handler already handles
// POST-only with application/timestamp-query content type.
