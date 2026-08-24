// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package tsa

import (
	"io"
	"log/slog"
	"net/http"
)

// Handler serves TSA requests using a RuntimeConfig that supports hot-swapping.
type Handler struct {
	config *RuntimeConfig
}

// NewHandler creates a Handler backed by the given RuntimeConfig.
func NewHandler(cfg *TSAConfig) *Handler {
	return &Handler{config: NewRuntimeConfig(cfg)}
}

// NewHandlerWithRuntime creates a Handler backed by an existing RuntimeConfig.
func NewHandlerWithRuntime(rc *RuntimeConfig) *Handler {
	return &Handler{config: rc}
}

// RuntimeConfig returns the underlying RuntimeConfig for hot-swap operations.
func (h *Handler) RuntimeConfig() *RuntimeConfig {
	return h.config
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		slog.Error("tsa: read body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	cfg := h.config.Load()
	respDER, err := SignRequest(body, cfg)
	if err != nil {
		slog.Error("tsa: sign", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.WriteHeader(http.StatusOK)
	w.Write(respDER)
}
