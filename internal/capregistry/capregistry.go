// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package capregistry provides a runtime wrapper around the capability register.
//
// Purpose: core validates declared capabilities at three points — AIC issuance,
// authentication, and gateway — against the register's capability specification.
// Specification JSON is loaded via embedded + disk override (changing JSON updates
// policy without recompilation) and supports SIGHUP hot-reload.
package capregistry

import (
	"fmt"
	"sync/atomic"

	"github.com/varwof/register"
	pki "github.com/varwof/types"
)

// CapabilityRegistry is an atomic wrapper around register.Registry that supports hot-reload.
// nil-safe: when not loaded, validation passes without blocking existing workflows;
// loadErr records the failure reason.
type CapabilityRegistry struct {
	regPtr atomic.Pointer[register.Registry]
}

// New creates an empty capability registry (no schemes loaded).
func New() *CapabilityRegistry {
	return &CapabilityRegistry{}
}

// LoadAndSet loads schemes from a disk directory (capability data tree)
// and atomically replaces the current registry.
// diskDir must be non-empty; embedded schemes were removed when the
// capability data split into a separate subproject.
// Returns an error if loading fails; the current registry remains unchanged.
func (cr *CapabilityRegistry) LoadAndSet(diskDir string) error {
	if diskDir == "" {
		return fmt.Errorf("capregistry: capability_schemes directory required (embedded schemes removed)")
	}
	schemes, err := register.LoadFromDir(diskDir)
	if err != nil {
		return fmt.Errorf("capregistry: load schemes: %w", err)
	}
	reg := register.NewRegistry()
	for _, def := range schemes {
		reg.Register(def)
	}
	cr.regPtr.Store(reg)
	return nil
}

// Registry returns the current registry (may be nil).
func (cr *CapabilityRegistry) Registry() *register.Registry {
	return cr.regPtr.Load()
}

// Enabled reports whether the capability registry has been loaded.
func (cr *CapabilityRegistry) Enabled() bool {
	return cr.regPtr.Load() != nil
}

// ValidateCapability validates whether a full identifier "scheme:capability_id" is registered.
// Returns nil when the registry is not loaded (does not block).
func (cr *CapabilityRegistry) ValidateCapability(formatted string) error {
	reg := cr.regPtr.Load()
	if reg == nil {
		return nil
	}
	_, _, err := reg.ValidateCapability(formatted)
	if err != nil {
		return fmt.Errorf("capregistry: %w", err)
	}
	return nil
}

// ValidateCapabilityIDs validates whether a set of "scheme:capability_id" identifiers are all registered.
// Returns the first unregistered capability identifier; returns nil if all are valid.
func (cr *CapabilityRegistry) ValidateCapabilityIDs(ids []string) error {
	for _, id := range ids {
		if err := cr.ValidateCapability(id); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAICCapabilities validates whether all capabilities declared in an AIC are registered.
// Returns the first invalid capability; returns nil if all are valid or the registry is not enabled.
func (cr *CapabilityRegistry) ValidateAICCapabilities(caps []pki.Capability) error {
	reg := cr.regPtr.Load()
	if reg == nil {
		return nil
	}
	for _, c := range caps {
		formatted := c.FullID()
		if _, _, err := reg.ValidateCapability(formatted); err != nil {
			return fmt.Errorf("aic capability %q not registered: %w", formatted, err)
		}
	}
	return nil
}

// ValidateClaim validates a single capability claim (AI-generated least-privilege set).
// Returns an error if the claim is invalid (unknown scheme / unregistered capability / undefined parameters).
func (cr *CapabilityRegistry) ValidateClaim(scheme, capability string) error {
	reg := cr.regPtr.Load()
	if reg == nil {
		return nil
	}
	_, _, err := reg.ValidateCapability(scheme + ":" + capability)
	if err != nil {
		return fmt.Errorf("capregistry: %w", err)
	}
	return nil
}
