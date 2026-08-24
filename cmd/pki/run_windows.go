// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// execBinary runs binary as a child process on Windows (no execve semantics),
// passing through standard IO and the exit code.
func execBinary(binary string, args []string) error {
	cmd := exec.Command(binary, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		if code, ok := ee.Sys().(syscall.WaitStatus); ok {
			os.Exit(int(code))
		}
		os.Exit(ee.ExitCode())
	}
	return err
}
