//go:build !windows

package main

import (
	"os"
	"syscall"
)

// execBinary replaces the current process to execute binary (execve semantics),
// returning an error only if exec fails.
func execBinary(binary string, args []string) error {
	argv := append([]string{binary}, args...)
	return syscall.Exec(binary, argv, os.Environ())
}
