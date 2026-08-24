// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import "fmt"

func ef(key string, args ...any) error {
	return bundle.Ef(curLang, key, args...)
}

func pf(key string, args ...any) {
	fmt.Print(bundle.T(curLang, key, args...))
}

func pfln(key string, args ...any) {
	fmt.Println(bundle.T(curLang, key, args...))
}

// splitCSV splits a comma-separated string, trimming whitespace.
