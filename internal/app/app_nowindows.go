// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build !windows

package app

// maybeRunAsWindowsService is a no-op on non-Windows platforms.
// On Windows it is implemented in app_windows.go.
func maybeRunAsWindowsService(_, _, _ string) bool {
	return false
}
