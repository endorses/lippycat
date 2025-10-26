//go:build !linux

package vinterface

import "fmt"

// DropPrivileges is not supported on non-Linux platforms.
func DropPrivileges(username string) error {
	if username == "" {
		return nil
	}
	return fmt.Errorf("privilege dropping not supported on this platform")
}

// CanDropPrivileges returns false on non-Linux platforms.
func CanDropPrivileges() bool {
	return false
}
