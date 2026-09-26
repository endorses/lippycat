//go:build !linux

package securestore

import "golang.org/x/sys/unix"

func publishNoReplace(oldFD int, oldName string, newFD int, newName string) (bool, bool, error) {
	if err := unix.Linkat(oldFD, oldName, newFD, newName, 0); err != nil {
		return false, true, err
	}
	if err := unix.Unlinkat(oldFD, oldName, 0); err != nil {
		return true, true, err
	}
	return true, false, nil
}
