//go:build linux

package securestore

import "golang.org/x/sys/unix"

// There is deliberately no link/unlink fallback: a Linux filesystem without
// RENAME_NOREPLACE cannot provide this atomic initialization contract.
func publishNoReplace(oldFD int, oldName string, newFD int, newName string) (bool, bool, error) {
	if err := unix.Renameat2(oldFD, oldName, newFD, newName, unix.RENAME_NOREPLACE); err != nil {
		return false, true, err
	}
	return true, false, nil
}
