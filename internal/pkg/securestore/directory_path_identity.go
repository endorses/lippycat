package securestore

import (
	"errors"

	"golang.org/x/sys/unix"
)

// SameDirectoryPath compares an owned private directory with a descriptor-opened
// trusted directory path. The latter may be a public key-file parent; it need
// not satisfy the stricter private store-directory mode. Neither path is cleaned
// before validation and no symbolic links are followed.
func (d *Dir) SameDirectoryPath(path string) (same bool, result error) {
	device, inode, err := d.directoryIdentity()
	if err != nil {
		return false, err
	}
	other, err := openDirectory(path, false)
	if err != nil {
		return false, err
	}
	defer func() { result = errors.Join(result, contextual("close compared directory", other.Close())) }()
	var st unix.Stat_t
	if err := unix.Fstat(int(other.Fd()), &st); err != nil {
		return false, contextual("inspect compared directory", err)
	}
	return device == uint64(st.Dev) && inode == uint64(st.Ino), nil
}
