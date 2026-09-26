package securestore

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// LockOrderKey supplies a stable ordering for locks across opened directories.
// Path aliases and renames share an ordering because descriptor identity is used.
func (d *Dir) LockOrderKey(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	dev, ino, err := d.directoryIdentity()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%020d:%020d:%s", dev, ino, name), nil
}

// SameDirectory compares the held directory descriptors, including after their
// paths are renamed. It never holds two directory mutexes at once.
func (d *Dir) SameDirectory(other *Dir) (bool, error) {
	dev, ino, err := d.directoryIdentity()
	if err != nil {
		return false, err
	}
	otherDev, otherIno, err := other.directoryIdentity()
	if err != nil {
		return false, err
	}
	return dev == otherDev && ino == otherIno, nil
}

func (d *Dir) directoryIdentity() (uint64, uint64, error) {
	if d == nil {
		return 0, 0, errors.New("securestore: directory is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return 0, 0, os.ErrClosed
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(d.file.Fd()), &st); err != nil {
		return 0, 0, contextual("inspect directory identity", err)
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}
