//go:build !linux

package securestore

import "errors"

func (d *Dir) RotationTemporaryAllocatedSize(string) (int64, error) {
	return 0, errors.New("securestore: rotation temporary accounting requires Linux")
}
