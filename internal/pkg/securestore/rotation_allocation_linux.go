//go:build linux

package securestore

import (
	"errors"
	"math"
	"os"
	"strings"
)

// RotationTemporaryAllocatedSize measures only recognized bounded private
// transaction temporaries. It does not infer authority or permit their cleanup.
func (d *Dir) RotationTemporaryAllocatedSize(name string) (_ int64, result error) {
	valid := false
	if strings.HasPrefix(name, rotationWorkspacePrefix) {
		rest := strings.TrimPrefix(name, rotationWorkspacePrefix)
		if len(rest) > 65 && rotationHex(rest[:64], 64) && rest[64] == '-' {
			rest = rest[65:]
			for _, role := range rotationStageNames {
				if strings.HasPrefix(rest, role+"-") && rotationHex(strings.TrimPrefix(rest, role+"-"), 32) {
					valid = true
				}
			}
		}
	}
	if strings.HasPrefix(name, ".securestore-tmp-") && rotationHex(strings.TrimPrefix(name, ".securestore-tmp-"), 32) {
		valid = true
	}
	if !valid {
		return 0, errors.New("securestore: invalid temporary allocation name")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return 0, os.ErrClosed
	}
	f, err := openPrivate(int(d.file.Fd()), name)
	if err != nil {
		return 0, err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	stat, err := validatePrivate(int(f.Fd()))
	if err != nil {
		return 0, err
	}
	if stat.Size > MaxEnvelopeBytes || stat.Blocks < 0 || uint64(stat.Blocks) > math.MaxInt64/512 {
		return 0, errors.New("securestore: temporary allocation bounds")
	}
	return stat.Blocks * 512, nil
}
