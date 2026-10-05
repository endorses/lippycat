//go:build linux

package ebpfadmission

import (
	"encoding/binary"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDecisionRequiresCompleteBoundedFrameIdentity(t *testing.T) {
	raw := make([]byte, 344)
	binary.NativeEndian.PutUint64(raw, 1)
	binary.NativeEndian.PutUint32(raw[24:], 3)
	binary.NativeEndian.PutUint32(raw[80:], 3)
	copy(raw[84:], []byte{1, 2, 3})
	got, err := DecodeDecision(raw)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, got.Identity[:got.IdentityLength])
	for _, scenario := range []string{"partial prefix", "too large", "missing time", "unknown reason", "malformed size"} {
		t.Run(scenario, func(t *testing.T) {
			invalid := append([]byte(nil), raw...)
			switch scenario {
			case "partial prefix":
				binary.NativeEndian.PutUint32(invalid[24:], 4)
			case "too large":
				binary.NativeEndian.PutUint32(invalid[80:], 257)
			case "missing time":
				binary.NativeEndian.PutUint64(invalid, 0)
			case "unknown reason":
				binary.NativeEndian.PutUint32(invalid[20:], 16)
			case "malformed size":
				invalid = invalid[:80]
			}
			_, err := DecodeDecision(invalid)
			require.Error(t, err)
		})
	}
	// Unsupported full-frame size is valid uncertainty, not malformed evidence.
	binary.NativeEndian.PutUint32(raw[24:], 300)
	binary.NativeEndian.PutUint32(raw[80:], 0)
	_, err = DecodeDecision(raw)
	require.NoError(t, err)
}
