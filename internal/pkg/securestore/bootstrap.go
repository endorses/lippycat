package securestore

import (
	"encoding/binary"
	"errors"
)

const MaxInitializationContextBytes = 4096

// InitializationBinding commits to a bounded offline operation before a usage
// ledger exists. Only this opaque keyed digest is persisted; context must not be
// persisted in plaintext. HMAC does not consume a GCM invocation and is separated
// from ledger MACs, store purposes and ordinary encrypted envelopes.
func (r *Keyring) InitializationBinding(purpose Purpose, context []byte) ([32]byte, error) {
	var result [32]byte
	if r == nil || r.active == nil || !purpose.valid() || len(context) == 0 || len(context) > MaxInitializationContextBytes {
		return result, errors.New("invalid encrypted store initialization context")
	}
	input := make([]byte, 2+len(context))
	binary.BigEndian.PutUint16(input[:2], uint16(purpose))
	copy(input[2:], context)
	copy(result[:], r.active.mac("lippycat/securestore/initialization/v1\x00", input))
	clear(input)
	return result, nil
}
