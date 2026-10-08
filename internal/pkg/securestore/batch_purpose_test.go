package securestore

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalBatchIndexPurposeAndUsageClassification(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "batch-index", 83)})
	_, usage, writer, binding := cryptoUsage(t, ring)
	require.EqualValues(t, 9, JournalBatchIndex)
	encoded, err := writer.Seal(JournalBatchIndex, binding, []byte("synthetic index"))
	require.NoError(t, err)
	require.EqualValues(t, 9, binary.BigEndian.Uint16(encoded[6:8]))
	plain, err := ring.Open(JournalBatchIndex, binding, encoded, 64)
	require.NoError(t, err)
	require.Equal(t, "synthetic index", string(plain))
	_, err = ring.Open(JournalState, binding, encoded, 64)
	require.ErrorIs(t, err, ErrEnvelope)
	_, err = writer.Seal(CallCorrelationState+1, binding, nil)
	require.ErrorIs(t, err, ErrEnvelope)
	// Index purpose alone must not put data growth into the reserved allowance.
	usage.usedSeals = MaxKeyInvocations * 9 / 10
	usage.reservedSeals = usage.usedSeals
	_, err = writer.Seal(JournalBatchIndex, binding, []byte("new product index"))
	require.ErrorIs(t, err, ErrKeyExhausted)
	_, err = writer.SealControl(JournalBatchIndex, binding, []byte("terminal index"))
	require.NoError(t, err)
	_, err = writer.SealControl(X3Product, binding, []byte("product"))
	require.Error(t, err)
}
