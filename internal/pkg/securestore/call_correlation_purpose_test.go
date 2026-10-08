package securestore

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCallCorrelationStatePurpose(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "call-correlation", 89)})
	_, usage, writer, binding := cryptoUsage(t, ring)
	require.EqualValues(t, 10, CallCorrelationState)
	encoded, err := writer.Seal(CallCorrelationState, binding, []byte("decision"))
	require.NoError(t, err)
	plain, err := ring.Open(CallCorrelationState, binding, encoded, 64)
	require.NoError(t, err)
	require.Equal(t, []byte("decision"), plain)
	_, err = ring.Open(AdministrativeState, binding, encoded, 64)
	require.ErrorIs(t, err, ErrEnvelope)
	usage.usedSeals = MaxKeyInvocations * 9 / 10
	usage.reservedSeals = usage.usedSeals
	_, err = writer.Seal(CallCorrelationState, binding, []byte("new decision"))
	require.ErrorIs(t, err, ErrKeyExhausted)
}
