package securestore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawPacketSpoolPurposeSeparation(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "raw-packets", 91)})
	_, usage, writer, binding := cryptoUsage(t, ring)
	encoded, err := writer.Seal(PacketSpoolBatch, binding, []byte("captured data"))
	require.NoError(t, err)
	_, err = ring.Open(PacketSpoolState, binding, encoded, 64)
	require.ErrorIs(t, err, ErrEnvelope)
	_, err = writer.SealControl(PacketSpoolBatch, binding, []byte("captured data"))
	require.Error(t, err)
	_, err = writer.SealControl(PacketCustodyState, binding, []byte("accepted captured data"))
	require.Error(t, err)
	usage.usedSeals = MaxKeyInvocations * 9 / 10
	usage.reservedSeals = usage.usedSeals
	_, err = writer.Seal(PacketSpoolBatch, binding, []byte("new captured data"))
	require.ErrorIs(t, err, ErrKeyExhausted)
	_, err = writer.SealControl(PacketSpoolState, binding, []byte("retirement"))
	require.NoError(t, err)
}
