package securestore

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUsageAttemptHasExactFenceWithoutFurtherLedgerWrites(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 67)})
	dir, u, _, binding := cryptoUsage(t, ring)
	writes := 0
	require.NoError(t, u.ReserveAttempt(2, 20, func(name string, b []byte) (Outcome, error) { writes++; return dir.Replace(name, b) }))
	u.write = func(string, []byte) (Outcome, error) {
		t.Fatal("finite attempt must not refill")
		return NotCommitted, nil
	}
	require.NoError(t, u.reserve(10, false))
	require.NoError(t, u.reserve(10, true))
	require.ErrorIs(t, u.reserve(1, true), ErrKeyExhausted)
	require.Equal(t, 1, writes)
	require.Error(t, u.ReserveAttempt(1, 1, dir.Replace))
	require.NoError(t, u.Close())
	again, err := OpenUsage(dir, ring, binding.Store)
	require.NoError(t, err)
	defer func() { require.NoError(t, again.Close()) }()
	require.Equal(t, invocationReservation, again.usedSeals)
	require.Equal(t, blockReservation, again.usedBlocks, "unused attempt capacity is lost on restart")
}
func TestUsageAttemptBlockFenceAndUncertainReservation(t *testing.T) {
	for _, outcome := range []Outcome{NotCommitted, Uncertain, Committed} {
		ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 68)})
		_, u, _, _ := cryptoUsage(t, ring)
		failure := errors.New("injected ledger outcome")
		err := u.ReserveAttempt(10, 5, func(string, []byte) (Outcome, error) { return outcome, failure })
		require.ErrorIs(t, err, ErrUsageFault)
		require.ErrorIs(t, u.reserve(1, true), ErrUsageFault)
		require.True(t, u.Stats().Faulted)
		require.Equal(t, OutcomeName(outcome), u.Stats().ReservationOutcome)
	}
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 69)})
	dir, u, _, _ := cryptoUsage(t, ring)
	require.NoError(t, u.ReserveAttempt(10, 5, dir.Replace))
	require.NoError(t, u.reserve(5, true))
	require.ErrorIs(t, u.reserve(1, true), ErrKeyExhausted)
}
