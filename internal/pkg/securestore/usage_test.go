package securestore

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUsageSurvivesRestartAndKeyIDRename(t *testing.T) {
	ref := cryptoKey(t, "active", 51)
	ring := cryptoRing(t, KeyConfig{Active: ref})
	dir, usage, writer, binding := cryptoUsage(t, ring)
	_, err := writer.Seal(X3Product, binding, []byte("content"))
	require.NoError(t, err)
	require.NoError(t, usage.Close())
	ref.ID = "renamed"
	renamed := cryptoRing(t, KeyConfig{Active: ref})
	again, err := OpenUsage(dir, renamed, binding.Store)
	require.NoError(t, err)
	defer func() { require.NoError(t, again.Close()) }()
	require.Equal(t, invocationReservation, again.usedSeals)
	require.Equal(t, blockReservation, again.usedBlocks)
	require.NoError(t, again.reserve(10, false))
	require.Equal(t, 2*invocationReservation, again.Stats().Invocations)
	_, err = OpenUsage(dir, ring, binding.Store)
	require.ErrorIs(t, err, ErrLocked)
}

func TestUsageNeverReinitializesMissingOrCorruptState(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 52)})
	dir, usage, _, binding := cryptoUsage(t, ring)
	require.NoError(t, usage.Close())
	outcome, err := InitializeUsage(dir, ring, binding.Store)
	require.Error(t, err)
	require.Equal(t, NotCommitted, outcome)
	wrong := binding.Store
	wrong[0]++
	_, err = OpenUsage(dir, ring, wrong)
	require.ErrorIs(t, err, ErrBinding)
	data, err := dir.Read(usageName(ring.active), usageBytes)
	require.NoError(t, err)
	data[31] ^= 1
	_, err = dir.Replace(usageName(ring.active), data)
	require.NoError(t, err)
	_, err = OpenUsage(dir, ring, binding.Store)
	require.ErrorIs(t, err, ErrAuthentication)
	// A newly provisioned key has no ledger. Runtime opening cannot initialize it.
	newRing := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new", 53)})
	_, err = OpenUsage(dir, newRing, binding.Store)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestUsageEnforcesDataAndControlCeilingsAcrossRestart(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 54)})
	dir, usage, _, binding := cryptoUsage(t, ring)
	require.NoError(t, usage.Close())
	for _, sample := range []struct{ seals, blocks uint64 }{
		{MaxKeyInvocations * 9 / 10, 1}, {1, MaxKeyBlocks * 9 / 10},
	} {
		_, err := dir.Replace(usageName(ring.active), encodeUsage(ring.active, binding.Store, sample.seals, sample.blocks))
		require.NoError(t, err)
		u, err := OpenUsage(dir, ring, binding.Store)
		require.NoError(t, err)
		require.True(t, u.Stats().RotateRecommended)
		require.ErrorIs(t, u.reserve(1, false), ErrKeyExhausted)
		require.NoError(t, u.reserve(1, true))
		require.NoError(t, u.Close())
	}
	for _, sample := range []struct{ seals, blocks uint64 }{
		{MaxKeyInvocations, 1}, {1, MaxKeyBlocks},
	} {
		_, err := dir.Replace(usageName(ring.active), encodeUsage(ring.active, binding.Store, sample.seals, sample.blocks))
		require.NoError(t, err)
		u, err := OpenUsage(dir, ring, binding.Store)
		require.NoError(t, err)
		require.ErrorIs(t, u.reserve(1, true), ErrKeyExhausted)
		require.NoError(t, u.Close())
	}
}

func TestUsageFailureCannotSealOrRetryUncertainReservation(t *testing.T) {
	for _, outcome := range []Outcome{NotCommitted, Uncertain, Committed} {
		t.Run(string(rune('a'+outcome)), func(t *testing.T) {
			ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 55)})
			_, usage, writer, binding := cryptoUsage(t, ring)
			calls := 0
			fault := errors.New("injected storage failure")
			usage.write = func(string, []byte) (Outcome, error) { calls++; return outcome, fault }
			sealed, err := writer.Seal(X3Product, binding, []byte("must not escape"))
			require.Nil(t, sealed)
			require.ErrorIs(t, err, ErrUsageFault)
			require.ErrorIs(t, err, fault)
			require.Equal(t, NotCommitted, OutcomeOf(err))
			var usageErr *UsageError
			require.ErrorAs(t, err, &usageErr)
			require.Equal(t, outcome, usageErr.ReservationOutcome)
			sealed, err = writer.SealControl(RevocationControl, binding, nil)
			require.Nil(t, sealed)
			require.ErrorIs(t, err, ErrUsageFault)
			require.Equal(t, 1, calls)
			require.True(t, usage.Stats().Faulted)
		})
	}
}

func TestUsageRestartDiscardsCommittedReservationOnReportedFailure(t *testing.T) {
	for _, outcome := range []Outcome{Uncertain, Committed} {
		t.Run(string(rune('a'+outcome)), func(t *testing.T) {
			ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 61)})
			dir, usage, writer, binding := cryptoUsage(t, ring)
			usage.write = func(name string, data []byte) (Outcome, error) {
				actual, err := dir.Replace(name, data)
				require.NoError(t, err)
				require.Equal(t, Committed, actual)
				return outcome, &CommitError{Outcome: outcome, Op: "injected lost sync acknowledgement", Err: errors.New("lost acknowledgement")}
			}
			encoded, err := writer.Seal(X3Product, binding, []byte("lost before encryption"))
			require.Nil(t, encoded)
			require.Error(t, err)
			require.Equal(t, NotCommitted, OutcomeOf(err), "auxiliary commitment is not object commitment")
			require.NoError(t, usage.Close())
			reopened, err := OpenUsage(dir, ring, binding.Store)
			require.NoError(t, err)
			defer func() { require.NoError(t, reopened.Close()) }()
			require.Equal(t, invocationReservation, reopened.usedSeals)
			require.Equal(t, blockReservation, reopened.usedBlocks)
			fresh, err := NewWriter(reopened)
			require.NoError(t, err)
			encoded, err = fresh.Seal(X3Product, binding, []byte("fresh after recovery"))
			require.NoError(t, err)
			require.NotEmpty(t, encoded)
			require.Equal(t, 2*invocationReservation, reopened.Stats().Invocations)
		})
	}
}

func TestUsageReservationCrossingAndConcurrentCeiling(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 62)})
	dir, usage, _, binding := cryptoUsage(t, ring)
	for range invocationReservation + 1 {
		require.NoError(t, usage.reserve(1, false))
	}
	require.Equal(t, 2*invocationReservation, usage.Stats().Invocations)
	require.NoError(t, usage.reserve(2*blockReservation, false))
	require.Greater(t, usage.Stats().Blocks, 2*blockReservation)
	require.NoError(t, usage.Close())
	_, err := dir.Replace(usageName(ring.active), encodeUsage(ring.active, binding.Store, MaxKeyInvocations-5, 0))
	require.NoError(t, err)
	nearEnd, err := OpenUsage(dir, ring, binding.Store)
	require.NoError(t, err)
	defer func() { require.NoError(t, nearEnd.Close()) }()
	results := make(chan error, 32)
	for range 32 {
		go func() { results <- nearEnd.reserve(1, true) }()
	}
	success := 0
	for range 32 {
		if err := <-results; err == nil {
			success++
		} else {
			require.ErrorIs(t, err, ErrKeyExhausted)
		}
	}
	require.Equal(t, 5, success)
	require.Equal(t, MaxKeyInvocations, nearEnd.Stats().Invocations)
}
