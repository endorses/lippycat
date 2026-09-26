//go:build linux

package securestore

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalWorkspaceUsageSupportsFiniteMultiBatchAttempt(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "next", 71)})
	cfg := workspaceConfig()
	cfg.Purpose = JournalState
	cfg.Destination = ".segments"
	cfg.UsageName = ring.UsageFileName()
	cfg.Keyrings = []*Keyring{ring}
	_, _, w := workspaceFixture(t, cfg)
	require.NoError(t, w.Reserve())
	w.ops.allocate = func(*os.File, int64) error { t.Fatal("no allocation after reservation"); return nil }
	id := [16]byte{9}
	out, err := w.InitializeUsage(ring, id)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	u, err := w.OpenUsageAttempt(ring, id)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, u.Close()) })
	_, err = w.OpenUsageAttempt(ring, id)
	require.Error(t, err)
	writes := 0
	require.NoError(t, u.ReserveAttempt(12, 10_000, func(name string, b []byte) (Outcome, error) {
		require.Equal(t, ring.UsageFileName(), name)
		writes++
		return w.Replace(RotationUsageReservation0, b)
	}))
	writer, err := NewWriter(u)
	require.NoError(t, err)
	for i := 0; i < 12; i++ {
		_, err = writer.SealControl(JournalState, Binding{Store: id, Object: "journal-state"}, []byte("bounded encrypted control"))
		require.NoError(t, err)
	}
	_, err = writer.SealControl(JournalState, Binding{Store: id, Object: "journal-state"}, nil)
	require.ErrorIs(t, err, ErrKeyExhausted)
	require.Equal(t, 1, writes)
	require.NoError(t, u.Close())
}

func TestJournalWorkspaceRequiresAttemptReservationBeforeSeal(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "next", 72)})
	cfg := workspaceConfig()
	cfg.Purpose = JournalState
	cfg.Destination = ".segments"
	cfg.UsageName = ring.UsageFileName()
	cfg.Keyrings = []*Keyring{ring}
	_, _, w := workspaceFixture(t, cfg)
	require.NoError(t, w.Reserve())
	id := [16]byte{10}
	_, err := w.InitializeUsage(ring, id)
	require.NoError(t, err)
	u, err := w.OpenUsageAttempt(ring, id)
	require.NoError(t, err)
	defer func() { require.NoError(t, u.Close()) }()
	writer, err := NewWriter(u)
	require.NoError(t, err)
	_, err = writer.Seal(JournalState, Binding{Store: id, Object: "journal-state"}, nil)
	require.ErrorIs(t, err, ErrUsageFault)
	require.ErrorIs(t, u.ReserveAttempt(1, 100, func(string, []byte) (Outcome, error) {
		t.Fatal("faulted attempt must not write ledger")
		return Committed, nil
	}), ErrUsageFault)
}
