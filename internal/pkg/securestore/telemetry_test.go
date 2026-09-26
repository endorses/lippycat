package securestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStorageTelemetryUsageDoesNotWaitForReservation(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 81)})
	_, u, writer, binding := cryptoUsage(t, ring)
	var telemetry Telemetry
	telemetry.Initialize("encrypted", ring)
	telemetry.BindUsage(u)
	telemetry.Ready()
	entered, release := make(chan struct{}), make(chan struct{})
	u.write = func(string, []byte) (Outcome, error) {
		close(entered)
		<-release
		return Uncertain, errors.New("secret-path/secret-payload")
	}
	done := make(chan error, 1)
	go func() { _, err := writer.Seal(X2Product, binding, []byte("private")); done <- err }()
	<-entered
	read := make(chan StorageStatus, 1)
	go func() { read <- telemetry.Snapshot() }()
	select {
	case s := <-read:
		require.Zero(t, s.Usage.Invocations)
	case <-time.After(time.Second):
		close(release)
		t.Fatal("status waited for ledger fsync")
	}
	close(release)
	err := <-done
	require.Error(t, err)
	telemetry.Record(OutcomeOf(err), err)
	telemetry.Fault(err)
	s := telemetry.Snapshot()
	require.Equal(t, "not_committed", s.LastOutcome)
	require.Equal(t, "uncertain", s.Usage.ReservationOutcome)
	require.Equal(t, uint64(1), s.DefiniteFailures)
	require.Zero(t, s.Uncertain)
	require.True(t, s.Usage.Faulted)
	require.Equal(t, invocationReservation, s.Usage.Invocations, "possibly committed reservation remains consumed in diagnostics")
	require.Equal(t, "usage_ledger_fault", s.FaultCode)
	encoded, err := json.Marshal(s)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "secret")
	require.NoError(t, u.Close())
	require.True(t, telemetry.Snapshot().Usage.Closed)
}

func TestStorageTelemetryUsageThresholdsAndNoPerSealPublication(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 82)})
	_, u, writer, binding := cryptoUsage(t, ring)
	_, err := writer.Seal(X2Product, binding, []byte("value"))
	require.NoError(t, err)
	view := u.diagnostic.Load()
	_, err = writer.Seal(X2Product, binding, []byte("value"))
	require.NoError(t, err)
	require.Same(t, view, u.diagnostic.Load(), "reserved batch telemetry must not allocate on every seal")
	for _, percent := range []uint64{0, 74, 75, 90, 100} {
		t.Run(fmt.Sprint(percent), func(t *testing.T) {
			seals, blocks := MaxKeyInvocations*percent/100, MaxKeyBlocks*percent/100
			u.publishUsage(Committed, seals, blocks)
			s := u.Stats()
			require.Equal(t, percent >= 75, s.RotateRecommended)
			require.Equal(t, MaxKeyInvocations-seals, s.TotalInvocationsRemaining)
			require.Equal(t, MaxKeyBlocks-blocks, s.TotalBlocksRemaining)
			if percent >= 90 {
				require.Zero(t, s.OrdinaryInvocationsRemaining)
				require.Zero(t, s.OrdinaryBlocksRemaining)
			}
		})
	}
}

func TestStorageTelemetryKeyMetadataCountersAndDetachment(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 83), Prior: []KeyRef{cryptoKey(t, "z", 84), cryptoKey(t, "a", 85)}})
	var telemetry Telemetry
	telemetry.Initialize("encrypted", ring)
	telemetry.Ready()
	telemetry.Record(NotCommitted, errors.New("chosen-selector"))
	telemetry.Record(Uncertain, errors.New("chosen-selector"))
	telemetry.Record(Committed, errors.New("chosen-selector"))
	s := telemetry.Snapshot()
	require.Equal(t, []string{"a", "z"}, s.PriorKeyIDs)
	s.PriorKeyIDs[0] = "changed"
	s = telemetry.Snapshot()
	require.Equal(t, []string{"a", "z"}, s.PriorKeyIDs)
	require.Equal(t, uint64(1), s.DefiniteFailures)
	require.Equal(t, uint64(1), s.Uncertain)
	require.Equal(t, uint64(1), s.Commits)
	require.Equal(t, uint64(1), s.CleanupWarnings)
	require.Equal(t, "committed", s.LastOutcome)
	require.Equal(t, "ready", s.State)
	require.Equal(t, "storage_error", s.LastErrorCode)
	telemetry.Closing()
	telemetry.Ready()
	telemetry.Fault(errors.New("closing-fault"))
	require.Equal(t, "closing", telemetry.Snapshot().State)
	telemetry.Closed(nil)
	telemetry.Closing()
	telemetry.Ready()
	telemetry.Fault(errors.New("closed-fault"))
	require.Equal(t, "closed", telemetry.Snapshot().State)
}
