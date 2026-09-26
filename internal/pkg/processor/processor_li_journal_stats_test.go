//go:build (processor || tap || all) && li

package processor

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestDeliveryJournalStatsUsesIndependentCountsAndFixedFaultCode(t *testing.T) {
	stats := delivery.JournalStats{
		Bytes: 123, MaxBytes: 456, Pending: 1, Persisted: 2, Held: 3,
		ReplayPending: 4, Approved: 5, Retained: 6, Expired: 7, Revoked: 8,
		Rejected: 9, Uncertain: 10, LastError: "sensitive-path-or-target",
	}
	storage := securestore.StorageStatus{Mode: "encrypted", State: "faulted", FaultCode: "authentication_failed", LastOutcome: "uncertain"}
	got := deliveryJournalStats(stats, storage)
	require.EqualValues(t, 123, got.Bytes)
	require.EqualValues(t, 456, got.MaxBytes)
	require.EqualValues(t, 1, got.Pending)
	require.EqualValues(t, 2, got.Persisted)
	require.EqualValues(t, 3, got.Held)
	require.EqualValues(t, 4, got.ReplayPending)
	require.EqualValues(t, 5, got.Approved)
	require.EqualValues(t, 6, got.Retained)
	require.EqualValues(t, 7, got.Expired)
	require.EqualValues(t, 8, got.Revoked)
	require.EqualValues(t, 9, got.Rejected)
	require.EqualValues(t, 10, got.Uncertain)
	require.Equal(t, "authentication_failed", got.LastError)
	require.Equal(t, "uncertain", got.Storage.LastOutcome)
	require.NotContains(t, got.String(), "sensitive-path-or-target")
	other := deliveryJournalStats(delivery.JournalStats{Bytes: 12}, securestore.StorageStatus{})
	require.EqualValues(t, 12, other.Bytes)
	require.Zero(t, other.Expired)
	require.EqualValues(t, 123, got.Bytes, "constructing X3 stats must not mutate X2 stats")
}
