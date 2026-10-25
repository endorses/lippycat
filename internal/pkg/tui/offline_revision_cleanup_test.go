//go:build tui || all

package tui

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineSessionDiscardCandidateRetriesWithoutClosingBaseExport(t *testing.T) {
	storage := testOfflineStorage(t)
	session, snapshot, err := indexOfflineProgressiveDataset(context.Background(), storage, 509, OfflineAnalysisConfig{Inputs: []string{writeOfflineEventFlows(t, 8)}, EventCapacity: 1}, nil, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	query, err := offline.AllPackets(context.Background(), session.Dataset, offline.Token{Dataset: 509, Revision: offline.BaseRevision})
	require.NoError(t, err)
	pin, err := offline.PinQuery(query)
	require.NoError(t, err)
	defer func() { require.NoError(t, pin.Close()) }()
	candidate := session.analysisCandidate
	failure := errors.New("candidate reader cleanup failed")
	attempts := 0
	require.NoError(t, candidate.registerViewCloser(offlineEventCloserFunc(func() error {
		attempts++
		if attempts == 1 {
			return failure
		}
		return nil
	}), nil))
	for _, first := range []bool{true, false} {
		result := make(chan error, 1)
		go func() { result <- session.discardAnalysisCandidate() }()
		select {
		case err := <-result:
			if first {
				require.ErrorIs(t, err, failure)
				require.Same(t, candidate, session.analysisCandidate)
			} else {
				require.NoError(t, err)
				require.Nil(t, session.analysisCandidate)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("discard blocked on the retained base export pin")
		}
		visits := 0
		require.NoError(t, pin.IterateRaw(context.Background(), func(record offline.RawRecord) error {
			visits++
			require.NotEmpty(t, record.RawData)
			return nil
		}))
		require.Equal(t, 8, visits)
		detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 509, Revision: offline.BaseRevision}, 7)
		require.NoError(t, err)
		require.Empty(t, detail.Packet.Protocol)
	}
	require.Equal(t, 2, attempts)
	_, err = snapshot.Dataset.Detail(context.Background(), offline.Token{Dataset: 509, Revision: offline.CompletedRevision}, 0)
	require.Error(t, err, "successfully discarded completed storage is closed")
	require.NoError(t, pin.Close())
	require.NoError(t, session.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineSessionDiscardCandidateSerializesWithClose(t *testing.T) {
	storage := testOfflineStorage(t)
	session, _, err := indexOfflineProgressiveDataset(context.Background(), storage, 510, OfflineAnalysisConfig{Inputs: []string{writeOfflineEventFlows(t, 8)}, EventCapacity: 1}, nil, nil)
	require.NoError(t, err)
	result := make(chan error, 2)
	go func() { result <- session.discardAnalysisCandidate() }()
	go func() { result <- session.Close() }()
	for range 2 {
		select {
		case err := <-result:
			require.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("candidate discard and session close did not join")
		}
	}
	require.Nil(t, session.analysisCandidate)
	require.NoError(t, session.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}
