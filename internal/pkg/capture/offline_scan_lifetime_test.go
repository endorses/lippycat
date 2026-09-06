package capture

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestOfflineBackingScanCancellationAndShutdown(t *testing.T) {
	for _, policy := range []offline.BackingPolicy{offline.BackingSource, offline.BackingSnapshot} {
		t.Run(string(policy), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.pcap")
			require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, [][]byte{make([]byte, 60)}, false, false), 0600))
			storage := sortTestStorage(t, 1<<20)
			registry := storage.NewBackingRegistry()
			ctx, cancel := context.WithCancel(WithOfflineBackings(context.Background(), registry, policy))
			defer cancel()
			cursor, err := newOfflineCursor(ctx, offlineTestDevices(t, path)[0], "", 0)
			require.NoError(t, err)
			defer func() { require.NoError(t, cursor.Close()) }()
			done := make(chan error, 1)
			go func() { done <- registry.Close() }()
			select {
			case err := <-done:
				t.Fatalf("registry closed with an active parser: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			cancel()
			_, err = cursor.Next(ctx)
			require.ErrorIs(t, err, context.Canceled)
			require.NoError(t, cursor.Close())
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("cancelled parser retained its scan lease")
			}
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
		})
	}
}

func TestOfflineBackingTruncatedDuringScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, [][]byte{make([]byte, 8193)}, false, false), 0600))
	registry := sortTestStorage(t, 1<<20).NewBackingRegistry()
	defer func() { require.NoError(t, registry.Close()) }()
	ctx := WithOfflineBackings(context.Background(), registry, offline.BackingSource)
	cursor, err := newOfflineCursor(ctx, offlineTestDevices(t, path)[0], "", 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, cursor.Close()) }()
	require.NoError(t, os.Truncate(path, 24))
	_, err = cursor.Next(ctx)
	require.ErrorIs(t, err, offline.ErrSourceChanged)
}
