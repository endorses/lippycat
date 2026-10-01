//go:build (processor || tap || all) && li

package processor

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestLIStartupReconciliationPrecedesRemoteServing(t *testing.T) {
	response, err := xml.Marshal(schema.GetAllDetailsResponse{
		ListOfTaskResponseDetails:        &schema.ListOfTaskResponseDetails{},
		ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{},
	})
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("read ADMF request: %v", err)
			return
		}
		if bytes.Contains(body, []byte("GetAllDetails")) {
			enteredOnce.Do(func() { close(entered) })
			<-release
		}
		w.Header().Set("Content-Type", "application/xml")
		if _, err := w.Write(response); err != nil {
			t.Logf("ADMF response ended: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	stateFile, keys := newTestFilterFile(t), newTestFilterKeys(t)
	_, err = li.InitializeEncryptedStateStore(stateFile, keys, li.StateOfflineOptions{})
	require.NoError(t, err)
	p, err := newTestProcessor(t, Config{
		ListenAddr: "127.0.0.1:0", ProcessorID: "startup-order", LIEnabled: true,
		LIStateFile: stateFile, LIStateKeys: keys,
		LIADMFEndpoint: server.URL, LIADMFSyncOnStartup: true, LIADMFSyncTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); cancel() })
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("startup ended before reconciliation: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("startup did not request ADMF reconciliation")
	}
	stats := &management.ProcessorStats{}
	p.populateLIEncodingStats(stats)
	require.NotNil(t, stats.LiStartupSync)
	require.Equal(t, "pending", stats.LiStartupSync.State)
	require.EqualValues(t, 1, stats.LiStartupSync.Attempts)
	require.Equal(t, p.liManager.StartupSyncStatus().LastAttempt.UTC().Format(time.RFC3339Nano), stats.LiStartupSync.LastAttempt)
	require.Empty(t, stats.LiStartupSync.RecoveredAt)
	p.listenerMu.Lock()
	address := p.listener.Addr().String()
	p.listenerMu.Unlock()
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	client := management.NewManagementServiceClient(connection)
	probe, probeCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = client.GetFilters(probe, &management.FilterRequest{})
	probeCancel()
	require.Error(t, err, "remote policy must not be served while administrative startup is incomplete")
	releaseOnce.Do(func() { close(release) })
	ready, readyCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer readyCancel()
	_, err = client.GetFilters(ready, &management.FilterRequest{}, grpc.WaitForReady(true))
	require.NoError(t, err, "serving begins after the real encrypted state and ADMF path completes")
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("processor did not stop")
	}
}

func TestLIStartupDeliveryFailureReleasesPreparedState(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	// Valid keys pass the initial preflight, but the actual journal is malformed.
	// State ownership acquired before that failure must be released by New.
	require.NoError(t, os.Mkdir(cfg.LIDeliveryX2SpoolDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.LIDeliveryX2SpoolDir, ".state"), []byte("invalid journal"), 0600))
	p, err := New(cfg)
	require.Error(t, err)
	require.Nil(t, p)
	store, err := li.OpenStateStore(cfg.LIStateFile, cfg.LIStateKeys)
	require.NoError(t, err, "failed delivery construction must release authenticated state ownership")
	require.NoError(t, store.Close())
	filter := filterStorageBackend(t, cfg)
	_, err = filter.Load(cfg.FilterFile)
	require.NoError(t, err, "failed delivery construction must release managed filter ownership")
}
