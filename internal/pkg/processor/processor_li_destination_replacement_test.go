//go:build (processor || tap || all) && li

package processor

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestLIDeliveryReplacementReservesCapacityAndRecoversRefusedDestination(t *testing.T) {
	cfg := delivery.DefaultConfig()
	certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
	cfg.TLSCertFile = filepath.Join(certDir, "delivery-client-cert.pem")
	cfg.TLSKeyFile = filepath.Join(certDir, "delivery-client-key.pem")
	cfg.TLSCAFile = filepath.Join(certDir, "ca-cert.pem")
	cfg.DialTimeout = time.Millisecond
	manager, err := delivery.NewManager(cfg)
	require.NoError(t, err)
	t.Cleanup(manager.Stop)
	limits := delivery.DefaultClientConfig()
	limits.QueueSize = 1
	limits.X2QueueBytes, limits.X3QueueBytes = 1024, 1024
	perDestination, err := limits.ReservedDestinationBytes()
	require.NoError(t, err)
	global, err := limits.ReservedGlobalBytes()
	require.NoError(t, err)
	limits.MemoryBudgetBytes = global + perDestination
	client := delivery.NewClient(manager, limits)
	require.NoError(t, client.Err())
	t.Cleanup(client.Stop)
	first := &li.Destination{DID: uuid.New(), Address: "127.0.0.1", Port: 1, X2Enabled: true}
	second := &li.Destination{DID: uuid.New(), Address: "127.0.0.1", Port: 2, X2Enabled: true}
	require.NoError(t, replaceLIDeliveryDestination(manager, client, first))
	replacement := *first
	replacement.Port = 3
	require.NoError(t, replaceLIDeliveryDestination(manager, client, &replacement))
	require.Contains(t, client.DestinationStats(), first.DID, "replacement must reserve its queue even before any PDU arrives")
	require.ErrorIs(t, replaceLIDeliveryDestination(manager, client, second), delivery.ErrQueueFull)
	_, err = manager.GetDestination(second.DID)
	require.ErrorIs(t, err, delivery.ErrDestinationNotFound)
	require.NoError(t, manager.RemoveDestination(first.DID))
	client.RemoveDestination(first.DID)
	require.NoError(t, replaceLIDeliveryDestination(manager, client, second), "modification must recover a previously refused destination once capacity is available")
	require.Contains(t, client.DestinationStats(), second.DID)
}
