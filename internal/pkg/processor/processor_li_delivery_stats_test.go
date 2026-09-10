//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/stats"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLIDeliveryStatusReportsOverflowAndUnavailableDestination(t *testing.T) {
	config := delivery.DefaultConfig()
	certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
	config.TLSCertFile = filepath.Join(certDir, "delivery-client-cert.pem")
	config.TLSKeyFile = filepath.Join(certDir, "delivery-client-key.pem")
	config.TLSCAFile = filepath.Join(certDir, "ca-cert.pem")
	config.DialTimeout = 50 * time.Millisecond
	config.X2KeepaliveEnabled = true
	manager, err := delivery.NewManager(config)
	require.NoError(t, err)
	t.Cleanup(manager.Stop)
	clientConfig := delivery.DefaultClientConfig()
	clientConfig.QueueSize = 1
	clientConfig.SendTimeout = 50 * time.Millisecond
	clientConfig.ShutdownTimeout = 10 * time.Millisecond
	client := delivery.NewClient(manager, clientConfig)
	t.Cleanup(client.Stop)
	oldClient, oldManager := liDeliveryClient, liDeliveryMgr
	liDeliveryClient, liDeliveryMgr = client, manager
	t.Cleanup(func() { liDeliveryClient, liDeliveryMgr = oldClient, oldManager })

	p := &Processor{liManager: li.NewManager(li.ManagerConfig{Enabled: true}, nil)}
	p.hunterManager = hunter.NewManager("delivery-test", 1, nil)
	p.statsCollector = stats.NewCollector("delivery-test", &p.packetsReceived, &p.packetsForwarded)
	did, idleDID, unusedDID := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{did, idleDID, unusedDID} {
		require.NoError(t, manager.AddDestination(&li.Destination{DID: id, Address: "127.0.0.1", Port: 1}))
	}
	xid := uuid.New()
	// One call fans out to two destination queues; the next call overflows one.
	require.NoError(t, client.SendX2(xid, []uuid.UUID{did, idleDID}, []byte("first")))
	require.NoError(t, client.SendX2(xid, []uuid.UUID{did}, []byte("second")))
	client.Start()
	require.Eventually(t, func() bool { return client.Stats().Retries > 0 }, time.Second, time.Millisecond)

	response, err := p.GetHunterStatus(context.Background(), &management.StatusRequest{})
	require.NoError(t, err)
	wire, err := proto.Marshal(response)
	require.NoError(t, err)
	decoded := &management.StatusResponse{}
	require.NoError(t, proto.Unmarshal(wire, decoded))
	got := decoded.ProcessorStats.LiDelivery
	require.NotNil(t, got)
	assert.Equal(t, uint64(2), got.X2EnqueueCalls)
	assert.Zero(t, got.X2Written)
	assert.Equal(t, uint64(1), got.X2Dropped)
	assert.Equal(t, int64(2), got.QueueDepth)
	assert.Positive(t, got.Retries)
	dest := got.Destinations[did.String()]
	require.NotNil(t, dest)
	assert.Equal(t, uint64(1), dest.DroppedByReason["queue_overflow"])
	assert.Equal(t, uint64(1), dest.X2QueueDepth)
	assert.Equal(t, uint64(1), dest.X2QueueCapacity)
	assert.Zero(t, dest.LastWriteUnixMs)
	assert.Zero(t, dest.X2Connections)
	assert.NotEqual(t, "connected", dest.ConnectionState)
	assert.True(t, dest.X2Keepalive.Enabled)
	assert.Equal(t, config.X2KeepaliveTimeP2.Milliseconds(), dest.X2Keepalive.TimeoutMs)
	assert.Zero(t, dest.X2Keepalive.LastAckUnixMs)
	require.NotNil(t, got.Destinations[unusedDID.String()])
	assert.Zero(t, got.Destinations[unusedDID.String()].QueueDepth)
	assert.True(t, got.Destinations[unusedDID.String()].X2Keepalive.Enabled)

	// A caller cannot mutate the delivery client's reason map via its snapshot.
	response.ProcessorStats.LiDelivery.Destinations[did.String()].DroppedByReason["queue_overflow"] = 999
	p.populateLIDeliveryStats(response.ProcessorStats)
	assert.Equal(t, uint64(1), response.ProcessorStats.LiDelivery.Destinations[did.String()].DroppedByReason["queue_overflow"])

	client.RemoveDestination(did)
	require.NoError(t, manager.RemoveDestination(did))
	p.populateLIDeliveryStats(response.ProcessorStats)
	assert.NotContains(t, response.ProcessorStats.LiDelivery.Destinations, did.String())
	assert.Equal(t, uint64(2), response.ProcessorStats.LiDelivery.X2Dropped)
}

func TestLIDeliveryStatusAbsentWhenDisabledOrUnconfigured(t *testing.T) {
	oldClient := liDeliveryClient
	t.Cleanup(func() { liDeliveryClient = oldClient })
	liDeliveryClient = nil
	for _, p := range []*Processor{{}, {liManager: li.NewManager(li.ManagerConfig{Enabled: true}, nil)}} {
		dst := &management.ProcessorStats{}
		p.populateLIDeliveryStats(dst)
		assert.Nil(t, dst.LiDelivery)
		p.populateLIDeliveryStats(nil)
	}
}
