//go:build li

package delivery

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
	"time"
)

func TestBufferLimitsValidation(t *testing.T) {
	require.NoError(t, DefaultClientConfig().Validate())
	for _, config := range []ClientConfig{
		{X2QueueSize: -1}, {X3QueueSize: -1}, {X2QueueBytes: -1}, {X3QueueBytes: -1}, {QueueSize: -1}, {X3MaxAge: -time.Second},
		{MemoryBudgetBytes: -1}, {MemoryBudgetBytes: 100},
		{X2QueueBytes: 100, X3QueueBytes: 100, MemoryBudgetBytes: 100},
		{X2QueueBytes: math.MaxInt64, X3QueueBytes: 1},
		{X2SpoolMaxBytes: 1}, {X2SpoolKeyFile: "key"}, {X2SpoolDir: "spool"},
	} {
		require.Error(t, config.Validate(), "%+v", config)
	}
	config := ClientConfig{QueueSize: 1, X2QueueBytes: 100, X3QueueBytes: 200}
	reserved, err := config.ReservedDestinationBytes()
	require.NoError(t, err)
	global, err := config.ReservedGlobalBytes()
	require.NoError(t, err)
	config.MemoryBudgetBytes = reserved + global
	require.NoError(t, config.Validate())
	config.MemoryBudgetBytes--
	require.Error(t, config.Validate())
}

func TestIndependentPDUCapacityOverrides(t *testing.T) {
	c := ClientConfig{QueueSize: 100, X2QueueSize: 5, X3QueueSize: 7}
	x2, x3 := c.EffectiveQueueSizes()
	require.Equal(t, 5, x2)
	require.Equal(t, 7, x3)
	reserved, err := c.ReservedDestinationBytes()
	require.NoError(t, err)
	require.EqualValues(t, 12*1024+256*1024, reserved)
	c.X2QueueSize = 0
	x2, x3 = c.EffectiveQueueSizes()
	require.Equal(t, 100, x2)
	require.Equal(t, 7, x3)
}

func TestMemoryBudgetReservesAdmissionAlongsideFullQueues(t *testing.T) {
	for _, limits := range [][2]int64{{32 << 20, 1 << 20}, {1 << 20, 32 << 20}} {
		config := ClientConfig{QueueSize: 1, X2QueueBytes: limits[0], X3QueueBytes: limits[1]}
		queues, err := config.ReservedDestinationBytes()
		require.NoError(t, err)
		// A full destination can coexist with one cloned incoming PDU while
		// admission checks whether it can evict or must reject that PDU.
		config.MemoryBudgetBytes = queues + DefaultReorderBudgetBytes
		require.Error(t, config.Validate(), "queue-only sizing omits the admitted payload clone")
		config.MemoryBudgetBytes += 32 << 20
		require.NoError(t, config.Validate())
		client := NewClient(nil, config)
		defer client.Stop()
		require.NoError(t, client.ReserveDestination(uuid.New()))
		_, budget, reserved := client.ResourceLimits()
		require.Equal(t, budget, reserved)
		require.Error(t, client.ReserveDestination(uuid.New()))
	}
	_, err := (ClientConfig{X3QueueBytes: math.MaxInt64}).ReservedGlobalBytes()
	require.Error(t, err, "admission scratch must not overflow global reservation")
}

func TestDocumentedDeliverySizingConfiguration(t *testing.T) {
	c := ClientConfig{QueueSize: 100000, X2QueueBytes: 67108864, X3QueueBytes: 83886080, X3MaxAge: 5 * time.Minute, MemoryBudgetBytes: 4294967296, X2SpoolDir: "/var/lib/lippycat/x2", X2SpoolMaxBytes: 1073741824, X2SpoolKeyFile: "/etc/lippycat/x2.key", X2SpoolReplayPolicy: "hold"}
	require.NoError(t, c.Validate())
}
