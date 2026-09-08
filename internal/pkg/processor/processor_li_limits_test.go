//go:build (processor || tap || all) && li

package processor

import (
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLIDeliveryInvalidLimitsRejectedWithoutTransport(t *testing.T) {
	old, oldManager := liDeliveryClient, liDeliveryMgr
	liDeliveryClient, liDeliveryMgr = nil, nil
	t.Cleanup(func() { liDeliveryClient, liDeliveryMgr = old, oldManager })
	p := &Processor{config: Config{LIDeliveryX3QueueBytes: -1}, liManager: li.NewManager(li.ManagerConfig{Enabled: true}, nil)}
	require.ErrorContains(t, p.validateLIConfiguration(), "invalid LI delivery limits")
	p.config.LIDeliveryX3QueueBytes = 0
	p.config.LIDeliveryX2SpoolDir = "spool"
	p.config.LIDeliveryX2SpoolMaxBytes = 1 << 20
	p.config.LIDeliveryX2SpoolKeyFile = "key"
	require.ErrorContains(t, p.validateLIConfiguration(), "requires configured delivery TLS")
}
