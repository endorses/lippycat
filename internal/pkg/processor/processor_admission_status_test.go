//go:build processor || tap || all

package processor

import (
	"context"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAdmissionHeartbeatAppearsInStatusAndTopology(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "admission-processor", ListenAddr: "localhost:55555", MaxHunters: 10})
	require.NoError(t, err)
	defer p.Shutdown()
	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{HunterId: "hunter-admission", Hostname: "host"})
	require.NoError(t, err)
	incoming := &management.MediaAdmissionStatus{Enabled: true, ConfiguredMode: "enforce", Scopes: []*management.MediaAdmissionScope{{State: "enforcing", DesiredGeneration: 7, InstalledGeneration: 7, InstalledEndpoints: 2, DecisionCounters: []uint64{3, 4}}}}
	p.hunterManager.UpdateHeartbeat("hunter-admission", time.Now().UnixNano(), management.HunterStatus_STATUS_HEALTHY, &management.HunterStats{RtpEbpf: incoming})
	incoming.Scopes[0].InstalledEndpoints = 100
	status, err := p.GetHunterStatus(context.Background(), &management.StatusRequest{HunterId: "hunter-admission"})
	require.NoError(t, err)
	require.Len(t, status.Hunters, 1)
	require.Equal(t, uint64(2), status.Hunters[0].Stats.RtpEbpf.Scopes[0].InstalledEndpoints)
	status.Hunters[0].Stats.RtpEbpf.Scopes[0].DecisionCounters[0] = 100
	topology, err := p.GetTopology(context.Background(), &management.TopologyRequest{})
	require.NoError(t, err)
	require.Len(t, topology.Processor.Hunters, 1)
	require.Equal(t, uint64(3), topology.Processor.Hunters[0].Stats.RtpEbpf.Scopes[0].DecisionCounters[0])
}
