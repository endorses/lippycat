package capture

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
)

type admissionStatusFunc func() mediaadmission.Snapshot

func (f admissionStatusFunc) Status() mediaadmission.Snapshot { return f() }
func TestCaptureAdmissionHeartbeatSnapshot(t *testing.T) {
	var reported Telemetry
	collector := newTelemetryCollector(func(t Telemetry) { reported = t })
	collector.admission = admissionStatusFunc(func() mediaadmission.Snapshot {
		return mediaadmission.Snapshot{Enabled: true, ConfiguredMode: mediaadmission.ModeEnforce, Scopes: []mediaadmission.ScopeTelemetry{{ScopeStatus: mediaadmission.ScopeStatus{State: mediaadmission.StateDegradedOpen, InstalledEndpoints: 3, PendingUpdates: 2, UpdateErrors: 1}, Counters: [16]uint64{6: 4, 11: 5}}}}
	})
	got := collector.report("eth0", 10, 2, 1, nil)
	require.Equal(t, int64(2), got.KernelDrops)
	require.Equal(t, int64(1), got.InterfaceDrops)
	require.Zero(t, got.PacketBufferDrops)
	require.Equal(t, 3, reported.MediaAdmission.Scopes[0].InstalledEndpoints)
	fields := admissionHeartbeatFields(got.MediaAdmission)
	values := map[string]any{}
	for i := 0; i < len(fields); i += 2 {
		values[fields[i].(string)] = fields[i+1]
	}
	require.Equal(t, 2, values["rtp_ebpf_pending"])
	require.Equal(t, uint64(4), values["rtp_ebpf_compatibility_passes"])
	require.Equal(t, uint64(5), values["rtp_ebpf_evidence_lost"])
	require.Nil(t, admissionHeartbeatFields(nil))
}
