//go:build (processor || tap || all) && li

package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const finalizedCallID = "phase0-finalized-call@example.invalid"

func newFinalizationReproductionProcessor(t *testing.T, pcapEnabled bool) (*Processor, string) {
	t.Helper()

	config := Config{
		ProcessorID: "phase0-finalization-reproduction",
		ListenAddr:  "localhost:0",
		MaxHunters:  1,
		LIEnabled:   true,
		FilterFile:  t.TempDir() + "/filters.yaml",
	}
	if pcapEnabled {
		config.PcapWriterConfig = &PcapWriterConfig{
			Enabled:      true,
			OutputDir:    t.TempDir(),
			FilePattern:  "{callid}.pcap",
			SyncInterval: time.Hour,
		}
	}

	p, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := p.Shutdown(); err != nil {
			t.Logf("processor shutdown: %v", err)
		}
	})

	filterID := activateFinalizationReproductionTask(t, p)
	return p, filterID
}

func activateFinalizationReproductionTask(t *testing.T, p *Processor) string {
	t.Helper()

	// Reuse the synthetic direction fixture's target; this reproduction only
	// needs the generated filter ID, not a delivery connection.
	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{
		DID: did, Address: "mdf.example.invalid", Port: 9999,
		X2Enabled: true, X3Enabled: true,
	}))
	taskID := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{
		XID: taskID, Targets: []li.TargetIdentity{dirTarget},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX3Only,
	}))

	return "li-" + taskID.String() + "-0"
}

func finalizedCallRTP() *types.PacketDisplay {
	pkt := dirRTPPacket(0x13572468, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort)
	pkt.VoIPData.CallID = finalizedCallID
	return pkt
}

func TestPhase4FinalizedCallWithPCAPIsRejectedByX3(t *testing.T) {
	p, filterID := newFinalizationReproductionProcessor(t, true)
	require.NotNil(t, p.sessionOutputManager)

	require.NoError(t, p.sessionOutputManager.WritePacket(
		finalizedCallID, "alice", "bob", time.Now(), []byte("synthetic packet"),
		layers.LinkTypeEthernet, true,
	))
	result, err := p.sessionOutputManager.writer.FinalizeCall(finalizedCallID, CallFinalizationProtocolComplete)
	require.NoError(t, err)
	require.True(t, result.Finalized)

	lateWriteErr := p.sessionOutputManager.WritePacket(
		finalizedCallID, "alice", "bob", time.Now(), []byte("late synthetic packet"),
		layers.LinkTypeEthernet, true,
	)
	assert.True(t, IsCallFinalized(lateWriteErr), "PCAP must reject the late finalized-call packet")

	before := p.getLIEncodingStats()
	p.processLIPacket(finalizedCallRTP(), []string{filterID})
	after := p.getLIEncodingStats()
	assert.Equal(t, before.X3Encoded, after.X3Encoded)
	assert.Equal(t, before.X3FinalizedSuppressed+1, after.X3FinalizedSuppressed)
}

func TestPhase4FinalizedCallWithoutPCAPIsRejectedByX3(t *testing.T) {
	p, filterID := newFinalizationReproductionProcessor(t, false)
	require.NotNil(t, p.sessionOutputManager)
	require.Nil(t, p.sessionOutputManager.writer)
	require.NotNil(t, p.callLifecycle,
		"LI requires terminal call state even when PCAP output is disabled")

	bye := dirSIPPacket("BYE "+dirTargetURI+" SIP/2.0", 0, dirRemoteURI, dirTargetURI, "xyz", "")
	bye.VoIPData.CallID = finalizedCallID
	bye.VoIPData.Method = "BYE"
	bye.VoIPData.CSeqMethod = "BYE"
	p.processLIPacket(bye, []string{filterID})
	result := p.callLifecycle.Finalize(finalizedCallID, CallFinalizationProtocolComplete)
	require.True(t, result.Finalized)
	assert.True(t, p.callLifecycle.IsFinalized(finalizedCallID))

	before := p.getLIEncodingStats()
	p.processLIPacket(finalizedCallRTP(), []string{filterID})
	after := p.getLIEncodingStats()
	assert.Equal(t, before.X3Encoded, after.X3Encoded)
	assert.Equal(t, before.X3FinalizedSuppressed+1, after.X3FinalizedSuppressed)
}
