package voip

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type recordingVIFManager struct {
	packets   []types.PacketDisplay
	closed    bool
	injectErr error
}

func (*recordingVIFManager) Name() string              { return "test0" }
func (*recordingVIFManager) Start() error              { return nil }
func (*recordingVIFManager) InjectPacket([]byte) error { return nil }
func (m *recordingVIFManager) InjectPacketBatch(packets []types.PacketDisplay) error {
	m.packets = append(m.packets, packets...)
	return m.injectErr
}
func (m *recordingVIFManager) Shutdown() error       { m.closed = true; return nil }
func (*recordingVIFManager) Stats() vinterface.Stats { return vinterface.Stats{} }

func TestVirtualInterfacePacketSinkConsumesNormalizedEnvelope(t *testing.T) {
	mgr := &recordingVIFManager{}
	sink := &virtualInterfacePacketSink{manager: mgr}
	env := &pipeline.PacketEnvelope{
		Data:           []byte{0, 1, 2, 3},
		LinkType:       layers.LinkTypeEthernet,
		CaptureTime:    time.Unix(123, 456),
		CaptureLength:  4,
		OriginalLength: 4,
	}

	result := sink.HandlePacket(context.Background(), env)
	require.Equal(t, pipeline.OutcomeAccepted, result.Outcome)
	require.Len(t, mgr.packets, 1)
	require.Equal(t, env.Data, mgr.packets[0].RawData)
	require.Equal(t, env.LinkType, mgr.packets[0].LinkType)
	require.NoError(t, sink.Close(context.Background()))
	require.True(t, mgr.closed)
}

func TestVirtualInterfacePacketSinkReportsInjectionFailure(t *testing.T) {
	mgr := &recordingVIFManager{injectErr: errors.New("queue full")}
	sink := &virtualInterfacePacketSink{manager: mgr}
	result := sink.HandlePacket(context.Background(), &pipeline.PacketEnvelope{Data: []byte{0}, LinkType: layers.LinkTypeEthernet})
	require.Equal(t, pipeline.OutcomeRetryableFailure, result.Outcome)
	require.ErrorContains(t, result.Err, "queue full")
}

func TestVirtualInterfacePacketSinkReportsQueueFullAsDrop(t *testing.T) {
	mgr := &recordingVIFManager{injectErr: vinterface.ErrQueueFull}
	sink := &virtualInterfacePacketSink{manager: mgr}

	result := sink.HandlePacket(context.Background(), &pipeline.PacketEnvelope{Data: []byte{0}, LinkType: layers.LinkTypeEthernet})

	require.Equal(t, pipeline.OutcomeDropped, result.Outcome)
	require.Equal(t, pipeline.DropQueueFull, result.DropReason)
	require.NoError(t, result.Err)
}
