//go:build processor || tap || all

package processor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/processor/subscriber"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
)

type radiusVirtualInterface struct{ packets []types.PacketDisplay }

func (*radiusVirtualInterface) Name() string              { return "test" }
func (*radiusVirtualInterface) Start() error              { return nil }
func (*radiusVirtualInterface) InjectPacket([]byte) error { return nil }
func (v *radiusVirtualInterface) InjectPacketBatch(p []types.PacketDisplay) error {
	v.packets = append(v.packets, p...)
	return nil
}
func (*radiusVirtualInterface) Shutdown() error         { return nil }
func (*radiusVirtualInterface) Stats() vinterface.Stats { return vinterface.Stats{} }

func TestRADIUSVirtualInterfaceRetainsCapture(t *testing.T) {
	f, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	raw, ci, err := r.ReadPacketData()
	require.NoError(t, err)
	scope := radius.CaptureScope{OriginNodeID: "original", SourceID: "mirror", Epoch: [16]byte{1}}
	o, _, err := radius.DecodePacket(raw, r.LinkType(), ci, scope, radius.Identity{Epoch: scope.Epoch, Sequence: 1})
	require.NoError(t, err)
	packet := &data.CapturedPacket{Data: raw, TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(r.LinkType()), Radius: grpcadapter.RADIUSToProto(o)}
	batch, err := source.FromProtoBatchE(&data.PacketBatch{HunterId: "relay", Packets: []*data.CapturedPacket{packet}})
	require.NoError(t, err)
	vif := &radiusVirtualInterface{}
	p := &Processor{config: Config{ProcessorID: "test"}, subscriberManager: subscriber.NewManager(1), vifManager: vif}
	p.processBatch(batch)
	require.Len(t, vif.packets, 1)
	require.Equal(t, raw, vif.packets[0].RawData)
	require.Equal(t, r.LinkType(), vif.packets[0].LinkType)
	require.True(t, time.Unix(0, packet.TimestampNs).Equal(vif.packets[0].Timestamp))
	require.Equal(t, "RADIUS", vif.packets[0].Protocol)
	require.Equal(t, scope, batch.Envelopes[0].RADIUS.Scope)
}
