package pipeline

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/stretchr/testify/require"
)

type provenanceAssemblyContext struct{ info gopacket.CaptureInfo }

func (c provenanceAssemblyContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

type provenanceFactory struct {
	received map[string]gopacket.CaptureInfo
}

func (f *provenanceFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, reassembly.AssemblerContext) reassembly.Stream {
	return &provenanceStream{factory: f}
}
func (*provenanceFactory) Shutdown() error { return nil }

type provenanceStream struct{ factory *provenanceFactory }

func (*provenanceStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true
	return true
}
func (s *provenanceStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	n, _ := sg.Lengths()
	if n > 0 {
		s.factory.received[string(sg.Fetch(n))] = sg.CaptureInfo(n - 1)
	}
}
func (*provenanceStream) ReassemblyComplete(reassembly.AssemblerContext) bool { return true }

func TestReassemblyContextPreservesQueuedByteProvenanceAtEOF(t *testing.T) {
	factory := &provenanceFactory{received: make(map[string]gopacket.CaptureInfo)}
	engine := NewReassemblyEngine(factory, DefaultReassemblyConfig())
	t.Cleanup(func() { require.NoError(t, engine.Close()) })
	packet := func(seq uint32, payload string, at time.Time) *PacketEnvelope {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}}
		tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: seq, ACK: true}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
		return &PacketEnvelope{Data: buffer.Bytes(), LinkType: layers.LinkTypeRaw, CaptureTime: at, Source: SourceProvenance{Kind: SourcePCAPReplay}}
	}
	at := time.Unix(100, 0)
	for _, p := range []struct {
		seq     uint32
		payload string
		id      int
	}{{100, "first", 3}, {200, "queued", 7}, {100, "first", 9}} {
		ts := at.Add(time.Duration(p.id) * time.Second)
		require.NoError(t, engine.AssembleWithContext(packet(p.seq, p.payload, ts), provenanceAssemblyContext{gopacket.CaptureInfo{Timestamp: ts, AncillaryData: []any{p.id}}}))
	}
	require.NotContains(t, factory.received, "queued")
	require.NoError(t, engine.Close())
	require.Equal(t, []any{7}, factory.received["queued"].AncillaryData)
	require.Equal(t, at.Add(7*time.Second), factory.received["queued"].Timestamp)
}
