package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

var limitTestNetFlow = gopacket.NewFlow(
	layers.EndpointIPv4,
	net.IP{192, 0, 2, 1},
	net.IP{192, 0, 2, 2},
)

type discardReassemblyFactory struct{}

func (discardReassemblyFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, reassembly.AssemblerContext) reassembly.Stream {
	return &discardReassemblyStream{}
}

func assembleLimitTestTCP(a *TCPAssembler, seq uint32, syn bool, payload byte) {
	tcp := &layers.TCP{
		SrcPort: 12345, DstPort: 5060, Seq: seq, SYN: syn,
		BaseLayer: layers.BaseLayer{Payload: []byte{payload}},
	}
	a.Assemble(limitTestNetFlow, tcp, time.Unix(int64(seq), 0))
}

func TestTCPAssemblerObservesForcedGapWhenPageLimitReleasesBufferedData(t *testing.T) {
	a := NewTCPAssemblerWithLimits(discardReassemblyFactory{}, 3, 100)
	assembleLimitTestTCP(a, 1000, true, 1)
	// Leave one-byte gaps. The third buffered page forces gopacket to deliver
	// across the first gap instead of retaining unbounded out-of-order data.
	assembleLimitTestTCP(a, 1003, false, 3)
	assembleLimitTestTCP(a, 1005, false, 5)
	assembleLimitTestTCP(a, 1007, false, 7)

	stats := a.GapStats()
	if stats.ForcedGapDeliveries == 0 || stats.MissingSequenceBytes == 0 {
		t.Fatalf("gap stats = %+v, want an observed forced gap", stats)
	}
}

func TestTCPAssemblerOutOfOrderRecoveryDoesNotCountAsForcedGap(t *testing.T) {
	a := NewTCPAssemblerWithLimits(discardReassemblyFactory{}, 10, 100)
	assembleLimitTestTCP(a, 1000, true, 1)
	assembleLimitTestTCP(a, 1003, false, 3)
	assembleLimitTestTCP(a, 1002, false, 2) // fills the gap normally

	if stats := a.GapStats(); stats.ForcedGapDeliveries != 0 || stats.MissingSequenceBytes != 0 {
		t.Fatalf("gap stats = %+v after recoverable reordering, want zero", stats)
	}
}

func TestTCPAssemblerExplicitFlushGapIsNotReportedAsForcedGap(t *testing.T) {
	a := NewTCPAssemblerWithLimits(discardReassemblyFactory{}, 10, 100)
	assembleLimitTestTCP(a, 1000, true, 1)
	assembleLimitTestTCP(a, 1003, false, 3)
	a.FlushAll()

	if stats := a.GapStats(); stats.ForcedGapDeliveries != 0 || stats.MissingSequenceBytes != 0 {
		t.Fatalf("gap stats = %+v after explicit flush, want zero", stats)
	}
}

type discardReassemblyStream struct{}

func (*discardReassemblyStream) Accept(*layers.TCP, gopacket.CaptureInfo, reassembly.TCPFlowDirection, reassembly.Sequence, *bool, reassembly.AssemblerContext) bool {
	return true
}
func (*discardReassemblyStream) ReassembledSG(reassembly.ScatterGather, reassembly.AssemblerContext) {
}
func (*discardReassemblyStream) ReassemblyComplete(reassembly.AssemblerContext) bool { return true }

func TestTCPAssemblerHasFiniteBufferedPageLimits(t *testing.T) {
	a := NewTCPAssembler(discardReassemblyFactory{})
	perConnection, total := a.BufferedPageLimits()
	if perConnection != DefaultMaxBufferedPagesPerConnection || total != DefaultMaxBufferedPagesTotal {
		t.Fatalf("limits = (%d, %d), want (%d, %d)", perConnection, total, DefaultMaxBufferedPagesPerConnection, DefaultMaxBufferedPagesTotal)
	}

	a = NewTCPAssemblerWithLimits(discardReassemblyFactory{}, 7, 23)
	perConnection, total = a.BufferedPageLimits()
	if perConnection != 7 || total != 23 {
		t.Fatalf("custom limits = (%d, %d), want (7, 23)", perConnection, total)
	}
}
