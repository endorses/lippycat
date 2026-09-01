package pipeline

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// benchmarkReassemblyFactory consumes every delivered byte without starting
// parser goroutines. The synthetic payload is a complete, generic SIP message;
// keeping the sink minimal isolates flow-sharded TCP reassembly throughput.
type benchmarkReassemblyFactory struct {
	bytes atomic.Uint64
}

func (f *benchmarkReassemblyFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, reassembly.AssemblerContext) reassembly.Stream {
	return &benchmarkReassemblyStream{bytes: &f.bytes}
}

func (*benchmarkReassemblyFactory) Shutdown() error { return nil }

type benchmarkReassemblyStream struct {
	bytes *atomic.Uint64
}

func (*benchmarkReassemblyStream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true
	return true
}

func (s *benchmarkReassemblyStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length > 0 {
		sg.Fetch(length)
		s.bytes.Add(uint64(length))
	}
}

func (*benchmarkReassemblyStream) ReassemblyComplete(reassembly.AssemblerContext) bool { return true }

type benchmarkTCPFlow struct {
	network gopacket.Flow
	port    layers.TCPPort
}

func BenchmarkReassemblyEngineSIPOverTCP(b *testing.B) {
	const flowCount = 64
	payload := []byte("OPTIONS sip:service@example.invalid SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKsynthetic\r\n" +
		"From: <sip:sender@example.invalid>;tag=generic\r\n" +
		"To: <sip:service@example.invalid>\r\n" +
		"Call-ID: benchmark@example.invalid\r\n" +
		"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
	flows := make([]benchmarkTCPFlow, flowCount)
	for i := range flows {
		flows[i] = benchmarkTCPFlow{
			network: gopacket.NewFlow(layers.EndpointIPv4,
				[]byte{192, 0, 2, byte(i + 1)}, []byte{198, 51, 100, byte(i + 1)}),
			port: layers.TCPPort(10000 + i),
		}
	}

	for _, shards := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("shards_%d", shards), func(b *testing.B) {
			factory := &benchmarkReassemblyFactory{}
			engine := NewReassemblyEngine(factory, ReassemblyConfig{ShardCount: shards})
			for _, flow := range flows {
				syn := &layers.TCP{SrcPort: flow.port, DstPort: 5060, Seq: 1, SYN: true}
				if err := engine.AssembleTCP(flow.network, syn, time.Unix(1, 0)); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			var workers sync.WaitGroup
			for worker, flow := range flows {
				packets := b.N / flowCount
				if worker < b.N%flowCount {
					packets++
				}
				if packets == 0 {
					continue
				}
				workers.Add(1)
				go func(flow benchmarkTCPFlow, packets int) {
					defer workers.Done()
					seq := uint32(2)
					for range packets {
						tcp := &layers.TCP{
							SrcPort: flow.port, DstPort: 5060, Seq: seq, ACK: true,
						}
						tcp.Payload = payload
						if err := engine.AssembleTCP(flow.network, tcp, time.Unix(2, 0)); err != nil {
							b.Error(err)
							return
						}
						seq += uint32(len(payload)) // #nosec G115 -- bounded benchmark payload
					}
				}(flow, packets)
			}
			workers.Wait()
			b.StopTimer()

			if err := engine.Close(); err != nil {
				b.Fatal(err)
			}
			stats := engine.LimitStats()
			if stats.MissingSequenceBytes != 0 || stats.NormalDiscontinuities != 0 || stats.ExplicitFlushDiscontinuities != 0 {
				b.Fatalf("reassembly integrity gap: %+v", stats)
			}
			expectedBytes := uint64(b.N) * uint64(len(payload))
			if delivered := factory.bytes.Load(); delivered != expectedBytes {
				b.Fatalf("reassembled byte mismatch: got %d, want %d", delivered, expectedBytes)
			}
			b.ReportMetric(float64(stats.MissingSequenceBytes), "missing_bytes")
			b.ReportMetric(float64(stats.NormalDiscontinuities+stats.ExplicitFlushDiscontinuities), "integrity_gaps")
			if elapsed := b.Elapsed(); elapsed > 0 {
				b.ReportMetric(float64(b.N)/elapsed.Seconds(), "packets/s")
			}
		})
	}
}
