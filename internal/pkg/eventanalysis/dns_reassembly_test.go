package eventanalysis

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func dnsReassemblyRuntime(t *testing.T, ports []uint16, debounce time.Duration) (*Runtime, *events.Dispatcher, *memorySink) {
	t.Helper()
	producer, err := events.NewLiveProducer("canonical-dns")
	require.NoError(t, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 128, SinkQueueSize: 128, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, dispatcher.Register(sink))
	policy := eventconfig.Default()
	dns := eventconfig.DefaultDNS()
	dns.Ports, dns.DetectTunneling, dns.Threshold, dns.Debounce = ports, true, 0, debounce
	policy.DNS = &dns
	runtime, err := New(Config{Dispatcher: dispatcher, Policy: &policy, DetectorNodeID: "analysis-owner", DetectorGeneration: "dns-generation"})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	t.Cleanup(func() {
		runtime.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, dispatcher.Close(ctx))
	})
	return runtime, dispatcher, sink
}

func canonicalDNSPayload(t *testing.T, id uint16, name string, response bool) []byte {
	t.Helper()
	message := &layers.DNS{ID: id, QR: response, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN}}}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, message))
	return buffer.Bytes()
}

func canonicalDNSFrame(payload []byte) []byte {
	framed := make([]byte, 2, len(payload)+2)
	binary.BigEndian.PutUint16(framed, uint16(len(payload)))
	return append(framed, payload...)
}

func dnsReassemblyCaptured(info capture.PacketInfo, hint string) *data.CapturedPacket {
	metadata := protocolmeta.Enrich(info.Packet, nil, false)
	metadata.Protocol = hint
	ci := info.Packet.Metadata().CaptureInfo
	return &data.CapturedPacket{Data: info.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), LinkType: uint32(info.LinkType), InterfaceName: info.Interface, CaptureLength: uint32(len(info.Packet.Data())), OriginalLength: uint32(len(info.Packet.Data())), Metadata: metadata}
}

func dnsReassemblyOutput(t *testing.T, dispatcher *events.Dispatcher, sink *memorySink) ([]events.DNSEvent, []events.NoticeEvent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, dispatcher.Flush(ctx))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var dns []events.DNSEvent
	var notices []events.NoticeEvent
	for _, event := range sink.events {
		switch value := event.(type) {
		case events.DNSEvent:
			dns = append(dns, value)
		case events.NoticeEvent:
			notices = append(notices, value)
		}
	}
	return dns, notices
}

func TestCanonicalDNSUDPValidatesRawPayloadAndConfiguredPorts(t *testing.T) {
	for _, transported := range []bool{false, true} {
		name := "local"
		if transported {
			name = "transported"
		}
		t.Run(name, func(t *testing.T) {
			runtime, dispatcher, sink := dnsReassemblyRuntime(t, []uint16{8053}, 0)
			source := Source{NodeID: "hunter", CaptureSource: "hunter", CaptureEpoch: "capture"}
			at := time.Unix(100, 0)
			observe := func(payload []byte, port uint16, hint string, truncated bool) {
				info, err := eventfixture.NetworkDatagram("192.0.2.1", "192.0.2.53", 40000, port, payload, at)
				require.NoError(t, err)
				if transported {
					raw := dnsReassemblyCaptured(info, hint)
					if hint == "DNS" {
						raw.Metadata.Dns = &data.DNSMetadata{QueryName: "unvalidated.example.test", TunnelingScore: 1}
					}
					if truncated {
						raw.OriginalLength++
					}
					require.NoError(t, runtime.ObserveCaptured(source, []*data.CapturedPacket{raw}))
					if hint == "DNS" {
						require.Equal(t, "unvalidated.example.test", raw.Metadata.Dns.QueryName, "borrowed input metadata must remain unchanged")
					}
				} else {
					info.Packet.Metadata().Truncated = truncated
					require.NoError(t, runtime.ObservePacket(source, info))
				}
			}
			payload := canonicalDNSPayload(t, 7, "raw.example.test", false)
			observe(payload, 8053, "", false)
			got, notices := dnsReassemblyOutput(t, dispatcher, sink)
			require.Len(t, got, 1)
			require.Equal(t, "raw.example.test", got[0].Query)
			require.Equal(t, at, got[0].Envelope().Timestamp)
			require.Len(t, notices, 1)
			require.Equal(t, uint64(1), notices[0].DNS.Queries)
			observe(payload, 53, "", false)
			observe(payload[:len(payload)-1], 8053, "", false)
			observe(payload, 8053, "", true)
			got, notices = dnsReassemblyOutput(t, dispatcher, sink)
			require.Len(t, got, 1, "unconfigured or incomplete UDP observations must not emit DNS")
			require.Len(t, notices, 1)
			if transported {
				observe(payload, 9053, "DNS", false)
				observe(payload[:len(payload)-1], 9053, "DNS", false)
				got, notices = dnsReassemblyOutput(t, dispatcher, sink)
				require.Len(t, got, 2, "a DNS hint must still validate the complete wire message")
				require.Equal(t, "raw.example.test", got[1].Query)
				require.Len(t, notices, 2)
				require.Equal(t, uint64(2), notices[1].DNS.Queries)
			}
		})
	}
}

func TestCanonicalDNSTCPPipeliningSegmentationAndRetransmission(t *testing.T) {
	for _, transported := range []bool{false, true} {
		name := "local"
		if transported {
			name = "transported"
		}
		t.Run(name, func(t *testing.T) {
			runtime, dispatcher, sink := dnsReassemblyRuntime(t, []uint16{8053}, 0)
			source := Source{NodeID: "hunter", CaptureSource: "hunter", CaptureEpoch: "capture", InterfaceName: "fixture"}
			at := time.Unix(100, 0)
			observe := func(sequence uint32, syn bool, payload []byte, timestamp time.Time, filtered bool) {
				info := tcpPacket(t, 40000, 8053, sequence, syn, payload, timestamp)
				current := source
				if filtered {
					current.CaptureScope = events.CaptureScopeFiltered
				}
				if transported {
					raw := dnsReassemblyCaptured(info, "DNS")
					raw.Metadata.Dns = &data.DNSMetadata{QueryName: "packet-local-fragment.test"}
					require.NoError(t, runtime.ObserveCaptured(current, []*data.CapturedPacket{raw}))
				} else {
					require.NoError(t, runtime.ObservePacket(current, info))
				}
			}
			first := canonicalDNSFrame(canonicalDNSPayload(t, 1, "first.example.test", false))
			second := canonicalDNSFrame(canonicalDNSPayload(t, 2, "second.example.test", true))
			observe(1000, true, nil, at, false)
			observe(1001, false, first[:1], at.Add(time.Second), false)
			observe(1002, false, first[1:len(first)-3], at.Add(2*time.Second), true)
			got, notices := dnsReassemblyOutput(t, dispatcher, sink)
			require.Empty(t, got)
			require.Empty(t, notices, "partial TCP messages must not reach the notice detector")
			combined := append(append([]byte(nil), first[len(first)-3:]...), second[:8]...)
			sequence := uint32(1001 + len(first) - 3)
			observe(sequence, false, combined, at.Add(3*time.Second), false)
			observe(sequence, false, combined, at.Add(4*time.Second), false)
			got, notices = dnsReassemblyOutput(t, dispatcher, sink)
			require.Len(t, got, 1)
			require.Equal(t, at.Add(3*time.Second), got[0].Envelope().Timestamp)
			require.Equal(t, events.CaptureScopeFiltered, got[0].Envelope().CaptureScope)
			require.True(t, got[0].Envelope().Partial)
			require.Len(t, notices, 1, "TCP retransmission must not create another finding")
			observe(uint32(1001+len(first)+8), false, second[8:], at.Add(5*time.Second), false)
			got, notices = dnsReassemblyOutput(t, dispatcher, sink)
			require.Len(t, got, 2)
			require.Equal(t, "first.example.test", got[0].Query)
			require.Equal(t, "second.example.test", got[1].Query)
			require.True(t, got[1].IsResponse)
			require.Equal(t, at.Add(5*time.Second), got[1].Envelope().Timestamp)
			require.Equal(t, events.CaptureScopeFull, got[1].Envelope().CaptureScope)
			require.Len(t, notices, 2)
			require.Equal(t, uint64(2), notices[1].DNS.Queries, "canonical frames count once, including responses")
			for _, notice := range notices {
				require.True(t, events.HasValidDeliveryIdentity(notice.Envelope()))
				require.Equal(t, "analysis-owner", notice.DetectorNodeID)
				require.Equal(t, "dns-generation", notice.DetectorGeneration)
			}
			require.NotEqual(t, notices[0].Envelope().EventID, notices[1].Envelope().EventID)
		})
	}
}

func TestCanonicalDNSTCPFinalByteMarkAndCaptureIsolation(t *testing.T) {
	runtime, dispatcher, sink := dnsReassemblyRuntime(t, []uint16{53}, time.Minute)
	source := Source{NodeID: "hunter-a", CaptureSource: "hunter-a", CaptureEpoch: "first", InterfaceName: "fixture"}
	at := time.Unix(100, 0)
	frame := canonicalDNSFrame(canonicalDNSPayload(t, 1, "isolated.example.test", false))
	observe := func(current Source, sequence uint32, syn bool, payload []byte, timestamp time.Time) {
		require.NoError(t, runtime.ObservePacket(current, tcpPacket(t, 40000, 53, sequence, syn, payload, timestamp)))
	}
	observe(source, 1000, true, nil, at)
	observe(source, 1001, false, frame[:8], at.Add(time.Second))
	other := source
	other.NodeID, other.CaptureSource = "hunter-b", "hunter-b"
	observe(other, 1009, false, frame[8:], at.Add(2*time.Second))
	other = source
	other.CaptureEpoch = "second"
	observe(other, 1009, false, frame[8:], at.Add(3*time.Second))
	got, notices := dnsReassemblyOutput(t, dispatcher, sink)
	require.Empty(t, got)
	require.Empty(t, notices)
	// The final-byte segment arrives before the missing middle. Provenance must
	// still use its capture mark, rather than the later gap-filling packet.
	observe(source, 1021, false, frame[20:], at.Add(4*time.Second))
	observe(source, 1009, false, frame[8:20], at.Add(5*time.Second))
	got, notices = dnsReassemblyOutput(t, dispatcher, sink)
	require.Len(t, got, 1)
	require.Equal(t, at.Add(4*time.Second), got[0].Envelope().Timestamp)
	require.Len(t, notices, 1)
	require.Equal(t, uint64(1), notices[0].DNS.Queries)

	for _, current := range []Source{other, {NodeID: "hunter-b", CaptureSource: "hunter-b", CaptureEpoch: "first", InterfaceName: "fixture"}} {
		require.NoError(t, runtime.ObservePacket(current, tcpPacket(t, 40001, 53, 5000, true, frame, at.Add(6*time.Second))))
	}
	got, notices = dnsReassemblyOutput(t, dispatcher, sink)
	require.Len(t, got, 3)
	require.Len(t, notices, 3, "source and epoch each own a debounce/evidence scope")
	for _, notice := range notices {
		require.Equal(t, uint64(1), notice.DNS.Queries)
		require.True(t, events.HasValidDeliveryIdentity(notice.Envelope()))
	}
}

func TestCanonicalDNSTCPRejectsInvalidAndIncompleteFrames(t *testing.T) {
	for _, hint := range []string{"", "DNS"} {
		t.Run("hint_"+hint, func(t *testing.T) {
			runtime, dispatcher, sink := dnsReassemblyRuntime(t, []uint16{53, 54}, 0)
			port := uint16(53)
			if hint != "" {
				port = 9053
			}
			source := Source{NodeID: "hunter", CaptureSource: "hunter", CaptureEpoch: "capture"}
			at := time.Unix(100, 0)
			observe := func(port uint16, payload []byte) {
				info := tcpPacket(t, 40000, port, 1000, true, payload, at)
				require.NoError(t, runtime.ObserveCaptured(source, []*data.CapturedPacket{dnsReassemblyCaptured(info, hint)}))
			}
			frame := canonicalDNSFrame(canonicalDNSPayload(t, 1, "complete.example.test", false))
			invalid := append([]byte{0, 0, 0, 5, 0, 0, 0, 0, 0}, canonicalDNSFrame(frame[2:len(frame)-1])...)
			observe(port, append(invalid, frame...))
			got, notices := dnsReassemblyOutput(t, dispatcher, sink)
			require.Len(t, got, 1)
			require.Equal(t, "complete.example.test", got[0].Query)
			require.Len(t, notices, 1)
			// A larger declared length must not let a packet-local parser's
			// apparently complete question bypass the frame boundary.
			incomplete := append([]byte(nil), frame...)
			binary.BigEndian.PutUint16(incomplete, uint16(len(frame)+100))
			observe(port+1, incomplete)
			runtime.EOF()
			got, notices = dnsReassemblyOutput(t, dispatcher, sink)
			require.Len(t, got, 1)
			require.Len(t, notices, 1)
			require.Positive(t, runtime.Stats().Invalid)
		})
	}
}

func TestCanonicalDNSTCPGapCannotReframeRetainedBytes(t *testing.T) {
	runtime, dispatcher, sink := dnsReassemblyRuntime(t, []uint16{53}, 0)
	source := Source{NodeID: "hunter", CaptureSource: "hunter", CaptureEpoch: "capture"}
	at := time.Unix(100, 0)
	frame := canonicalDNSFrame(canonicalDNSPayload(t, 1, "gap.example.test", false))
	observe := func(sequence uint32, syn bool, payload []byte, timestamp time.Time) {
		require.NoError(t, runtime.ObservePacket(source, tcpPacket(t, 40000, 53, sequence, syn, payload, timestamp)))
	}
	observe(1000, true, nil, at)
	observe(1001, false, frame[:10], at.Add(time.Second))
	observe(1012, false, frame[11:], at.Add(2*time.Second)) // The byte at sequence 1011 was never captured.
	boundary := at.Add(2 * runtime.cfg.Connections.IdleTimeout)
	runtime.Expire(boundary)
	got, notices := dnsReassemblyOutput(t, dispatcher, sink)
	require.Empty(t, got)
	require.Empty(t, notices, "a known TCP byte gap must not manufacture a DNS observation or finding")
	observe(10000, true, frame, boundary.Add(time.Second))
	got, notices = dnsReassemblyOutput(t, dispatcher, sink)
	require.Len(t, got, 1, "a new connection can establish its own DNS frame boundary")
	require.Equal(t, "gap.example.test", got[0].Query)
	require.Len(t, notices, 1)
	require.Equal(t, uint64(1), notices[0].DNS.Queries)
}
