//go:build processor || tap || all

package processor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type diagnosticLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *diagnosticLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *diagnosticLogBuffer) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func diagnosticEnvelope(t *testing.T, body string, tcp bool) *pipeline.PacketEnvelope {
	t.Helper()
	message := []byte(fmt.Sprintf("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:selected@example.invalid>\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: synthetic-central\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	return diagnosticPayloadEnvelope(t, message, tcp)
}

func diagnosticPayloadEnvelope(t *testing.T, payload []byte, tcp bool) *pipeline.PacketEnvelope {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	var transport gopacket.SerializableLayer
	if tcp {
		ip.Protocol = layers.IPProtocolTCP
		layer := &layers.TCP{SrcPort: 5060, DstPort: 5060, ACK: true, PSH: true, Seq: 1}
		require.NoError(t, layer.SetNetworkLayerForChecksum(ip))
		transport = layer
	} else {
		ip.Protocol = layers.IPProtocolUDP
		layer := &layers.UDP{SrcPort: 5060, DstPort: 5060}
		require.NoError(t, layer.SetNetworkLayerForChecksum(ip))
		transport = layer
	}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, transport, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeRaw, gopacket.Default)
	packet.Metadata().CaptureLength, packet.Metadata().Length = len(packet.Data()), len(packet.Data())
	return pipeline.NewDecodedPacketEnvelope(packet, layers.LinkTypeRaw)
}

func TestSDPDiagnosticsCentralIngressWithoutAdmissionOrEventDemand(t *testing.T) {
	var logs diagnosticLogBuffer
	logger.UseFile(&logs)
	t.Cleanup(logger.Enable)
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "synthetic-central"})
	require.NoError(t, err)
	require.Nil(t, p.eventRuntime)
	require.Nil(t, p.detector)
	partial := diagnosticEnvelope(t, "c=IN IP4 192.0.2.1\r\nm=audio 8000 RTP/AVP 0\r\nm=invalid\r\n", false)
	failure := diagnosticEnvelope(t, "m=invalid\r\n", true)
	inactive := diagnosticEnvelope(t, "c=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n", false)
	before := append([]byte(nil), partial.Data...)
	p.processBatch(&source.PacketBatch{SourceID: "synthetic-hunter", Envelopes: []*pipeline.PacketEnvelope{partial, failure, inactive}})
	require.Nil(t, p.eventRuntime, "diagnostics never creates optional analysis runtime")
	require.Equal(t, before, partial.Data)
	require.Nil(t, partial.Metadata, "diagnostics never changes output metadata")
	stats := p.sdpDiagnostics.counters.Snapshot()
	require.Equal(t, uint64(3), stats.Bodies)
	require.Equal(t, uint64(2), stats.Failures)
	require.Equal(t, uint64(1), stats.Partial)
	require.NoError(t, p.Shutdown())
	var warnings []map[string]any
	for _, line := range strings.Split(logs.snapshot(), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "SDP endpoint derivation incomplete" {
			warnings = append(warnings, record)
		}
	}
	require.Len(t, warnings, 1)
	require.Equal(t, "processor", warnings[0]["reporting_path"])
	require.Equal(t, float64(2), warnings[0]["incomplete"])
	encoded, err := json.Marshal(warnings)
	require.NoError(t, err)
	for _, private := range []string{"synthetic-central", "synthetic-hunter", "192.0.2.1", "selected@example.invalid"} {
		require.NotContains(t, string(encoded), private)
	}
}

func TestSDPDiagnosticsCentralFramingAndLocalReportingOwner(t *testing.T) {
	body := "m=invalid\r\n"
	fullTCP := diagnosticEnvelope(t, body, true)
	require.Equal(t, []byte(body), completeSDPBody(fullTCP))
	tcpLayer := fullTCP.Packet().Layer(layers.LayerTypeTCP).(*layers.TCP)
	partial := tcpLayer.Payload[:len(tcpLayer.Payload)-2]
	require.Empty(t, completeSDPBody(diagnosticPayloadEnvelope(t, partial, true)), "a TCP fragment cannot supply complete SDP failure evidence")
	noLength := bytes.Replace(tcpLayer.Payload, []byte("Content-Length: 11\r\n"), nil, 1)
	require.Empty(t, completeSDPBody(diagnosticPayloadEnvelope(t, noLength, true)))
	truncated := diagnosticEnvelope(t, body, false)
	truncated.OriginalLength++
	require.Empty(t, completeSDPBody(truncated))

	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "synthetic-tap"})
	require.NoError(t, err)
	local := source.NewLocalSource(source.LocalSourceConfig{ProcessorID: "synthetic-tap"})
	voip := voipprocessor.New(voipprocessor.DefaultConfig())
	t.Cleanup(voip.Close)
	local.SetVoIPProcessor(voipprocessor.NewSourceAdapter(voip))
	p.SetPacketSource(local)
	p.processBatch(&source.PacketBatch{SourceID: local.SourceID(), Envelopes: []*pipeline.PacketEnvelope{diagnosticEnvelope(t, body, false)}})
	require.Zero(t, p.sdpDiagnostics.counters.Snapshot().Bodies, "local tap's VoIP parser owns reporting")
	p.processBatch(&source.PacketBatch{SourceID: "remote-hunter", Envelopes: []*pipeline.PacketEnvelope{diagnosticEnvelope(t, body, false)}})
	require.Equal(t, uint64(1), p.sdpDiagnostics.counters.Snapshot().Bodies, "remote input still has a central reporting owner")
}
