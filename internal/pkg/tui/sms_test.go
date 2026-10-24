//go:build tui || all

package tui

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func tuiSMSMessage(t *testing.T, callID string) []byte {
	t.Helper()
	tp, err := hex.DecodeString("010005912143f500000ae8329bfd4697d9ec37")
	require.NoError(t, err)
	body := append([]byte{0, 0x23, 0, 0, byte(len(tp))}, tp...)
	return append([]byte(fmt.Sprintf("MESSAGE sip:bob@test SIP/2.0\r\nCall-ID: %s\r\nCSeq: 1 MESSAGE\r\nVia: SIP/2.0/TCP test;branch=z9hG4bK-sms\r\nFrom: <sip:alice@test>\r\nTo: <sip:bob@test>\r\nContent-Type: Application/Vnd.3gpp.Sms; charset=binary\r\nContent-Length: %d\r\n\r\n", callID, len(body))), body...)
}

func TestLocalSMSDecodedFromCompleteRawMessage(t *testing.T) {
	message := tuiSMSMessage(t, "raw")
	packet := &types.PacketDisplay{Timestamp: time.Unix(10, 0), Transport: 6, VoIPData: &types.VoIPMetadata{CallID: "raw", Method: "MESSAGE", RawSIP: message}}
	aggregator := NewLocalCallAggregator(nil, nil)
	aggregator.silent = true
	aggregator.ProcessPacket(packet)
	calls := aggregator.GetCalls()
	require.Len(t, calls, 1)
	require.Equal(t, "hellohello", calls[0].SMS[0].Message.Text)
	require.Equal(t, uint64(1), packet.VoIPData.CSeqNumber)
	packet.VoIPData.RawSIP = message[:len(message)-1]
	packet.VoIPData.SMS = nil
	enrichDisplaySMS(packet)
	require.Nil(t, packet.VoIPData.SMS)
}

func TestOfflineSMSFramingStorageAndCallContent(t *testing.T) {
	at := time.Unix(100, 0)
	first := tuiSMSMessage(t, "first")
	second := tuiSMSMessage(t, "second")
	// One complete message split across packets, followed by two coalesced MESSAGE
	// transactions on the same TCP connection. Every complete message is decoded.
	stream := append(append([]byte(nil), first...), second...)
	split := len(first) / 2
	path := writeOfflineSIPExpiryCapture(t, offlineSIPPacket(t, 100, stream[:split], at), offlineSIPPacket(t, uint32(100+split), stream[split:], at.Add(time.Second)))
	for _, compact := range []bool{false, true} {
		t.Run(fmt.Sprint(compact), func(t *testing.T) {
			session, err := indexOfflineDatasetBackend(context.Background(), testOfflineStorage(t), 77, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, nil, nil, compact, true)
			require.NoError(t, err)
			defer func() { require.NoError(t, session.Close()) }()
			require.Len(t, session.Calls, 2)
			for _, call := range session.Calls {
				require.Equal(t, "SMS", call.State)
				require.Len(t, call.SMS, 1)
				require.Equal(t, "hellohello", call.SMS[0].Message.Text)
				require.Equal(t, sms.StatusDecoded, call.SMS[0].Message.Status)
			}
			detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 77}, 1)
			require.NoError(t, err)
			require.NotNil(t, detail.Packet.VoIPData)
			require.NotNil(t, detail.Packet.VoIPData.SMS)
			require.Equal(t, "hellohello", detail.Packet.VoIPData.SMS.Text)
		})
	}
}

func TestLiveSMSUDPMetadataContainsDecodedContent(t *testing.T) {
	message := tuiSMSMessage(t, "udp")
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(message)))
	packet := &types.PacketDisplay{Timestamp: time.Unix(10, 0), Transport: 17, LinkType: layers.LinkTypeRaw, RawData: buffer.Bytes(), VoIPData: &types.VoIPMetadata{CallID: "udp", Method: "MESSAGE"}}
	aggregator := NewLocalCallAggregator(nil, nil)
	aggregator.silent = true
	aggregator.ProcessPacket(packet)
	require.Equal(t, "hellohello", packet.VoIPData.SMS.Text)
}

func TestLocalSMSStopReleasesContentAndIgnoresLatePackets(t *testing.T) {
	aggregator := NewLocalCallAggregator(nil, nil)
	aggregator.silent = true
	packet := &types.PacketDisplay{Timestamp: time.Unix(10, 0), VoIPData: &types.VoIPMetadata{CallID: "one", Method: "MESSAGE", SMS: &sms.Message{Status: sms.StatusDecoded, Text: "first", Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Part: 1, Total: 2}}}}
	aggregator.ProcessPacket(packet)
	require.NotEmpty(t, aggregator.GetCalls()[0].SMS)
	aggregator.Stop()
	require.Empty(t, aggregator.GetCalls()[0].SMS)
	aggregator.ProcessPacket(packet)
	require.Empty(t, aggregator.GetCalls()[0].SMS)
}

func TestOfflineSMSUDPPreservesDecodedBodyInBothStorageFormats(t *testing.T) {
	message := tuiSMSMessage(t, "udp")
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(message)))
	parsed := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	parsed.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), Length: len(buffer.Bytes()), CaptureLength: len(buffer.Bytes())}
	path := writeOfflineSIPExpiryCapture(t, captureadapter.FromPacketInfo(capture.PacketInfo{Packet: parsed}, pipeline.SourcePCAPReplay))
	for _, compact := range []bool{false, true} {
		t.Run(fmt.Sprint(compact), func(t *testing.T) {
			session, err := indexOfflineDatasetBackend(context.Background(), testOfflineStorage(t), 78, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, nil, nil, compact, true)
			require.NoError(t, err)
			defer func() { require.NoError(t, session.Close()) }()
			require.Len(t, session.Calls, 1)
			require.Len(t, session.Calls[0].SMS, 1)
			require.Equal(t, "hellohello", session.Calls[0].SMS[0].Message.Text)
			detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 78}, 0)
			require.NoError(t, err)
			require.NotNil(t, detail.Packet.VoIPData.SMS)
			require.Equal(t, "hellohello", detail.Packet.VoIPData.SMS.Text)
		})
	}
}

func TestTUISIPSourceProvenanceScopesMultipartAcrossCallIDs(t *testing.T) {
	aggregator := NewLocalCallAggregator(nil, nil)
	aggregator.silent = true
	handler := NewTUISIPHandler(NewCallTracker(), aggregator)
	defer handler.Close()
	send := func(id string, part uint8, domain uint32) {
		handler.consumeSIPResult(pipeline.SIPResult{Timestamp: time.Unix(100, 0), CallID: id, Method: "MESSAGE", CSeqMethod: "MESSAGE", CSeqNumber: 1, From: "sip:alice@test", To: "sip:bob@test", SMS: &sms.Message{Status: sms.StatusDecoded, Text: fmt.Sprint(part), Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Part: part, Total: 2}}, Packet: &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth0", ObservationDomainKnown: true, ObservationDomain: domain}}})
	}
	send("first", 1, 42)
	send("other-domain", 2, 43)
	calls := aggregator.GetCalls()
	require.Len(t, calls, 2)
	for _, call := range calls {
		require.Equal(t, sms.AssemblyPending, call.SMS[0].Message.Assembly.Status)
		require.Equal(t, []string{"eth0"}, call.Hunters)
	}
	send("same-domain", 2, 42)
	calls = aggregator.GetCalls()
	for _, call := range calls {
		if call.CallID == "other-domain" {
			require.Equal(t, sms.AssemblyPending, call.SMS[0].Message.Assembly.Status)
		} else {
			require.Equal(t, sms.AssemblyComplete, call.SMS[0].Message.Assembly.Status)
			require.Equal(t, "12", call.SMS[0].Message.Assembly.Text)
		}
	}
	aggregator.Stop()
}

func TestLocalSMSIdleNotificationExpiresLiveButNotOfflineCapture(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint(replay), func(t *testing.T) {
			aggregator := NewLocalCallAggregator(nil, nil)
			aggregator.offline = replay
			defer aggregator.Stop()
			packet := &types.PacketDisplay{Timestamp: time.Now().Add(-6 * time.Minute), VoIPData: &types.VoIPMetadata{CallID: "one", Method: "MESSAGE", SMS: &sms.Message{Status: sms.StatusDecoded, Text: "partial", Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Part: 1, Total: 2}}}}
			aggregator.ProcessPacket(packet)
			aggregator.notifyCallUpdates()
			message := aggregator.GetCalls()[0].SMS[0].Message
			if replay {
				require.Equal(t, sms.AssemblyPending, message.Assembly.Status)
			} else {
				require.Equal(t, sms.AssemblyExpired, message.Assembly.Status)
			}
			require.Equal(t, "partial", message.Text)
		})
	}
}
