package source

import (
	"context"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/smsflow"
	"github.com/stretchr/testify/require"
)

func smsSourcePacket(t *testing.T, callID, text string, part uint8) *pipeline.PacketEnvelope {
	t.Helper()
	var user []byte
	first := byte(1)
	if part != 0 {
		first = 0x41
		user = []byte{5, 0, 3, 42, 2, part}
	}
	for _, unit := range utf16.Encode([]rune(text)) {
		user = append(user, byte(unit>>8), byte(unit))
	}
	tpdu := append([]byte{first, 0, 2, 0x91, 0x21, 0, 8, byte(len(user))}, user...)
	body := append([]byte{0, part + 1, 0, 0, byte(len(tpdu))}, tpdu...)
	payload := []byte(fmt.Sprintf("MESSAGE sip:bob@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>;tag=alice\r\nTo: <sip:bob@example.test>\r\nCall-ID: %s\r\nCSeq: 1 MESSAGE\r\nVia: SIP/2.0/UDP peer;branch=z9hG4bK-%s\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Length: %d\r\n\r\n", callID, callID, len(body)))
	payload = append(payload, body...)
	info := sourcePolicyPacket(t, payload, 5060)
	envelope, err := grpcadapter.FromCapturedPacket(convertPacketInfo(info), pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, NodeID: "test-tap"})
	require.NoError(t, err)
	return envelope
}

func smsSource(t *testing.T, keywords []string) *LocalSource {
	t.Helper()
	s := NewLocalSource(LocalSourceConfig{ProtocolMode: "voip", BatchSize: 100})
	require.NoError(t, s.SetSMSConfig(smsflow.Config{Keywords: keywords}))
	t.Cleanup(s.closeSMS)
	return s
}

func smsBatch(t *testing.T, s *LocalSource) *PacketBatch {
	t.Helper()
	s.sendBatch()
	select {
	case batch := <-s.Batches():
		return batch
	case <-time.After(time.Second):
		t.Fatal("SMS output batch missing")
		return nil
	}
}

func TestSMSLocalSourceDisabledAssemblyNeverWithholds(t *testing.T) {
	s := smsSource(t, nil)
	s.appendEnvelope(smsSourcePacket(t, "second", "lo", 2), nil, nil, nil)
	first := smsBatch(t, s)
	wire, err := first.ToProtoBatchE()
	require.NoError(t, err)
	require.Equal(t, data.SMSMetadata_ASSEMBLY_STATUS_PENDING, wire.Packets[0].Metadata.Sip.Sms.Assembly.Status)
	s.appendEnvelope(smsSourcePacket(t, "first", "hel", 1), nil, nil, nil)
	second := smsBatch(t, s)
	wire, err = second.ToProtoBatchE()
	require.NoError(t, err)
	require.Equal(t, "hello", wire.Packets[0].Metadata.Sip.Sms.Assembly.Text)
	require.Equal(t, "hel", wire.Packets[0].Metadata.Sip.Sms.Text)
	require.Zero(t, s.SMSStats().PendingMessages)
}

func TestSMSLocalSourceKeywordAcrossTransactionsAndCompletion(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	var completed atomic.Int32
	s.appendEnvelope(smsSourcePacket(t, "first", "hel", 1), nil, func() { completed.Add(1) }, nil)
	require.Empty(t, s.currentBatch)
	require.Equal(t, 1, s.SMSStats().PendingMessages)
	s.appendEnvelope(smsSourcePacket(t, "second", "lo", 2), nil, func() { completed.Add(1) }, nil)
	batch := smsBatch(t, s)
	require.Len(t, batch.Envelopes, 2)
	require.Zero(t, completed.Load(), "completion belongs to processor output lifecycle")
	wire, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	for _, packet := range wire.Packets {
		require.Equal(t, "hello", packet.Metadata.Sip.Sms.Assembly.Text)
	}
	batch.RunAfterProcess()
	batch.RunAfterProcess()
	require.EqualValues(t, 2, completed.Load())
	require.Zero(t, s.SMSStats().PendingMessages)
}

func TestSMSLocalSourceRetainedSelectionResetAndExpiry(t *testing.T) {
	for _, mode := range []string{"selection", "capture-reset", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			s := smsSource(t, []string{"hello"})
			selected := true
			completed := 0
			first := smsSourcePacket(t, "first", "hel", 1)
			s.appendEnvelope(first, nil, func() { completed++ }, func(*pipeline.PacketEnvelope) bool { return selected })
			require.Equal(t, 1, s.SMSStats().PendingMessages)
			switch mode {
			case "selection":
				selected = false
				s.appendEnvelope(smsSourcePacket(t, "second", "lo", 2), nil, func() { completed++ }, func(*pipeline.PacketEnvelope) bool { return selected })
			case "capture-reset":
				s.closeSMS()
			case "expiry":
				s.expireSMS(first.CaptureTime.Add(6 * time.Minute))
			}
			require.Empty(t, s.currentBatch)
			require.Zero(t, s.SMSStats().PendingMessages)
			if mode == "selection" {
				require.Equal(t, 2, completed)
			} else {
				require.Equal(t, 1, completed)
			}
			s.closeSMS()
			if mode == "selection" {
				require.Equal(t, 2, completed)
			} else {
				require.Equal(t, 1, completed)
			}
		})
	}
}

func TestSMSLocalSourcePrefersSuppliedMetadata(t *testing.T) {
	s := smsSource(t, nil)
	envelope := smsSourcePacket(t, "supplied", "raw", 0)
	result, metadata, ok, err := localSMSResult(envelope)
	require.NoError(t, err)
	require.True(t, ok)
	result.SMS.Text = "upstream decoded"
	metadata.Sip = &data.SIPMetadata{CallId: result.CallID, Method: "MESSAGE", Sms: grpcadapter.ToProtoSMS(result.SMS)}
	envelope.Metadata, err = grpcadapter.MetadataFromProto(metadata)
	require.NoError(t, err)
	envelope.Data = []byte{1, 2, 3} // Complete upstream interpretation remains available.
	s.appendEnvelope(envelope, nil, nil, nil)
	wire, err := smsBatch(t, s).ToProtoBatchE()
	require.NoError(t, err)
	require.Equal(t, "upstream decoded", wire.Packets[0].Metadata.Sip.Sms.Text)
	require.Equal(t, sms.StatusDecoded, grpcadapter.FromProtoSMS(wire.Packets[0].Metadata.Sip.Sms).Status)
}

func smsSourceInfo(envelope *pipeline.PacketEnvelope) capture.PacketInfo {
	packet := gopacket.NewPacket(envelope.Data, envelope.LinkType, gopacket.Default)
	packet.Metadata().Timestamp = envelope.CaptureTime
	return capture.PacketInfo{Packet: packet, LinkType: envelope.LinkType, Interface: envelope.Source.InterfaceName}
}

func TestSMSLocalSourceUDPWorkerAndBaselineSelection(t *testing.T) {
	for _, baseline := range []bool{true, false} {
		t.Run(fmt.Sprint(baseline), func(t *testing.T) {
			s := smsSource(t, []string{"hello"})
			s.ctx = context.Background()
			s.config.BatchTimeout = time.Hour
			if !baseline {
				s.SetApplicationFilter(&sourcePolicyFilter{direct: false})
			}
			input := make(chan capture.PacketInfo, 2)
			input <- smsSourceInfo(smsSourcePacket(t, "first", "hel", 1))
			input <- smsSourceInfo(smsSourcePacket(t, "second", "lo", 2))
			close(input)
			s.batchingWorker(input)
			if !baseline {
				require.Zero(t, s.SMSStats().Transactions, "keyword text cannot grant capture eligibility")
				select {
				case <-s.Batches():
					t.Fatal("unselected SMS forwarded")
				default:
				}
				return
			}
			select {
			case batch := <-s.Batches():
				require.Len(t, batch.Envelopes, 2)
				wire, err := batch.ToProtoBatchE()
				require.NoError(t, err)
				for _, packet := range wire.Packets {
					require.Equal(t, "hello", packet.Metadata.Sip.Sms.Assembly.Text)
				}
			default:
				t.Fatal("UDP SMS did not reach source output")
			}
		})
	}
}

func TestSMSLocalSourceInjectedReassemblyRetainsCallbacks(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	s.config.BatchSize = 2
	s.config.BatchTimeout = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	injections := make(chan InjectedPacket, 2)
	s.SetTCPInjectionChannel(injections)
	done := make(chan struct{})
	go func() { s.batchingWorker(nil); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	var completed atomic.Int32
	for part, text := range []string{"hel", "lo"} {
		envelope := smsSourcePacket(t, fmt.Sprint(part), text, uint8(part+1))
		info := smsTCPInfo(t, envelope)
		// The injection contract carries a synthesized complete transport packet.
		// Attach explicit metadata as the TCP reassembly adapter normally does.
		result, _, _, err := localSMSResult(envelope)
		require.NoError(t, err)
		injections <- InjectedPacket{PacketInfo: info, Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: result.CallID, Method: "MESSAGE", CseqMethod: "MESSAGE", CseqNumber: result.CSeqNumber, ViaBranch: result.ViaBranch, Sms: grpcadapter.ToProtoSMS(result.SMS)}}, AfterProcess: func() { completed.Add(1) }}
		if part == 0 {
			require.Eventually(t, func() bool { return s.SMSStats().PendingMessages == 1 }, time.Second, time.Millisecond)
			require.Zero(t, completed.Load())
			select {
			case <-s.Batches():
				t.Fatal("incomplete TCP SMS forwarded")
			default:
			}
		}
	}
	select {
	case batch := <-s.Batches():
		require.Len(t, batch.Envelopes, 2)
		require.Zero(t, completed.Load())
		batch.RunAfterProcess()
		require.EqualValues(t, 2, completed.Load())
	case <-time.After(time.Second):
		t.Fatal("complete injected SMS was not released")
	}
}

func TestSMSLocalSourceIndependentPolicyPath(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	require.NoError(t, s.SetCapturePolicies(capturepolicy.CapturePolicies{Signalling: capturepolicy.SignallingAll, Media: capturepolicy.MediaProcessor}, nil))
	completed := 0
	for part, text := range []string{"hel", "lo"} {
		info := smsSourceInfo(smsSourcePacket(t, fmt.Sprint(part), text, uint8(part+1)))
		handled, accepted := s.policyPacket(info, nil)
		require.True(t, handled)
		require.NotNil(t, accepted)
		s.appendPolicyPacket(accepted, func() { completed++ })
		if part == 0 {
			require.Empty(t, s.currentBatch)
			require.Zero(t, completed)
		}
	}
	batch := smsBatch(t, s)
	require.Len(t, batch.Envelopes, 2)
	require.Zero(t, completed)
	batch.RunAfterProcess()
	require.Equal(t, 2, completed)
	require.EqualValues(t, 2, s.Stats().PacketsForwarded)
}

func TestSMSLocalSourceResourceLimitAndStopRelease(t *testing.T) {
	for _, mode := range []string{"bytes", "stop", "reconfigure"} {
		t.Run(mode, func(t *testing.T) {
			s := smsSource(t, []string{"hello"})
			completed := 0
			if mode == "bytes" {
				require.NoError(t, s.SetSMSConfig(smsflow.Config{Keywords: []string{"hello"}, MaxPendingBytes: 1}))
			}
			s.appendEnvelope(smsSourcePacket(t, "first", "hel", 1), nil, func() { completed++ }, nil)
			switch mode {
			case "stop":
				s.Stop()
			case "reconfigure":
				require.NoError(t, s.SetSMSConfig(smsflow.Config{}))
			}
			require.Equal(t, 1, completed)
			require.Empty(t, s.currentBatch)
			require.Zero(t, s.SMSStats().PendingMessages)
			if mode == "bytes" {
				require.Positive(t, s.SMSStats().ResourceLimited)
			}
		})
	}
}

func smsTCPInfo(t *testing.T, envelope *pipeline.PacketEnvelope) capture.PacketInfo {
	t.Helper()
	info := smsSourceInfo(envelope)
	original := info.Packet.NetworkLayer().(*layers.IPv4)
	ip := *original
	ip.Protocol = layers.IPProtocolTCP
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 10, ACK: true, PSH: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(&ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ip, tcp, gopacket.Payload(info.Packet.TransportLayer().LayerPayload())))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = envelope.CaptureTime
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeRaw, Interface: info.Interface}
}

func TestSMSLocalSourceRetainedSameIDRuleReplacement(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	filter := &sourceProofFilter{epoch: 1, target: "alice"}
	s.SetApplicationFilter(filter)
	completed := 0
	first := smsSourcePacket(t, "first", "hel", 1)
	s.appendEnvelope(first, nil, func() { completed++ }, s.smsSelectionCheck(smsSourceInfo(first), callregistry.Lifetime{}))
	require.Equal(t, 1, s.SMSStats().PendingMessages)
	filter.epoch = 2
	second := smsSourcePacket(t, "second", "lo", 2)
	s.appendEnvelope(second, nil, func() { completed++ }, s.smsSelectionCheck(smsSourceInfo(second), callregistry.Lifetime{}))
	require.Empty(t, s.currentBatch, "same-ID replacement cannot relabel held content")
	require.Equal(t, 2, completed)
	require.Zero(t, s.SMSStats().PendingMessages)
}

func TestSMSLocalSourceWorkerExpiresIdleRetainedPackets(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	require.NoError(t, s.SetSMSConfig(smsflow.Config{Keywords: []string{"hello"}, Assembly: sms.Config{Lifetime: 20 * time.Millisecond}}))
	s.config.BatchTimeout = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	injection := make(chan InjectedPacket, 1)
	s.SetTCPInjectionChannel(injection)
	done := make(chan struct{})
	go func() { s.batchingWorker(nil); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	envelope := smsSourcePacket(t, "first", "hel", 1)
	envelope.CaptureTime = time.Now()
	info := smsTCPInfo(t, envelope)
	var completed atomic.Int32
	injection <- InjectedPacket{PacketInfo: info, AfterProcess: func() { completed.Add(1) }}
	require.Eventually(t, func() bool { return completed.Load() == 1 }, time.Second, time.Millisecond)
	require.Zero(t, s.SMSStats().PendingMessages)
	require.Positive(t, s.SMSStats().Expired)
	select {
	case <-s.Batches():
		t.Fatal("expired incomplete SMS forwarded")
	default:
	}
}

func TestSMSLocalSourcePolicyBoundaryDiscardsPendingBeforeApply(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	installLocalCaptureFixture(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx, s.cancel = ctx, cancel
	completed := 0
	s.appendEnvelope(smsSourcePacket(t, "old", "hel", 1), nil, func() { completed++ }, nil)
	s.started = true
	s.captureDone = make(chan struct{})
	close(s.captureDone)
	s.batchingDone = make(chan struct{})
	close(s.batchingDone)
	buffer := capture.NewPacketBuffer(ctx, 1)
	s.packetBuffer.Store(buffer)
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for batch := range s.batches {
			batch.RunAfterProcess()
		}
	}()
	t.Cleanup(func() { cancel(); s.packetBuffer.Load().Close(); s.wg.Wait(); close(s.batches); <-consumerDone })
	require.NoError(t, s.ApplyPolicyBoundary(t.Context(), "udp", func() error {
		require.Equal(t, 1, completed, "retained callback must be released before policy changes")
		require.Zero(t, s.SMSStats().PendingMessages)
		return nil
	}))
	require.Equal(t, 1, completed)
	require.Positive(t, s.smsGeneration.Load())
}

func TestSMSLocalSourceRetiringQueuedFramesCannotJoinNewCapture(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			var keywords []string
			if enabled {
				keywords = []string{"hello"}
			}
			s := smsSource(t, keywords)
			old := smsSourcePacket(t, "old", "hel", 1)
			s.closeSMS()
			completed := 0
			s.appendEnvelope(old, nil, func() { completed++ }, nil)
			if enabled {
				require.Equal(t, 1, completed)
				require.Empty(t, s.currentBatch)
			} else {
				require.Len(t, s.currentBatch, 1, "disabled filtering preserves raw output across capture gaps")
				batch := smsBatch(t, s)
				batch.RunAfterProcess()
				require.Equal(t, 1, completed)
			}
			fresh := smsSourcePacket(t, "fresh", "lo", 2)
			fresh.CaptureTime = time.Now()
			s.appendEnvelope(fresh, nil, nil, nil)
			if enabled {
				require.Equal(t, 1, s.SMSStats().PendingMessages)
				require.Empty(t, s.currentBatch)
			} else {
				batch := smsBatch(t, s)
				wire, err := batch.ToProtoBatchE()
				require.NoError(t, err)
				require.Equal(t, data.SMSMetadata_ASSEMBLY_STATUS_PENDING, wire.Packets[0].Metadata.Sip.Sms.Assembly.Status)
			}
		})
	}
}

func TestSMSLocalSourcePreservesLearnedAuthorizationGeneration(t *testing.T) {
	s := smsSource(t, nil)
	envelope := smsSourcePacket(t, "single", "hello", 0)
	envelope.Source.CapturePolicyGeneration = 123
	s.appendEnvelope(envelope, nil, nil, func(current *pipeline.PacketEnvelope) bool { return current.Source.CapturePolicyGeneration == 123 })
	require.Len(t, s.currentBatch, 1)
	require.EqualValues(t, 123, s.currentBatch[0].Source.CapturePolicyGeneration)
}

func TestSMSLocalSourceUDPDatagramRejectsTrailingMessageWhenFiltering(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, trailing := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%t/second-message=%t", enabled, trailing), func(t *testing.T) {
				var keywords []string
				if enabled {
					keywords = []string{"hello"}
				}
				s := smsSource(t, keywords)
				s.ctx = context.Background()
				s.config.BatchTimeout = time.Hour
				first := smsSourceInfo(smsSourcePacket(t, "allowed", "hello", 0))
				payload := append([]byte(nil), first.Packet.TransportLayer().LayerPayload()...)
				if trailing {
					rejected := smsSourceInfo(smsSourcePacket(t, "rejected", "secret", 0))
					payload = append(payload, rejected.Packet.TransportLayer().LayerPayload()...)
				} else {
					payload = append(payload, []byte("\r\n\r\n")...)
				}
				info := sourcePolicyPacket(t, payload, 5060)
				input := make(chan capture.PacketInfo, 1)
				input <- info
				close(input)
				s.batchingWorker(input)
				if enabled && trailing {
					require.Zero(t, s.Stats().PacketsForwarded)
					select {
					case <-s.Batches():
						t.Fatal("approved first SMS exposed rejected second SIP body")
					default:
					}
					return
				}
				select {
				case batch := <-s.Batches():
					require.Len(t, batch.Envelopes, 1)
					require.Equal(t, info.Packet.Data(), batch.Envelopes[0].Data, "disabled filtering preserves baseline raw bytes, including a trailing frame")
				default:
					t.Fatal("eligible single frame or disabled-filter datagram was not forwarded")
				}
			})
		}
	}
}

func TestSMSLocalSourceFilterAcceptsSuppliedMetadataWithoutRawFrame(t *testing.T) {
	s := smsSource(t, []string{"hello"})
	envelope := smsSourcePacket(t, "supplied", "hello", 0)
	result, metadata, ok, err := localSMSResult(envelope)
	require.NoError(t, err)
	require.True(t, ok)
	metadata.Sip = &data.SIPMetadata{CallId: result.CallID, Method: "MESSAGE", CseqMethod: "MESSAGE", Sms: grpcadapter.ToProtoSMS(result.SMS)}
	envelope.Metadata, err = grpcadapter.MetadataFromProto(metadata)
	require.NoError(t, err)
	envelope.Data = []byte{1, 2, 3}
	completed := 0
	s.appendEnvelope(envelope, nil, func() { completed++ }, nil)
	batch := smsBatch(t, s)
	require.Len(t, batch.Envelopes, 1)
	require.Zero(t, completed)
	batch.RunAfterProcess()
	require.Equal(t, 1, completed)
}
