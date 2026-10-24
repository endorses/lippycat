package remotecapture

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func remoteSMSPacket(part uint8, callID, text string) *data.CapturedPacket {
	message := &sms.Message{Status: sms.StatusDecoded, Encoding: sms.EncodingGSM7, Direction: sms.DirectionMO, To: "+123", Text: text, Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: part}}
	return &data.CapturedPacket{TimestampNs: time.Unix(10, 0).UnixNano(), Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: callID, Method: "MESSAGE", CseqMethod: "MESSAGE", CseqNumber: 1, ViaBranch: "branch", FromUri: "sip:alice@test", ToUri: "sip:bob@test", Sms: grpcadapter.ToProtoSMS(message)}}}
}

func TestRemoteSMSAcrossCallIDsAndResponseOnlyUpdates(t *testing.T) {
	client := &Client{calls: make(map[string]*types.CallInfo)}
	first := remoteSMSPacket(1, "one", "hello ")
	client.updateCallState(first, "hunter")
	client.updateCallState(first, "hunter")
	require.Len(t, client.calls["one"].SMS, 1)
	client.updateCallState(remoteSMSPacket(2, "two", "world"), "hunter")
	for _, id := range []string{"one", "two"} {
		require.Equal(t, sms.AssemblyComplete, client.calls[id].SMS[0].Message.Assembly.Status)
		require.Equal(t, "hello world", client.calls[id].SMS[0].Message.Assembly.Text)
	}
	response := remoteSMSPacket(1, "one", "")
	response.Metadata.Sip.Sms = nil
	response.Metadata.Sip.Method = "RESPONSE"
	response.Metadata.Sip.ResponseCode = 200
	client.updateCallState(response, "hunter")
	require.Equal(t, "hello ", client.calls["one"].SMS[0].Message.Text)
	require.Equal(t, "SMS", client.calls["one"].State)
	require.Zero(t, client.calls["one"].Duration)
}

func TestRemoteSMSCompleteUpstreamUpdatePreservesGroupIdentity(t *testing.T) {
	client := &Client{calls: make(map[string]*types.CallInfo)}
	first := remoteSMSPacket(1, "one", "hello ")
	firstMessage := grpcadapter.FromProtoSMS(first.Metadata.Sip.Sms)
	firstMessage.Assembly = sms.AssemblyInfo{ID: "upstream", Status: sms.AssemblyPending}
	first.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(firstMessage)
	client.updateCallState(first, "hunter")
	second := remoteSMSPacket(2, "two", "world")
	secondMessage := grpcadapter.FromProtoSMS(second.Metadata.Sip.Sms)
	secondMessage.Assembly = sms.AssemblyInfo{ID: "upstream", Status: sms.AssemblyComplete, Text: "hello world", Received: []uint8{1, 2}}
	second.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(secondMessage)
	client.updateCallState(second, "hunter")
	require.Equal(t, sms.AssemblyComplete, client.calls["one"].SMS[0].Message.Assembly.Status)
	require.Equal(t, "hello world", client.calls["one"].SMS[0].Message.Assembly.Text)
}

func TestRemoteSMSUsesCompleteRawFallbackAndPrefersMetadata(t *testing.T) {
	tp, err := hex.DecodeString("010005912143f500000ae8329bfd4697d9ec37")
	require.NoError(t, err)
	body := append([]byte{0, 0x23, 0, 0, byte(len(tp))}, tp...)
	payload := append([]byte(fmt.Sprintf("MESSAGE sip:bob@test SIP/2.0\r\nCall-ID: raw\r\nCSeq: 1 MESSAGE\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	packet := &data.CapturedPacket{Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "raw"}, Transport: "UDP"}}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	packet.Data = buffer.Bytes()
	packet.LinkType = uint32(layers.LinkTypeRaw)
	decoded := remoteSMS(packet, nil)
	require.NotNil(t, decoded)
	require.Equal(t, "hellohello", decoded.Text)
	packet.Data = packet.Data[:len(packet.Data)-2]
	require.Nil(t, remoteSMS(packet, nil))
	packet.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(&sms.Message{Status: sms.StatusDecoded, Text: "supplied"})
	require.Equal(t, "supplied", remoteSMS(packet, nil).Text)
}

func TestRemoteSMSExpiryAndProvenanceIsolation(t *testing.T) {
	client := &Client{calls: make(map[string]*types.CallInfo)}
	first := remoteSMSPacket(1, "one", "first")
	message := grpcadapter.FromProtoSMS(first.Metadata.Sip.Sms)
	message.Assembly.ID = "same-id"
	first.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
	client.updateCallState(first, "source-a")
	complete := remoteSMSPacket(2, "two", "second")
	message = grpcadapter.FromProtoSMS(complete.Metadata.Sip.Sms)
	message.Assembly = sms.AssemblyInfo{ID: "same-id", Status: sms.AssemblyComplete, Text: "unrelated"}
	complete.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
	client.updateCallState(complete, "source-b")
	require.Equal(t, sms.AssemblyPending, client.calls["one"].SMS[0].Message.Assembly.Status)
	// An ordinary subsequent SIP message advances expiry without needing another
	// SMS body and leaves the complete content from the other source intact.
	response := &data.CapturedPacket{TimestampNs: time.Unix(310, 0).UnixNano(), Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "one", CseqMethod: "MESSAGE", ResponseCode: 200}}}
	client.updateCallState(response, "source-a")
	require.Equal(t, sms.AssemblyExpired, client.calls["one"].SMS[0].Message.Assembly.Status)
	require.Equal(t, "first", client.calls["one"].SMS[0].Message.Text)
	require.Equal(t, sms.AssemblyComplete, client.calls["two"].SMS[0].Message.Assembly.Status)
}

func TestRemoteSMSSessionCloseReleasesContent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{ctx: ctx, cancel: cancel, calls: make(map[string]*types.CallInfo)}
	first := remoteSMSPacket(1, "one", "first")
	client.updateCallState(first, "hunter")
	require.NotEmpty(t, client.calls)
	client.Close()
	require.Empty(t, client.calls)
	client.updateCallState(first, "hunter")
	require.Empty(t, client.calls)
}

func TestRemoteSMSContentCallAndByteBounds(t *testing.T) {
	client := &Client{calls: make(map[string]*types.CallInfo)}
	for i := 0; i < types.SMSContentCallLimit+1; i++ {
		id := fmt.Sprintf("call-%04d", i)
		client.calls[id] = &types.CallInfo{CallID: id, StartTime: time.Unix(int64(i), 0), SMS: []types.SMSRecord{{TransactionID: id, Message: &sms.Message{Status: sms.StatusDecoded, Text: "short"}}}}
	}
	client.pruneSMSContent()
	require.Empty(t, client.calls["call-0000"].SMS)
	require.NotEmpty(t, client.calls["call-1000"].SMS)
	require.Len(t, client.calls, types.SMSContentCallLimit+1, "ordinary call state remains available")
	client.calls = make(map[string]*types.CallInfo)
	for i := 0; i < 130; i++ {
		id := fmt.Sprint(i)
		client.calls[id] = &types.CallInfo{CallID: id, StartTime: time.Unix(int64(i), 0), SMS: []types.SMSRecord{{TransactionID: id, Message: &sms.Message{Text: strings.Repeat("x", 128<<10)}}}}
	}
	client.pruneSMSContent()
	retained := 0
	for _, call := range client.calls {
		retained += types.SMSRecordsBytes(call.SMS)
	}
	require.LessOrEqual(t, retained, types.SMSContentByteLimit)
	require.Empty(t, client.calls["0"].SMS)
	require.NotEmpty(t, client.calls["129"].SMS)
}

func TestRemoteSMSIdleWorkerExpiresPendingAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{ctx: ctx, cancel: cancel, calls: make(map[string]*types.CallInfo)}
	first := remoteSMSPacket(1, "idle", "partial")
	first.TimestampNs = time.Now().Add(-6 * time.Minute).UnixNano()
	client.updateCallState(first, "hunter")
	t.Cleanup(func() { client.Close(); client.smsExpiryWG.Wait() })
	client.smsExpiryWG.Add(1)
	go client.runSMSExpiry()
	require.Eventually(t, func() bool {
		client.callsMu.RLock()
		defer client.callsMu.RUnlock()
		return client.calls["idle"].SMS[0].Message.Assembly.Status == sms.AssemblyExpired
	}, 3*time.Second, 10*time.Millisecond)
	client.callsMu.RLock()
	require.Equal(t, "partial", client.calls["idle"].SMS[0].Message.Text)
	client.callsMu.RUnlock()
	client.Close()
	require.Empty(t, client.calls)
}

func TestRemoteSMSProducerNegativeUpdatesNeverComplete(t *testing.T) {
	for _, status := range []sms.AssemblyStatus{sms.AssemblyConflict, sms.AssemblyExpired, sms.AssemblyResourceLimited} {
		for _, sawPending := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pending=%t", status, sawPending), func(t *testing.T) {
				client := &Client{calls: make(map[string]*types.CallInfo)}
				first := remoteSMSPacket(1, "one", "first")
				message := grpcadapter.FromProtoSMS(first.Metadata.Sip.Sms)
				message.Assembly = sms.AssemblyInfo{ID: "G", Status: status}
				if sawPending {
					message.Assembly.Status = sms.AssemblyPending
				}
				first.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
				client.updateCallState(first, "hunter")
				second := remoteSMSPacket(2, "two", "second")
				message = grpcadapter.FromProtoSMS(second.Metadata.Sip.Sms)
				message.Assembly = sms.AssemblyInfo{ID: "G", Status: status}
				second.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
				client.updateCallState(second, "hunter")
				for _, id := range []string{"one", "two"} {
					require.Equal(t, status, client.calls[id].SMS[0].Message.Assembly.Status)
					require.NotEqual(t, sms.AssemblyComplete, client.calls[id].SMS[0].Message.Assembly.Status)
				}
				require.Equal(t, client.calls["one"].SMS[0].Message.Assembly.ID, client.calls["two"].SMS[0].Message.Assembly.ID)
			})
		}
	}
}

func TestRemoteSMSKnownDomainGroupsAcrossInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name         string
		known        bool
		secondDomain uint32
		complete     bool
	}{
		{"known-same", true, 42, true}, {"known-distinct", true, 43, false}, {"unknown-distinct-interfaces", false, 42, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{nodeID: "processor", calls: make(map[string]*types.CallInfo)}
			first := remoteSMSPacket(1, "one", "hello ")
			first.InterfaceName = "eth0"
			first.ObservationDomainKnown = tc.known
			first.ObservationDomain = 42
			message := grpcadapter.FromProtoSMS(first.Metadata.Sip.Sms)
			message.Assembly = sms.AssemblyInfo{ID: "G", Status: sms.AssemblyPending}
			first.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
			client.updateCallState(first, "hunter")
			second := remoteSMSPacket(2, "two", "world")
			second.InterfaceName = "eth1"
			second.ObservationDomainKnown = tc.known
			second.ObservationDomain = tc.secondDomain
			message = grpcadapter.FromProtoSMS(second.Metadata.Sip.Sms)
			message.Assembly = sms.AssemblyInfo{ID: "G", Status: sms.AssemblyComplete, Text: "hello world", Received: []uint8{1, 2}}
			second.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
			client.updateCallState(second, "hunter")
			if tc.complete {
				require.Equal(t, sms.AssemblyComplete, client.calls["one"].SMS[0].Message.Assembly.Status)
				require.Equal(t, "hello world", client.calls["one"].SMS[0].Message.Assembly.Text)
			} else {
				require.Equal(t, sms.AssemblyPending, client.calls["one"].SMS[0].Message.Assembly.Status)
			}
		})
	}
}
