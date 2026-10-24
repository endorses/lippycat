package voip

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/types"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/stretchr/testify/require"
)

func smsAggregatorPacket(callID string, sequence uint64, part uint8, text string) *data.CapturedPacket {
	message := &sms.Message{Status: sms.StatusDecoded, Encoding: sms.EncodingGSM7, Direction: sms.DirectionMO, To: "+123", Text: text}
	if part > 0 {
		message.Concat = &sms.Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: part}
	}
	return &data.CapturedPacket{TimestampNs: time.Unix(10, 0).UnixNano(), Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: callID, Method: "MESSAGE", CseqMethod: "MESSAGE", CseqNumber: sequence, ViaBranch: "branch", FromUri: "sip:alice@test", ToUri: "sip:bob@test", Sms: grpcadapter.ToProtoSMS(message)}}}
}

func TestCallAggregatorSMSCollectionAndCrossCallAssembly(t *testing.T) {
	aggregator := NewCallAggregator()
	first := smsAggregatorPacket("one", 1, 1, "hello ")
	aggregator.ProcessPacket(first, "hunter")
	aggregator.ProcessPacket(first, "hunter")
	one, ok := aggregator.GetCall("one")
	require.True(t, ok)
	require.Len(t, one.SMS, 1)
	require.Equal(t, CallStateMessage, one.State)
	require.Equal(t, one.StartTime, one.EndTime)
	aggregator.ProcessPacket(smsAggregatorPacket("two", 1, 2, "world"), "hunter")
	for _, id := range []string{"one", "two"} {
		call, ok := aggregator.GetCall(id)
		require.True(t, ok)
		require.Equal(t, sms.AssemblyComplete, call.SMS[0].Message.Assembly.Status)
		require.Equal(t, "hello world", call.SMS[0].Message.Assembly.Text)
	}
	response := smsAggregatorPacket("one", 1, 0, "")
	response.Metadata.Sip.Method = "RESPONSE"
	response.Metadata.Sip.ResponseCode = 200
	response.Metadata.Sip.Sms = nil
	aggregator.ProcessPacket(response, "hunter")
	later := smsAggregatorPacket("one", 2, 0, "second transaction")
	later.TimestampNs += int64(time.Minute)
	aggregator.ProcessPacket(later, "hunter")
	one, _ = aggregator.GetCall("one")
	require.Len(t, one.SMS, 2)
	require.Equal(t, one.StartTime, one.EndTime)
	require.Empty(t, aggregator.GetActiveCalls())
	require.Equal(t, "hello ", one.SMS[0].Message.Text)
	one.SMS[0].Message.Text = "mutated"
	one.SMS[0].Message.Assembly.Received[0] = 99
	stored, _ := aggregator.GetCall("one")
	require.Equal(t, "hello ", stored.SMS[0].Message.Text)
	require.Equal(t, []uint8{1, 2}, stored.SMS[0].Message.Assembly.Received)
}

func TestCallAggregatorSMSDoesNotJoinDifferentSources(t *testing.T) {
	aggregator := NewCallAggregator()
	aggregator.ProcessPacket(smsAggregatorPacket("one", 1, 1, "hello "), "a")
	aggregator.ProcessPacket(smsAggregatorPacket("two", 1, 2, "world"), "b")
	call, _ := aggregator.GetCall("one")
	require.Equal(t, sms.AssemblyPending, call.SMS[0].Message.Assembly.Status)
}

func TestCallAggregatorSMSExpiryResetAndEviction(t *testing.T) {
	at := time.Unix(10, 0)
	aggregator := NewCallAggregatorWithCapacity(2)
	aggregator.ProcessPacket(smsAggregatorPacket("pending", 1, 1, "first"), "hunter")
	aggregator.ExpireSMS(at.Add(5 * time.Minute))
	pending, _ := aggregator.GetCall("pending")
	require.Equal(t, sms.AssemblyExpired, pending.SMS[0].Message.Assembly.Status)
	require.Equal(t, "first", pending.SMS[0].Message.Text)
	require.Equal(t, CallStateMessage, pending.State)
	aggregator.ResetCall("pending")
	_, exists := aggregator.GetCall("pending")
	require.False(t, exists)
	aggregator.ProcessPacket(smsAggregatorPacket("first", 1, 1, "first"), "hunter")
	aggregator.ProcessPacket(smsAggregatorPacket("other", 1, 0, "single"), "hunter")
	// Evict the call containing part one before part two is seen. The assembler
	// cannot borrow a contribution whose owning call was released.
	aggregator.ProcessPacket(smsAggregatorPacket("second", 1, 2, "second"), "hunter")
	second, _ := aggregator.GetCall("second")
	require.Equal(t, sms.AssemblyPending, second.SMS[0].Message.Assembly.Status)
	aggregator.ClearSMS()
	for _, call := range aggregator.GetCalls() {
		require.Empty(t, call.SMS)
	}
}

func TestCallAggregatorSMSEvictionMarksRemainingPartialGroup(t *testing.T) {
	aggregator := NewCallAggregatorWithCapacity(2)
	first := smsAggregatorPacket("first", 1, 1, "one")
	first.Metadata.Sip.Sms.Concat.Total = 3
	second := smsAggregatorPacket("second", 1, 2, "two")
	second.Metadata.Sip.Sms.Concat.Total = 3
	aggregator.ProcessPacket(first, "hunter")
	aggregator.ProcessPacket(second, "hunter")
	aggregator.ProcessPacket(smsAggregatorPacket("unrelated", 1, 0, "single"), "hunter")
	retained, _ := aggregator.GetCall("second")
	require.Equal(t, sms.AssemblyResourceLimited, retained.SMS[0].Message.Assembly.Status)
	require.Equal(t, "two", retained.SMS[0].Message.Text)
}

func TestCallAggregatorSMSKnownDomainGroupsAcrossInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name         string
		known        bool
		secondDomain uint32
		complete     bool
	}{
		{"known-same", true, 42, true}, {"known-distinct", true, 43, false}, {"unknown-distinct-interfaces", false, 42, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aggregator := NewCallAggregator()
			first := smsAggregatorPacket("one", 1, 1, "hello ")
			first.InterfaceName = "eth0"
			first.ObservationDomainKnown = tc.known
			first.ObservationDomain = 42
			message := grpcadapter.FromProtoSMS(first.Metadata.Sip.Sms)
			message.Assembly = sms.AssemblyInfo{ID: "G", Status: sms.AssemblyPending}
			first.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
			aggregator.ProcessPacket(first, "hunter")
			second := smsAggregatorPacket("two", 1, 2, "world")
			second.InterfaceName = "eth1"
			second.ObservationDomainKnown = tc.known
			second.ObservationDomain = tc.secondDomain
			message = grpcadapter.FromProtoSMS(second.Metadata.Sip.Sms)
			message.Assembly = sms.AssemblyInfo{ID: "G", Status: sms.AssemblyComplete, Text: "hello world", Received: []uint8{1, 2}}
			second.Metadata.Sip.Sms = grpcadapter.ToProtoSMS(message)
			aggregator.ProcessPacket(second, "hunter")
			call, _ := aggregator.GetCall("one")
			if tc.complete {
				require.Equal(t, sms.AssemblyComplete, call.SMS[0].Message.Assembly.Status)
				require.Equal(t, "hello world", call.SMS[0].Message.Assembly.Text)
			} else {
				require.Equal(t, sms.AssemblyPending, call.SMS[0].Message.Assembly.Status)
			}
		})
	}
}

func TestCallAggregatorSMSDisplayKnownDomainUsesCaptureNodeAcrossInterfaces(t *testing.T) {
	aggregator := NewCallAggregator()
	for part := uint8(1); part <= 2; part++ {
		iface := fmt.Sprintf("eth%d", part)
		packet := &types.PacketDisplay{NodeID: "local", Interface: iface, Timestamp: time.Unix(100, 0), ObservationDomainKnown: true, ObservationDomain: 42, VoIPData: &types.VoIPMetadata{CallID: fmt.Sprint(part), Method: "MESSAGE", CSeqNumber: 1, From: "sip:alice@test", To: "sip:bob@test", SMS: &sms.Message{Status: sms.StatusDecoded, Text: fmt.Sprint(part), Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: part}}}}
		aggregator.ProcessPacketDisplay(packet, iface)
	}
	for _, call := range aggregator.GetCalls() {
		require.Equal(t, sms.AssemblyComplete, call.SMS[0].Message.Assembly.Status)
		require.Equal(t, "12", call.SMS[0].Message.Assembly.Text)
	}
}
