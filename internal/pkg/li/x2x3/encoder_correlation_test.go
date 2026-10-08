package x2x3

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func correlationSIPPacket(callID string) *types.PacketDisplay {
	return &types.PacketDisplay{Timestamp: time.Unix(100, 0), NodeID: "poi-a", VoIPData: &types.VoIPMetadata{CallID: callID, RawSIP: []byte("MESSAGE sip:b@example.test SIP/2.0\r\nCall-ID: " + callID + "\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbody")}}
}

func correlationRTPPacket(callID string) *types.PacketDisplay {
	return &types.PacketDisplay{Timestamp: time.Unix(100, 0), NodeID: "poi-a", RawData: []byte{0x80, 0, 0, 1}, VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 7, CallID: callID}}
}

func requireCorrelationSequence(t *testing.T, pdu *PDU, want uint32) {
	t.Helper()
	attrs := FindAllAttributes(pdu.Attributes, AttrSequenceNumber)
	require.Len(t, attrs, 1)
	got, err := NewAttributeParser().ParseSequenceNumber(&attrs[0])
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestEncoderSelectedCorrelationSequenceScopes(t *testing.T) {
	sequencer := NewSequencer(20)
	x2 := NewX2EncoderWithSequencer(sequencer, "domain", "nf")
	x3 := NewX3EncoderWithSequencer(sequencer, "domain", "nf")
	xid := uuid.New()
	for i, callID := range []string{"leg-a", "leg-b"} {
		pdu, err := x2.EncodeIRIWithPolicyAndCorrelationID(correlationSIPPacket(callID), xid, SIPContentIRIOnly, 0)
		require.NoError(t, err)
		require.Zero(t, pdu.Header.CorrelationID)
		require.NotContains(t, string(pdu.Payload), "\r\n\r\nbody")
		requireCorrelationSequence(t, pdu, uint32(i))
		cc, err := x3.EncodeCCWithCorrelationID(correlationRTPPacket(callID), xid, 0)
		require.NoError(t, err)
		require.Zero(t, cc.Header.CorrelationID)
		requireCorrelationSequence(t, cc, uint32(i))
	}
	other, err := x2.EncodeIRIWithPolicyAndCorrelationID(correlationSIPPacket("leg-c"), xid, SIPContentFull, 42)
	require.NoError(t, err)
	requireCorrelationSequence(t, other, 0)
	require.Equal(t, 3, sequencer.Len())
}

func TestEncoderCorrelationDefaultWireCompatibility(t *testing.T) {
	xid := uuid.New()
	for _, policy := range []SIPContentPolicy{SIPContentFull, SIPContentIRIOnly} {
		packet := correlationSIPPacket("default-leg")
		legacy := NewX2Encoder()
		expected, err := legacy.EncodeIRIWithPolicy(packet, xid, policy)
		require.NoError(t, err)
		actual, err := NewX2Encoder().EncodeIRIWithPolicyAndCorrelationID(packet, xid, policy, legacy.generateCorrelationID(packet.VoIPData.CallID))
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	for _, callID := range []string{"default-leg", ""} {
		packet := correlationRTPPacket(callID)
		legacy := NewX3Encoder()
		expected, err := legacy.EncodeCC(packet, xid)
		require.NoError(t, err)
		id := legacy.generateCorrelationID(packet.VoIPData.SSRC, callID)
		actual, err := NewX3Encoder().EncodeCCWithCorrelationID(packet, xid, id)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		expected, err = NewX3Encoder().EncodeCCWithPayload(packet, xid, []byte("explicit"))
		require.NoError(t, err)
		actual, err = NewX3Encoder().EncodeCCWithPayloadAndCorrelationID(packet, xid, []byte("explicit"), id)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func TestEncoderCorrelationPayloadBatchAndErrors(t *testing.T) {
	x3 := NewX3Encoder()
	xid := uuid.New()
	packet := correlationRTPPacket("a")
	pdu, err := x3.EncodeCCWithPayloadAndCorrelationID(packet, xid, []byte("explicit"), 42)
	require.NoError(t, err)
	require.Equal(t, []byte("explicit"), pdu.Payload)
	require.Equal(t, []byte{0x80, 0, 0, 1}, packet.RawData)
	requireCorrelationSequence(t, pdu, 0)
	pdus, errs := x3.EncodeCCBatchWithCorrelationID([]*types.PacketDisplay{packet, nil, correlationRTPPacket("b")}, xid, 42)
	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], ErrNotRTP)
	require.Len(t, pdus, 2)
	for i, pdu := range pdus {
		require.Equal(t, uint64(42), pdu.Header.CorrelationID)
		requireCorrelationSequence(t, pdu, uint32(i+1))
	}
	_, err = x3.EncodeCCWithPayloadAndCorrelationID(packet, xid, nil, 42)
	require.ErrorIs(t, err, ErrNoPayload)
	_, err = NewX2Encoder().EncodeIRIWithPolicyAndCorrelationID(nil, xid, SIPContentFull, 42)
	require.ErrorIs(t, err, ErrNotVoIP)
}

func TestEncoderCorrelationConcurrentSelections(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()
	var wg sync.WaitGroup
	for i := uint64(0); i < 32; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			pdu, err := encoder.EncodeCCWithCorrelationID(correlationRTPPacket("same-leg"), xid, id)
			if err != nil {
				t.Error(err)
				return
			}
			if pdu.Header.CorrelationID != id {
				t.Errorf("correlation ID = %d, want %d", pdu.Header.CorrelationID, id)
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, 32, encoder.sequencer.Len())
}
