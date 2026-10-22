//go:build li

package x2x3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestKeepaliveControlPDU(t *testing.T) {
	for _, pdu := range []*PDU{NewKeepalivePDUWithSequence(0), NewKeepaliveAckPDU(42)} {
		wire, err := pdu.MarshalBinary()
		require.NoError(t, err)
		decoded, err := ReadPDU(bytes.NewReader(wire))
		require.NoError(t, err)
		require.Equal(t, uint32(48), decoded.Header.HeaderLength)
		require.Zero(t, decoded.Header.PayloadLength)
		require.Zero(t, decoded.Header.PayloadFormat)
		require.Zero(t, decoded.Header.PayloadDirection)
		require.Equal(t, uuid.Nil, decoded.Header.XID)
		require.Zero(t, decoded.Header.CorrelationID)
		require.Empty(t, decoded.Payload)
		require.Len(t, decoded.Attributes, 1)
		require.Equal(t, AttrSequenceNumber, decoded.Attributes[0].Type)
		require.Len(t, decoded.Attributes[0].Value, SequenceNumberSize)
		sequence, err := decoded.KeepaliveSequence()
		require.NoError(t, err)
		require.Equal(t, pdu.Attributes[0].Value, decoded.Attributes[0].Value)
		if pdu.Header.Type == PDUTypeKeepalive {
			require.Equal(t, uint32(0), sequence)
		} else {
			require.Equal(t, uint32(42), sequence)
		}
	}
}

func TestKeepaliveRejectsUnsupportedMajorVersion(t *testing.T) {
	for _, pdu := range []*PDU{NewKeepalivePDUWithSequence(7), NewKeepaliveAckPDU(7)} {
		wire, err := pdu.MarshalBinary()
		require.NoError(t, err)
		binary.BigEndian.PutUint16(wire[:2], 0x0100)
		_, err = ReadPDU(bytes.NewReader(wire))
		require.ErrorIs(t, err, ErrInvalidVersion)
		var decoded PDU
		require.ErrorIs(t, decoded.UnmarshalBinary(wire), ErrInvalidVersion)
	}
}

func TestKeepaliveRejectsMalformedSequence(t *testing.T) {
	for _, size := range []int{0, 1, 3, 5, 8} {
		pdu := NewKeepalivePDUWithSequence(7)
		pdu.Attributes[0].Value = make([]byte, size)
		_, err := pdu.KeepaliveSequence()
		require.Error(t, err)
	}
}

func TestKeepaliveRejectsAdditionalAttributes(t *testing.T) {
	pdu := NewKeepalivePDUWithSequence(1)
	pdu.AddAttribute((&TLVEncoder{}).EncodeUint32(AttrSequenceNumber, 2))
	_, err := pdu.KeepaliveSequence()
	require.Error(t, err)
}
