//go:build li

package x2x3

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeepaliveControlPDU(t *testing.T) {
	for _, pdu := range []*PDU{NewKeepalivePDUWithSequence(0), NewKeepaliveAckPDU(42)} {
		wire, err := pdu.MarshalBinary()
		require.NoError(t, err)
		decoded, err := ReadPDU(bytes.NewReader(wire))
		require.NoError(t, err)
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

func TestKeepaliveRejectsAdditionalAttributes(t *testing.T) {
	pdu := NewKeepalivePDUWithSequence(1)
	pdu.AddAttribute((&TLVEncoder{}).EncodeUint32(AttrSequenceNumber, 2))
	_, err := pdu.KeepaliveSequence()
	require.Error(t, err)
}
