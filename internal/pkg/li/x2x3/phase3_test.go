package x2x3

import (
	"errors"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSIPPayloadRequired(t *testing.T) {
	_, err := NewX2Encoder().EncodeIRI(&types.PacketDisplay{VoIPData: &types.VoIPMetadata{CallID: "safe", Method: "INVITE"}}, uuid.New())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoSIPPayload))
}
func TestRawIPCCPreservesEvidence(t *testing.T) {
	raw := []byte{0x45, 0, 0, 20}
	ts := time.Unix(1, 2)
	p, err := NewX3Encoder().EncodeRawIPCC(&types.PacketDisplay{Timestamp: ts, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", RawData: raw}, uuid.New(), "192.0.2.1")
	require.NoError(t, err)
	assert.Equal(t, PayloadFormatIPv4, p.Header.PayloadFormat)
	assert.Equal(t, raw, p.Payload)
	require.NotNil(t, FindAttribute(p.Attributes, AttrTimestamp))
}
func TestRawEthernetCCFormat(t *testing.T) {
	p, err := NewX3Encoder().EncodeRawIPCC(&types.PacketDisplay{RawData: []byte{1, 2, 3}, LinkType: layers.LinkTypeEthernet}, uuid.New(), "2001:db8::1")
	require.NoError(t, err)
	assert.Equal(t, PayloadFormatEthernet, p.Header.PayloadFormat)
}
