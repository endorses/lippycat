package application

import (
	"encoding/binary"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/require"
)

func dhcpPayload() []byte {
	b := make([]byte, 240)
	b[0] = 1
	b[1] = 1
	b[2] = 6
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	return b
}

func TestDHCPSignatureUsesValidatedExtraction(t *testing.T) {
	b := dhcpPayload()
	b = append(b, 53, 1, 1, 52, 1, 1, 12, 2, 'a', 'b', 255)
	copy(b[108:236], []byte{12, 2, 'c', 'd', 255})
	ctx := &signatures.DetectionContext{Payload: b, Transport: "UDP", SrcPort: 68, DstPort: 67}
	result := NewDHCPSignature().Detect(ctx)
	require.NotNil(t, result)
	require.Equal(t, "DHCP", result.Protocol)
	require.Equal(t, "abcd", result.Metadata["options"].(map[string]interface{})["hostname"])
	ctx.Payload = append(dhcpPayload(), 53, 1, 1, 12, 2, 'a')
	result = NewDHCPSignature().Detect(ctx)
	require.NotNil(t, result)
	require.Equal(t, true, result.Metadata["partial"])
	require.Equal(t, true, result.Metadata["truncated"])
	ctx.Payload = append(dhcpPayload(), 53, 1, 1, 53, 1, 2, 255)
	require.Nil(t, NewDHCPSignature().Detect(ctx))
}

func TestDHCPSignaturePreservesBOOTP(t *testing.T) {
	for _, b := range [][]byte{dhcpPayload()[:236], append(dhcpPayload(), 255)} {
		result := NewDHCPSignature().Detect(&signatures.DetectionContext{Payload: b, Transport: "UDP", SrcPort: 68, DstPort: 67})
		require.NotNil(t, result)
		require.Equal(t, "BOOTP", result.Protocol)
	}
	b := dhcpPayload()
	b[236] = 0
	result := NewDHCPSignature().Detect(&signatures.DetectionContext{Payload: b, Transport: "UDP", SrcPort: 68, DstPort: 67})
	require.NotNil(t, result)
	require.Equal(t, "BOOTP", result.Protocol)
}
