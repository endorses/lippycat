package capture

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildESPPayload constructs a synthetic ESP payload with NULL encryption.
// Layout: [inner transport data][padding 0x01,0x02,...][pad_len][next_hdr][ICV]
func buildESPPayload(innerData []byte, nextHdr byte, padLen int, icvSize int) []byte {
	payloadLen := len(innerData) + padLen + 2 + icvSize
	payload := make([]byte, payloadLen)
	copy(payload, innerData)
	// Sequential padding bytes
	for i := 0; i < padLen; i++ {
		payload[len(innerData)+i] = byte(i + 1)
	}
	// pad_len and next_hdr
	payload[len(innerData)+padLen] = byte(padLen)
	payload[len(innerData)+padLen+1] = nextHdr
	// ICV is zero-filled (already done by make)
	return payload
}

// buildMinimalUDPHeader creates a minimal UDP header with correct length field.
func buildMinimalUDPHeader(srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	hdr := make([]byte, udpLen)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(udpLen))
	// checksum left at 0
	copy(hdr[8:], payload)
	return hdr
}

// buildMinimalTCPHeader creates a minimal 20-byte TCP header.
func buildMinimalTCPHeader(srcPort, dstPort uint16, payload []byte) []byte {
	hdrLen := 20 + len(payload)
	hdr := make([]byte, hdrLen)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	hdr[12] = 5 << 4 // data offset = 5 (20 bytes), min valid
	copy(hdr[20:], payload)
	return hdr
}

// resetESPNullConfig resets the cached ESP-NULL config so tests can re-initialize.
func resetESPNullConfig() {
	espNullConfigOnce = sync.Once{}
	espNullEnabled = false
	espFixedICVSize = -1
}

func TestTryESPTrailerValidation_AutoDetect(t *testing.T) {
	// Build a UDP packet inside ESP-NULL with ICV size 12 (HMAC-SHA1-96).
	sipPayload := []byte("INVITE sip:bob@example.com SIP/2.0\r\n")
	udpData := buildMinimalUDPHeader(5060, 5060, sipPayload)
	espPayload := buildESPPayload(udpData, 17, 2, 12) // next_hdr=17 (UDP), 2 pad bytes, 12-byte ICV

	proto, innerLen, ok := tryESPTrailerValidation(espPayload, -1)
	require.True(t, ok, "should detect UDP via trailer validation")
	assert.Equal(t, layers.IPProtocolUDP, proto)
	assert.Equal(t, len(udpData), innerLen)
}

func TestTryESPTrailerValidation_FixedICV12(t *testing.T) {
	sipPayload := []byte("SIP/2.0 200 OK\r\n")
	udpData := buildMinimalUDPHeader(5060, 5060, sipPayload)
	espPayload := buildESPPayload(udpData, 17, 1, 12)

	proto, innerLen, ok := tryESPTrailerValidation(espPayload, 12)
	require.True(t, ok)
	assert.Equal(t, layers.IPProtocolUDP, proto)
	assert.Equal(t, len(udpData), innerLen)
}

func TestTryESPTrailerValidation_FixedICV0(t *testing.T) {
	// NULL authentication (0-byte ICV).
	sipPayload := []byte("BYE sip:bob@example.com SIP/2.0\r\n")
	udpData := buildMinimalUDPHeader(5060, 5060, sipPayload)
	espPayload := buildESPPayload(udpData, 17, 0, 0)

	proto, innerLen, ok := tryESPTrailerValidation(espPayload, 0)
	require.True(t, ok)
	assert.Equal(t, layers.IPProtocolUDP, proto)
	assert.Equal(t, len(udpData), innerLen)
}

func TestTryESPTrailerValidation_FixedICVWrong(t *testing.T) {
	// Build with ICV 12 but try to parse with fixed ICV 16 — should fail.
	sipPayload := []byte("INVITE sip:bob@example.com SIP/2.0\r\n")
	udpData := buildMinimalUDPHeader(5060, 5060, sipPayload)
	espPayload := buildESPPayload(udpData, 17, 2, 12)

	_, _, ok := tryESPTrailerValidation(espPayload, 16)
	assert.False(t, ok, "wrong ICV size should not match")
}

func TestTryESPTrailerValidation_TCP(t *testing.T) {
	// TCP SYN packet (no payload) inside ESP-NULL.
	tcpData := buildMinimalTCPHeader(5060, 5060, nil)
	espPayload := buildESPPayload(tcpData, 6, 2, 12) // next_hdr=6 (TCP)

	proto, innerLen, ok := tryESPTrailerValidation(espPayload, -1)
	require.True(t, ok)
	assert.Equal(t, layers.IPProtocolTCP, proto)
	assert.Equal(t, len(tcpData), innerLen)
}

func TestTryESPTrailerValidation_EncryptedPayload(t *testing.T) {
	// Encrypted payload has random padding, should not match.
	payload := make([]byte, 40)
	// Fill with random-looking bytes (non-sequential padding)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	// Set last bytes to look like a trailer with next_hdr=17 but bad padding
	payload[len(payload)-1] = 17   // next_hdr = UDP
	payload[len(payload)-2] = 4    // pad_len = 4
	payload[len(payload)-6] = 0xFF // non-sequential padding

	_, _, ok := tryESPTrailerValidation(payload, -1)
	assert.False(t, ok, "encrypted payload should not match")
}

func TestGetESPNullConfig_Defaults(t *testing.T) {
	resetESPNullConfig()
	viper.Reset()

	enabled, icvSize := getESPNullConfig()
	assert.False(t, enabled)
	assert.Equal(t, -1, icvSize)
}

func TestGetESPNullConfig_Enabled(t *testing.T) {
	resetESPNullConfig()
	viper.Reset()
	viper.Set("esp_null", true)
	viper.Set("esp_icv_size", 12)

	enabled, icvSize := getESPNullConfig()
	assert.True(t, enabled)
	assert.Equal(t, 12, icvSize)
}

func TestGetESPNullConfig_InvalidICVSize(t *testing.T) {
	resetESPNullConfig()
	viper.Reset()
	viper.Set("esp_null", true)
	viper.Set("esp_icv_size", 7) // invalid

	enabled, icvSize := getESPNullConfig()
	assert.True(t, enabled)
	assert.Equal(t, -1, icvSize, "invalid ICV size should fall back to auto-detect")
}

func TestTryESPTrailerValidation_AllICVSizes(t *testing.T) {
	// Verify all valid ICV sizes work with auto-detect.
	for _, icv := range []int{0, 8, 12, 16} {
		t.Run("icv_"+string(rune('0'+icv/4)), func(t *testing.T) {
			sipPayload := []byte("REGISTER sip:example.com SIP/2.0\r\n")
			udpData := buildMinimalUDPHeader(5060, 5060, sipPayload)
			espPayload := buildESPPayload(udpData, 17, 3, icv)

			proto, _, ok := tryESPTrailerValidation(espPayload, -1)
			require.True(t, ok, "should detect with ICV size %d", icv)
			assert.Equal(t, layers.IPProtocolUDP, proto)
		})
	}
}

func TestTryESPTrailerValidation_NonVoIPProtocol(t *testing.T) {
	// HTTP payload inside ESP-NULL — heuristic mode would miss this
	// but trailer validation should still identify the inner protocol.
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	tcpData := buildMinimalTCPHeader(12345, 80, httpPayload)
	espPayload := buildESPPayload(tcpData, 6, 2, 12)

	proto, innerLen, ok := tryESPTrailerValidation(espPayload, 12)
	require.True(t, ok)
	assert.Equal(t, layers.IPProtocolTCP, proto)
	assert.Equal(t, len(tcpData), innerLen)
}
