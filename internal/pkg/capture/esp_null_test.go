package capture

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/google/gopacket"
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

// buildESPNullIPv6Packet assembles a full Ethernet/IPv6/ESP-NULL packet carrying the
// given inner transport segment, matching the on-wire layout decapsulateESPNull expects.
func buildESPNullIPv6Packet(spi uint32, innerTransport []byte, nextHdr byte, padLen, icvSize int) []byte {
	espPayload := buildESPPayload(innerTransport, nextHdr, padLen, icvSize)
	espFull := make([]byte, 8+len(espPayload))
	binary.BigEndian.PutUint32(espFull[0:4], spi) // SPI
	binary.BigEndian.PutUint32(espFull[4:8], 1)   // Seq
	copy(espFull[8:], espPayload)

	ip := make([]byte, 40)
	ip[0] = 0x60                                              // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(espFull))) // payload length
	ip[6] = 50                                                // Next Header = ESP
	ip[7] = 64                                                // hop limit
	ip[8] = 0x20                                              // non-zero src addr
	ip[24] = 0x20                                             // non-zero dst addr

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x86DD) // EtherType IPv6

	raw := make([]byte, 0, len(eth)+len(ip)+len(espFull))
	raw = append(raw, eth...)
	raw = append(raw, ip...)
	raw = append(raw, espFull...)
	return raw
}

// TestESPStripTrailerLen_TCP verifies espStripTrailerLen strips exactly
// icvSize+2+pad_len bytes from a TCP inner segment across all valid ICV sizes.
func TestESPStripTrailerLen_TCP(t *testing.T) {
	tcpData := buildMinimalTCPHeader(5060, 5060, []byte("MESSAGE sip:x@y SIP/2.0\r\n\r\n"))
	for _, padLen := range []int{0, 1, 2, 5} {
		for _, icv := range []int{0, 8, 12, 16} {
			espPayload := buildESPPayload(tcpData, 6, padLen, icv)
			// Fixed ICV.
			got := espStripTrailerLen(espPayload, icv, layers.IPProtocolTCP)
			assert.Equal(t, len(tcpData), got, "icv=%d pad=%d fixed", icv, padLen)
			assert.Equal(t, icv+2+padLen, len(espPayload)-got, "stripped bytes icv=%d pad=%d", icv, padLen)
			// Auto-detect.
			gotAuto := espStripTrailerLen(espPayload, -1, layers.IPProtocolTCP)
			assert.Equal(t, len(tcpData), gotAuto, "icv=%d pad=%d auto", icv, padLen)
		}
	}
}

// TestESPStripTrailerLen_FallbackImplausible verifies that an implausible trailer
// falls back to the full payload length rather than returning garbage.
func TestESPStripTrailerLen_FallbackImplausible(t *testing.T) {
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	payload[len(payload)-1] = 6   // next_hdr = TCP
	payload[len(payload)-2] = 200 // pad_len absurdly large → innerEnd <= 0
	got := espStripTrailerLen(payload, 12, layers.IPProtocolTCP)
	assert.Equal(t, len(payload), got, "implausible trailer falls back to full length")
}

// TestDecapsulateESPNull_TCPStripsTrailerAndFixesLength is the regression test for the
// trailer/ICV bug: a decapsulated TCP segment must carry the SIP payload with NO
// trailing ESP trailer bytes, and the outer IPv6 payload length must match the stripped
// segment length (otherwise TCP sequence numbers desync and requests never reassemble).
func TestDecapsulateESPNull_TCPStripsTrailerAndFixesLength(t *testing.T) {
	resetESPNullConfig()
	viper.Reset()
	viper.Set("esp_null", true)
	viper.Set("esp_icv_size", 12)
	defer func() {
		resetESPNullConfig()
		viper.Reset()
	}()

	sip := []byte("MESSAGE sip:+4915215940608@ims.example SIP/2.0\r\n" +
		"Content-Type: text/plain\r\nContent-Length: 4\r\n\r\ntest")
	tcpData := buildMinimalTCPHeader(5060, 5060, sip)
	padLen, icvSize := 2, 12
	raw := buildESPNullIPv6Packet(0xdeadbeef, tcpData, 6, padLen, icvSize)

	pkt := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.Default)
	require.NotNil(t, pkt.Layer(layers.LayerTypeIPSecESP), "input must parse as ESP")

	out, ok := decapsulateESPNull(pkt)
	require.True(t, ok, "decapsulation should succeed")

	ip6Layer := out.Layer(layers.LayerTypeIPv6)
	require.NotNil(t, ip6Layer, "rebuilt packet must have IPv6 layer")
	ip6 := ip6Layer.(*layers.IPv6)
	assert.Equal(t, len(tcpData), int(ip6.Length),
		"IPv6 payload length must equal stripped TCP segment length (no trailer)")
	assert.Equal(t, layers.IPProtocolTCP, ip6.NextHeader)

	tcpLayer := out.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "rebuilt packet must have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.Equal(t, sip, tcp.Payload, "TCP payload must be the SIP content with no trailer bytes")
}

// TestDecapsulateESPNull_CachedSPIStripsTrailer exercises the SPI-cache hot path used in
// explicit --esp-null mode: after a SPI is confirmed, a TCP continuation segment whose
// payload does not start with SIP text must still be stripped of its ESP trailer.
func TestDecapsulateESPNull_CachedSPIStripsTrailer(t *testing.T) {
	resetESPNullConfig()
	viper.Reset()
	viper.Set("esp_null", true)
	viper.Set("esp_icv_size", 12)
	defer func() {
		resetESPNullConfig()
		viper.Reset()
	}()

	const spi = uint32(0xcafef00d)
	// Pre-seed the cache as if a prior packet on this SPI confirmed TCP.
	espNullSPICache.Store(spi, layers.IPProtocolTCP)

	// Continuation payload: not SIP text, so content heuristics fail and the cache path runs.
	body := []byte("continuation body bytes that are not SIP")
	tcpData := buildMinimalTCPHeader(5060, 5060, body)
	padLen, icvSize := 3, 12
	raw := buildESPNullIPv6Packet(spi, tcpData, 6, padLen, icvSize)

	pkt := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.Default)
	out, ok := decapsulateESPNull(pkt)
	require.True(t, ok)

	ip6 := out.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	assert.Equal(t, len(tcpData), int(ip6.Length),
		"cache path must strip trailer so IPv6 length equals TCP segment length")
	tcp := out.Layer(layers.LayerTypeTCP).(*layers.TCP)
	assert.Equal(t, body, tcp.Payload)
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
