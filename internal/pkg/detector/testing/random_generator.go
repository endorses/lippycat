package testing

import (
	"crypto/rand"
	"math/big"
)

// RandomPacketGenerator generates random packet payloads for false positive testing
type RandomPacketGenerator struct {
	seed int64
}

// NewRandomPacketGenerator creates a new random packet generator
func NewRandomPacketGenerator() *RandomPacketGenerator {
	return &RandomPacketGenerator{}
}

// GenerateRandomPayload creates a random byte slice of specified length
func (g *RandomPacketGenerator) GenerateRandomPayload(length int) []byte {
	payload := make([]byte, length)
	_, err := rand.Read(payload)
	if err != nil {
		panic(err)
	}
	return payload
}

// GeneratePrintablePayload creates a payload with printable ASCII characters
func (g *RandomPacketGenerator) GeneratePrintablePayload(length int) []byte {
	payload := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(95))
		if err != nil {
			panic(err)
		}
		payload[i] = byte(32 + n.Int64()) // ASCII 32-126
	}
	return payload
}

// GenerateBinaryPayload creates a payload with random binary data
func (g *RandomPacketGenerator) GenerateBinaryPayload(length int) []byte {
	return g.GenerateRandomPayload(length)
}

// GenerateWithPattern creates a payload with a specific byte pattern
func (g *RandomPacketGenerator) GenerateWithPattern(length int, pattern []byte) []byte {
	payload := make([]byte, length)
	for i := 0; i < length; i++ {
		payload[i] = pattern[i%len(pattern)]
	}
	return payload
}

// GenerateCommonPatterns returns common patterns that might trigger false positives
func (g *RandomPacketGenerator) GenerateCommonPatterns() [][]byte {
	patterns := [][]byte{
		// All zeros
		make([]byte, 1500),
		// All ones
		g.GenerateWithPattern(1500, []byte{0xFF}),
		// Alternating pattern
		g.GenerateWithPattern(1500, []byte{0xAA, 0x55}),
		// Sequential bytes
		func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
		// Common text patterns
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("POST /api HTTP/1.1\r\n"),
		[]byte("INVITE sip:user@example.com SIP/2.0\r\n"),
		[]byte("\x00\x00\x00\x00\x00\x00\x00\x00"),
	}
	return patterns
}

// GenerateVariableLengthPayloads generates payloads of various common sizes
func (g *RandomPacketGenerator) GenerateVariableLengthPayloads() [][]byte {
	sizes := []int{0, 1, 8, 16, 32, 64, 128, 256, 512, 1024, 1500}
	payloads := make([][]byte, len(sizes))
	for i, size := range sizes {
		payloads[i] = g.GenerateRandomPayload(size)
	}
	return payloads
}

// GenerateEdgeCases generates edge case payloads
func (g *RandomPacketGenerator) GenerateEdgeCases() [][]byte {
	return [][]byte{
		// Empty payload
		{},
		// Single byte
		{0x00},
		// Two bytes
		{0x00, 0x00},
		// Minimum DNS-like (12 bytes header)
		g.GenerateRandomPayload(12),
		// Minimum DHCP-like (240 bytes)
		g.GenerateRandomPayload(240),
		// Maximum Ethernet frame
		g.GenerateRandomPayload(1500),
		// Jumbo frame
		g.GenerateRandomPayload(9000),
	}
}
