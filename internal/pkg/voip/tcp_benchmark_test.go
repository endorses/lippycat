package voip

import (
	"context"
	"testing"
	"time"

	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// BenchmarkCallIDDetector_SetCallID benchmarks Call-ID detection performance
func BenchmarkCallIDDetector_SetCallID(b *testing.B) {
	detector := NewCallIDDetector()
	defer detector.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "benchmark-call-id-" + string(rune(i%1000))
		detector.SetCallID(callID)
	}
}

// BenchmarkCallIDDetector_Wait benchmarks Call-ID waiting performance
func BenchmarkCallIDDetector_Wait(b *testing.B) {
	detector := NewCallIDDetector()
	defer detector.Close()

	// Set a Call-ID first
	detector.SetCallID("benchmark-call-id")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.Wait()
	}
}

// BenchmarkSIPStreamProcessing benchmarks SIP stream processing performance
func BenchmarkSIPStreamProcessing(b *testing.B) {
	// Reset config for consistent benchmarking
	ResetConfigOnce()

	ctx := context.Background()
	detector := NewCallIDDetector()
	defer detector.Close()

	readerStream := tcpreader.NewReaderStream()
	config := GetConfig()
	mockFactory := &sipStreamFactory{
		config: config,
	}

	stream := &SIPStream{
		reader:         &readerStream,
		callIDDetector: detector,
		ctx:            ctx,
		factory:        mockFactory,
		createdAt:      time.Now(),
	}

	// Sample SIP message for benchmarking
	sipMessage := []byte(`INVITE sip:user@example.com SIP/2.0
Call-ID: benchmark-call-id-12345@example.com
From: <sip:caller@example.com>;tag=12345
To: <sip:user@example.com>
Content-Length: 0

`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.processSipMessage(sipMessage)
	}
}

// BenchmarkDetectCallIDHeader benchmarks Call-ID header detection
func BenchmarkDetectCallIDHeader(b *testing.B) {
	testCases := []string{
		"Call-ID: benchmark-call-id-12345@example.com",
		"i: short-call-id",
		"From: user@example.com", // Non-Call-ID header
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var callID string
		line := testCases[i%len(testCases)]
		detectCallIDHeader(line, &callID)
	}
}

// BenchmarkTCPStreamFactory benchmarks stream factory creation performance
func BenchmarkTCPStreamFactory(b *testing.B) {
	ResetConfigOnce()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		factory := NewSipStreamFactory(ctx)
		factory.(*sipStreamFactory).Shutdown()
	}
}

// BenchmarkContentLengthParsing benchmarks secure content length parsing
func BenchmarkContentLengthParsing(b *testing.B) {
	testValues := []string{
		"0",
		"1024",
		"65536",
		"invalid",
		"999999999999999999999", // Very large number
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		value := testValues[i%len(testValues)]
		ParseContentLengthSecurely(value)
	}
}

// BenchmarkSIPMessageReading benchmarks complete SIP message reading
func BenchmarkSIPMessageReading(b *testing.B) {
	ResetConfigOnce()
	ctx := context.Background()
	detector := NewCallIDDetector()
	defer detector.Close()

	config := GetConfig()
	mockFactory := &sipStreamFactory{
		config: config,
	}

	// Create sample SIP message data
	sipData := []byte(`INVITE sip:user@example.com SIP/2.0
Call-ID: benchmark-call-id@example.com
From: <sip:caller@example.com>;tag=12345
To: <sip:user@example.com>
Content-Length: 0

`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readerStream := tcpreader.NewReaderStream()
		stream := &SIPStream{
			reader:         &readerStream,
			callIDDetector: detector,
			ctx:            ctx,
			factory:        mockFactory,
			createdAt:      time.Now(),
		}

		// Directly process the SIP message instead of complex stream simulation
		stream.processSipMessage(sipData)
	}
}

// BenchmarkSecurityValidation benchmarks Call-ID security validation
func BenchmarkSecurityValidation(b *testing.B) {
	testCallIDs := []string{
		"normal-call-id@example.com",
		"call-id-with-special-chars!@#$%^&*()",
		"very-long-call-id-" + string(make([]byte, 500)),
		"../path/traversal/attempt",
		"call\x00id\x00with\x00nulls",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := testCallIDs[i%len(testCallIDs)]
		ValidateCallIDForSecurity(callID)
	}
}

// BenchmarkCallIDSanitization benchmarks Call-ID sanitization performance
func BenchmarkCallIDSanitization(b *testing.B) {
	testCallIDs := []string{
		"short-call-id",
		"medium-length-call-id@example.com",
		"very-long-call-id-" + string(make([]byte, 1000)),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := testCallIDs[i%len(testCallIDs)]
		SanitizeCallIDForLogging(callID)
	}
}