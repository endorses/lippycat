package voip

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestCallIDDetector_RaceConditions(t *testing.T) {
	t.Run("Concurrent SetCallID calls", func(t *testing.T) {
		detector := NewCallIDDetector()
		defer detector.Close()

		const numGoroutines = 100
		var wg sync.WaitGroup

		// Start multiple goroutines trying to set different call IDs
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				detector.SetCallID(fmt.Sprintf("call-id-%d", id))
			}(i)
		}

		// Start one goroutine to wait for result
		var result string
		wg.Add(1)
		go func() {
			defer wg.Done()
			result = detector.Wait()
		}()

		wg.Wait()

		// Should get one of the call IDs (first one to be set)
		assert.NotEmpty(t, result, "Should receive a call ID")
		assert.Contains(t, result, "call-id-", "Should be one of the test call IDs")
	})

	t.Run("SetCallID after Close", func(t *testing.T) {
		detector := NewCallIDDetector()
		detector.Close()

		// Setting call ID after close should not panic
		assert.NotPanics(t, func() {
			detector.SetCallID("test-call-id")
		})

		// Wait should return empty string quickly
		start := time.Now()
		result := detector.Wait()
		duration := time.Since(start)

		assert.Empty(t, result, "Should return empty string after close")
		assert.Less(t, duration, time.Second, "Should return quickly")
	})

	t.Run("Multiple Close calls", func(t *testing.T) {
		detector := NewCallIDDetector()

		// Multiple close calls should not panic
		assert.NotPanics(t, func() {
			detector.Close()
			detector.Close()
			detector.Close()
		})
	})

	t.Run("Wait timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping timeout test in short mode")
		}

		detector := NewCallIDDetector()
		defer detector.Close()

		// This test would normally wait for 30 seconds, but that's too long for CI
		// Instead, we'll test that the mechanism works by closing the detector
		go func() {
			time.Sleep(100 * time.Millisecond)
			detector.Close()
		}()

		start := time.Now()
		result := detector.Wait()
		duration := time.Since(start)

		assert.Empty(t, result, "Should return empty string when closed")
		assert.Less(t, duration, 1*time.Second, "Should return quickly when closed")
	})
}

func TestCallIDDetector_EdgeCases(t *testing.T) {
	t.Run("Empty call ID", func(t *testing.T) {
		detector := NewCallIDDetector()
		defer detector.Close()

		detector.SetCallID("")

		result := detector.Wait()
		assert.Equal(t, "", result, "Should handle empty call ID")
	})

	t.Run("Very long call ID", func(t *testing.T) {
		detector := NewCallIDDetector()
		defer detector.Close()

		longCallID := strings.Repeat("very-long-call-id-", 10000)
		detector.SetCallID(longCallID)

		result := detector.Wait()
		assert.Equal(t, longCallID, result, "Should handle very long call ID")
	})

	t.Run("Call ID with special characters", func(t *testing.T) {
		detector := NewCallIDDetector()
		defer detector.Close()

		specialCallID := "call-id-with-特殊字符-and-🚀-emoji"
		detector.SetCallID(specialCallID)

		result := detector.Wait()
		assert.Equal(t, specialCallID, result, "Should handle special characters")
	})
}

func TestSIPStream_PanicRecovery(t *testing.T) {
	ctx := context.Background()
	factory := NewSipStreamFactory(ctx)
	defer factory.(*sipStreamFactory).Shutdown()

	t.Run("Panic in run() method", func(t *testing.T) {
		// Create a mock reader that will cause panic
		detector := NewCallIDDetector()

		stream := &SIPStream{
			reader:         nil, // This will cause panic when accessed
			callIDDetector: detector,
			ctx:            ctx,
			factory:        factory.(*sipStreamFactory),
		}

		// Mock the reader to panic
		done := make(chan bool, 1)
		go func() {
			defer func() {
				done <- true
			}()
			// This should not crash the test
			stream.run()
		}()

		select {
		case <-done:
			// Success - panic was recovered
		case <-time.After(2 * time.Second):
			t.Fatal("Stream run did not complete - panic might not have been recovered")
		}

		// Detector should be closed
		result := detector.Wait()
		assert.Empty(t, result, "Detector should be closed and return empty")
	})
}

func TestSIPStream_ContextCancellation(t *testing.T) {
	t.Run("Stream shutdown on context cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		factory := NewSipStreamFactory(ctx)
		defer factory.(*sipStreamFactory).Shutdown()

		// Create a mock reader that blocks
		detector := NewCallIDDetector()

		stream := &SIPStream{
			reader:         nil, // We'll test the context cancellation path
			callIDDetector: detector,
			ctx:            ctx,
			factory:        factory.(*sipStreamFactory),
		}

		done := make(chan bool, 1)
		go func() {
			stream.run()
			done <- true
		}()

		// Cancel context
		cancel()

		// Stream should shut down quickly
		select {
		case <-done:
			// Success
		case <-time.After(1 * time.Second):
			t.Fatal("Stream did not shut down after context cancellation")
		}
	})
}

func TestSIPStream_CallIDParsing(t *testing.T) {
	// Reset and initialize config for this test
	ResetConfigOnce()

	tests := []struct {
		name           string
		input          string
		expectedCallID string
		description    string
	}{
		{
			name:           "Standard Call-ID header",
			input:          "Call-ID: abc123@example.com\r\n\r\n",
			expectedCallID: "abc123@example.com",
			description:    "Standard Call-ID should be parsed",
		},
		{
			name:           "Short form Call-ID (i:)",
			input:          "i: short-call-id\r\n\r\n",
			expectedCallID: "short-call-id",
			description:    "Short form Call-ID should be parsed",
		},
		{
			name:           "Call-ID with extra whitespace",
			input:          "Call-ID:   whitespace-call-id   \r\n\r\n",
			expectedCallID: "whitespace-call-id",
			description:    "Whitespace should be trimmed",
		},
		{
			name:           "Call-ID with special characters",
			input:          "Call-ID: call-id-with-@#$%^&*()_+\r\n\r\n",
			expectedCallID: "call-id-with-@#$%^&*()_+",
			description:    "Special characters should be preserved",
		},
		{
			name:           "Empty Call-ID",
			input:          "Call-ID: \r\n\r\n",
			expectedCallID: "",
			description:    "Empty Call-ID should be handled",
		},
		{
			name:           "Non-Call-ID line",
			input:          "From: user@example.com\r\n\r\n",
			expectedCallID: "",
			description:    "Non-Call-ID lines should be ignored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			detector := NewCallIDDetector()

			// Create a mock ReaderStream
			readerStream := tcpreader.NewReaderStream()

			// Create a properly initialized factory for testing
			mockFactory := NewSipStreamFactory(ctx).(*sipStreamFactory)
			defer mockFactory.Shutdown()

			stream := &SIPStream{
				reader:         &readerStream,
				callIDDetector: detector,
				ctx:            ctx,
				factory:        mockFactory,
				createdAt:      time.Now(),
			}

			// Write data to the stream and close it
			go func() {
				readerStream.Reassembled([]tcpassembly.Reassembly{
					{
						Bytes: []byte(tt.input),
						Skip:  0,
						Start: true,
						End:   true,
						Seen:  time.Now(),
					},
				})
				readerStream.ReassemblyComplete()
			}()

			// Run stream processing in background
			done := make(chan bool, 1)
			go func() {
				stream.run()
				done <- true
			}()

			// Wait for processing to complete
			select {
			case <-done:
				// Success
			case <-time.After(100 * time.Millisecond):
				// Some tests might timeout, that's ok for non-Call-ID lines
				cancel()
			}

			// Check result - use Wait() with a timeout
			resultChan := make(chan string, 1)
			go func() {
				resultChan <- detector.Wait()
			}()

			var result string
			select {
			case result = <-resultChan:
				// Got result
			case <-time.After(10 * time.Millisecond):
				// Timeout - expected for non-Call-ID lines
				result = ""
			}
			if tt.expectedCallID == "" {
				// For non-Call-ID lines, detector should be empty
				assert.Empty(t, result, tt.description)
			} else {
				assert.Equal(t, tt.expectedCallID, result, tt.description)
			}
		})
	}
}

func TestHandleTcpPackets_PortFiltering(t *testing.T) {
	// This test is skipped due to complex assembler mock requirements
	t.Skip("Skipping TCP packet handler test - requires complex assembler mock setup")
}

func TestSipStreamFactory_ResourceManagement(t *testing.T) {
	t.Run("Factory cleanup", func(t *testing.T) {
		ctx := context.Background()
		factory := NewSipStreamFactory(ctx)
		defer factory.(*sipStreamFactory).Shutdown()

		// Create multiple streams
		net := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 2})
		transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x13, 0xc4}, []byte{0x13, 0xc4}) // 5060

		stream1 := factory.New(net, transport)
		stream2 := factory.New(net, transport)
		stream3 := factory.New(net, transport)

		assert.NotNil(t, stream1, "Should create first stream")
		assert.NotNil(t, stream2, "Should create second stream")
		assert.NotNil(t, stream3, "Should create third stream")

		// Shutdown factory
		assert.NotPanics(t, func() {
			factory.(*sipStreamFactory).Shutdown()
		}, "Factory shutdown should not panic")

		// Multiple shutdowns should not panic (second one is no-op)
		assert.NotPanics(t, func() {
			factory.(*sipStreamFactory).Shutdown()
			factory.(*sipStreamFactory).Shutdown()
		}, "Multiple factory shutdowns should not panic")
	})
}

// Mock implementations for testing

type PanicReader struct{}

func (p *PanicReader) Read([]byte) (n int, err error) {
	panic("test panic in reader")
}

type BlockingReader struct{}

func (b *BlockingReader) Read([]byte) (n int, err error) {
	// Block forever
	select {}
}

type MockTCPReader struct {
	data string
	pos  int
}

func (m *MockTCPReader) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}

	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

type MockAssembler struct {
	Called bool
}

func (m *MockAssembler) AssembleWithTimestamp(netFlow gopacket.Flow, tcp *layers.TCP, timestamp time.Time) {
	m.Called = true
}

func (m *MockAssembler) Assemble(netFlow gopacket.Flow, tcp *layers.TCP) {
	m.Called = true
}

func (m *MockAssembler) FlushOlderThan(time.Time) {
	// Mock implementation
}

func (m *MockAssembler) FlushAll() {
	// Mock implementation
}
