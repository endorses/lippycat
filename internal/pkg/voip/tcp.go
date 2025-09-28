package voip

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type CallIDDetector struct {
	mu     sync.Mutex
	callID string
	found  bool
	done   chan struct{}
	closed bool
}

func NewCallIDDetector() *CallIDDetector {
	return &CallIDDetector{
		done: make(chan struct{}),
	}
}

func (c *CallIDDetector) SetCallID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.found && !c.closed {
		c.callID = id
		c.found = true
		c.closed = true
		close(c.done)
	}
}

func (c *CallIDDetector) Wait() string {
	timeout := GetConfig().CallIDDetectionTimeout
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.callID
	case <-time.After(timeout): // Prevent indefinite waiting
		return ""
	}
}

func (c *CallIDDetector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
}

type sipStreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	config           *Config
	lastLogTime      int64
	streamQueue      chan *queuedStream
	queueWorker      sync.WaitGroup
}

type queuedStream struct {
	reader   *tcpreader.ReaderStream
	detector *CallIDDetector
}

func NewSipStreamFactory(ctx context.Context) tcpassembly.StreamFactory {
	ctx, cancel := context.WithCancel(ctx)
	config := GetConfig()
	factory := &sipStreamFactory{
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
		streamQueue: make(chan *queuedStream, config.StreamQueueBuffer),
	}

	// Start queue worker goroutine to process queued streams
	factory.queueWorker.Add(1)
	go factory.processQueue()

	return factory
}

func (f *sipStreamFactory) processQueue() {
	defer f.queueWorker.Done()

	for {
		select {
		case <-f.ctx.Done():
			// Drain the queue and close remaining streams
			for {
				select {
				case queuedStream := <-f.streamQueue:
					if queuedStream.detector != nil {
						queuedStream.detector.Close()
					}
				default:
					return
				}
			}
		case queuedStream := <-f.streamQueue:
			// Check if we can process this stream now
			current := atomic.LoadInt64(&f.activeGoroutines)
			if current < int64(f.config.MaxGoroutines) {
				// Process the stream
				stream := &SIPStream{
					reader:         queuedStream.reader,
					callIDDetector: queuedStream.detector,
					ctx:            f.ctx,
					factory:        f,
				}
				atomic.AddInt64(&f.activeGoroutines, 1)
				go stream.run()
			} else {
				// Still at capacity, put it back in queue or drop it
				select {
				case f.streamQueue <- queuedStream:
					// Successfully queued again
				default:
					// Queue is full, gracefully close the stream
					logger.Warn("Stream queue full, dropping stream gracefully")
					if queuedStream.detector != nil {
						queuedStream.detector.Close()
					}
				}
			}
		}
	}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	detector := NewCallIDDetector()

	// Check if we're at the goroutine limit
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.config.MaxGoroutines) {
		// Try to queue the stream instead of dropping it immediately
		queuedStream := &queuedStream{
			reader:   &r,
			detector: detector,
		}

		select {
		case f.streamQueue <- queuedStream:
			// Successfully queued, stream will be processed when capacity is available
			logger.Debug("Stream queued due to goroutine limit",
				"max_goroutines", f.config.MaxGoroutines,
				"current_goroutines", current,
				"queue_length", len(f.streamQueue))
		default:
			// Queue is full, log and gracefully close
			now := time.Now().Unix()
			lastLog := atomic.LoadInt64(&f.lastLogTime)
			logInterval := int64(f.config.LogGoroutineLimitInterval.Seconds())
			if now-lastLog > logInterval {
				atomic.StoreInt64(&f.lastLogTime, now)
				logger.Warn("SIP stream queue full, dropping stream",
					"max_goroutines", f.config.MaxGoroutines,
					"queue_capacity", cap(f.streamQueue),
					"action", "graceful_degradation")
			}
			detector.Close()
			// Return a placeholder stream that reads and discards data
			// This prevents connection errors while gracefully degrading performance
			go func() {
				defer r.Close()
				buf := make([]byte, 1024)
				for {
					select {
					case <-f.ctx.Done():
						return
					default:
						_, err := r.Read(buf)
						if err != nil {
							return
						}
					}
				}
			}()
		}
		return &r
	}

	// We have capacity, process immediately
	stream := &SIPStream{
		reader:         &r,
		callIDDetector: detector,
		ctx:            f.ctx,
		factory:        f,
	}

	// Increment goroutine counter before starting
	atomic.AddInt64(&f.activeGoroutines, 1)
	go stream.run()
	return &r
}

func (f *sipStreamFactory) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	// Wait for the queue worker to finish
	f.queueWorker.Wait()
}

// GetActiveGoroutines returns the current number of active stream processing goroutines
func (f *sipStreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum allowed goroutines
func (f *sipStreamFactory) GetMaxGoroutines() int64 {
	return int64(f.config.MaxGoroutines)
}

type SIPStream struct {
	reader         *tcpreader.ReaderStream
	callIDDetector *CallIDDetector
	ctx            context.Context
	factory        *sipStreamFactory
}

func (s *SIPStream) run() {
	defer func() {
		// Decrement goroutine counter
		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		if r := recover(); r != nil {
			logger.Error("SIP stream panic recovered",
				"panic_value", r,
				"stream_context", s.ctx.Err())
		}
		// Ensure resources are cleaned up
		if s.callIDDetector != nil {
			s.callIDDetector.Close()
		}
	}()

	buf := bufio.NewReader(s.reader)
	for {
		select {
		case <-s.ctx.Done():
			logger.Debug("SIP stream shutting down due to context cancellation")
			return
		default:
			// Continue processing
		}

		line, err := buf.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				logger.Error("Error reading SIP stream", "error", err)
			}
			return
		}

		// Detect SIP header line with robust parsing
		var callID string
		line = strings.TrimSpace(line)

		// Handle both full and compact form headers (case-insensitive)
		if detectCallIDHeader(line, &callID) {
			// Successfully parsed Call-ID
		}

		if callID != "" {
			s.callIDDetector.SetCallID(callID)
			return // done after detecting first Call-ID
		}
	}
}

// detectCallIDHeader robustly parses Call-ID headers in both full and compact form
func detectCallIDHeader(line string, callID *string) bool {
	line = strings.TrimSpace(line)

	// Try full form first (case-insensitive)
	if len(line) > 8 && strings.EqualFold(line[:8], "call-id:") {
		*callID = strings.TrimSpace(line[8:])
		return *callID != ""
	}

	// Try compact form (case-insensitive)
	if len(line) > 2 && strings.EqualFold(line[:2], "i:") {
		*callID = strings.TrimSpace(line[2:])
		return *callID != ""
	}

	return false
}

func handleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort {
		packet := pkt.Packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Use the assembler properly to process the packet
			// The stream factory will handle call ID detection
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				layer,
				packet.Metadata().Timestamp,
			)
		}
	}
}
