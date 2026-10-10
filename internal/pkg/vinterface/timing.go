package vinterface

import (
	"context"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// TimingReplayer handles packet timing replay for virtual interfaces
// It respects original PCAP timestamps (like tcpreplay) when enabled
type TimingReplayer struct {
	mu             sync.Mutex
	firstTimestamp time.Time
	replayStart    time.Time
	enabled        bool
}

// NewTimingReplayer creates a new timing replayer
func NewTimingReplayer(enabled bool) *TimingReplayer {
	return &TimingReplayer{
		enabled: enabled,
	}
}

// WaitForPacketTime sleeps if needed to match the original packet timing
// pktTimestamp is the timestamp from the PCAP file
func (tr *TimingReplayer) WaitForPacketTime(pktTimestamp time.Time) {
	if err := tr.WaitForPacketTimeContext(context.Background(), pktTimestamp); err != nil {
		logger.Error("Virtual interface replay timing failed", "error", err)
	}
}

// WaitForPacketTimeContext waits for original packet timing, or returns promptly
// when the replay session is cancelled. Callers must serialize packet delivery
// and call Reset between passes after the previous pass has stopped.
func (tr *TimingReplayer) WaitForPacketTimeContext(ctx context.Context, pktTimestamp time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !tr.enabled {
		return nil
	}

	tr.mu.Lock()

	// Initialize timing on first packet
	if tr.firstTimestamp.IsZero() {
		tr.firstTimestamp = pktTimestamp
		tr.replayStart = time.Now()
		tr.mu.Unlock()
		return nil
	}

	// Calculate how much time has elapsed in the PCAP
	pcapElapsed := pktTimestamp.Sub(tr.firstTimestamp)
	// Calculate how much real time has elapsed
	realElapsed := time.Since(tr.replayStart)
	tr.mu.Unlock()

	// Sleep if we're ahead of the PCAP timing
	if pcapElapsed > realElapsed {
		sleepDuration := pcapElapsed - realElapsed
		// Sanity check: don't sleep for more than 10 seconds
		// (protects against corrupted timestamps)
		if sleepDuration > 0 && sleepDuration < 10*time.Second {
			timer := time.NewTimer(sleepDuration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return ctx.Err()
}

// Reset resets the timing state (useful for starting a new capture)
func (tr *TimingReplayer) Reset() {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.firstTimestamp = time.Time{}
	tr.replayStart = time.Time{}
}
