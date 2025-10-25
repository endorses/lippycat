package vinterface

import (
	"sync"
	"time"
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
	if !tr.enabled {
		return
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Initialize timing on first packet
	if tr.firstTimestamp.IsZero() {
		tr.firstTimestamp = pktTimestamp
		tr.replayStart = time.Now()
		return
	}

	// Calculate how much time has elapsed in the PCAP
	pcapElapsed := pktTimestamp.Sub(tr.firstTimestamp)
	// Calculate how much real time has elapsed
	realElapsed := time.Since(tr.replayStart)

	// Sleep if we're ahead of the PCAP timing
	if pcapElapsed > realElapsed {
		sleepDuration := pcapElapsed - realElapsed
		// Sanity check: don't sleep for more than 10 seconds
		// (protects against corrupted timestamps)
		if sleepDuration > 0 && sleepDuration < 10*time.Second {
			time.Sleep(sleepDuration)
		}
	}
}

// Reset resets the timing state (useful for starting a new capture)
func (tr *TimingReplayer) Reset() {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.firstTimestamp = time.Time{}
	tr.replayStart = time.Time{}
}
