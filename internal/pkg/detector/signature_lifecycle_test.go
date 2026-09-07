package detector

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/stretchr/testify/require"
)

type maintenanceSignature struct {
	signatures.Signature
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (s *maintenanceSignature) SweepSIPIPPairs() int {
	if s.calls.Add(1) == 1 {
		close(s.started)
	}
	<-s.release
	return 0
}

func (s *maintenanceSignature) SIPIPPairStats() map[string]interface{} {
	return map[string]interface{}{
		"entries":       7,
		"max_entries":   100,
		"ttl_evictions": uint64(2),
		"cap_evictions": uint64(3),
	}
}

func TestSignatureMaintenanceLifecycle(t *testing.T) {
	d := New()
	sig := &maintenanceSignature{
		Signature: voip.NewSIPSignature(),
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(sig.release) }) }
	t.Cleanup(func() {
		release()
		d.Shutdown()
	})
	d.RegisterSignature(sig)

	// No packet processing or pair lookup is needed to trigger maintenance.
	select {
	case <-sig.started:
	case <-time.After(5 * signatureCleanupInterval):
		t.Fatal("registered signature was not swept")
	}

	// An in-progress sweep must finish before any shutdown caller returns.
	var shutdowns sync.WaitGroup
	shutdowns.Add(2)
	done := make(chan struct{})
	for range 2 {
		go func() {
			defer shutdowns.Done()
			d.Shutdown()
		}()
	}
	go func() {
		shutdowns.Wait()
		close(done)
	}()
	select {
	case <-d.cleanupStop:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not signal maintenance to stop")
	}
	select {
	case <-done:
		t.Fatal("shutdown returned while signature maintenance was running")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after signature maintenance completed")
	}
	d.Shutdown()
	require.Equal(t, int32(1), sig.calls.Load())
}

func TestGetStatsIncludesSIPIPPairs(t *testing.T) {
	d := New()
	t.Cleanup(d.Shutdown)
	require.NotContains(t, d.GetStats(), "sip_ip_pairs")
	sig := &maintenanceSignature{Signature: voip.NewSIPSignature()}
	// This test only exercises telemetry; any background sweep may finish freely.
	sig.started = make(chan struct{})
	sig.release = make(chan struct{})
	close(sig.release)
	d.RegisterSignature(sig)
	require.Equal(t, sig.SIPIPPairStats(), d.GetStats()["sip_ip_pairs"])
}
