//go:build linux

package admissionintegration

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/endorses/lippycat/internal/pkg/capture/ebpfadmission"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"golang.org/x/sys/unix"
)

func (s *Session) initTelemetry(ctx context.Context, backend *ebpfadmission.Backend) error {
	telemetry := &sessionTelemetry{counters: backend.Counters, diagnostics: mediaadmission.NewDiagnostics(s.Config.OwnerCapacity, s.Config.MissingMediaInterval), last: make(map[mediaadmission.DomainID]mediaadmission.State)}
	telemetry.evidence.Capacity = s.Config.ShadowEvidenceCapacity
	s.telemetry = telemetry
	if s.Config.Mode != mediaadmission.ModeShadow {
		return nil
	}
	reader, err := backend.DecisionReader()
	if err != nil {
		return err
	}
	telemetry.done = make(chan struct{})
	var once sync.Once
	var closeErr error
	telemetry.stop = func() error { once.Do(func() { closeErr = reader.Close() }); return closeErr }
	go func() {
		select {
		case <-ctx.Done():
			if err := telemetry.stop(); err != nil {
				logger.Error("Failed to close admission evidence reader", "error", err)
			}
		case <-telemetry.done:
		}
	}()
	go func() {
		defer close(telemetry.done)
		for {
			record, err := reader.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					telemetry.mu.Lock()
					telemetry.evidence.ReadErrors++
					telemetry.evidence.Incomplete = true
					telemetry.mu.Unlock()
				}
				return
			}
			decision, err := ebpfadmission.DecodeDecision(record.RawSample)
			telemetry.mu.Lock()
			if err != nil {
				telemetry.evidence.Malformed++
				telemetry.evidence.Incomplete = true
				telemetry.mu.Unlock()
				continue
			}
			var monotonic unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
				telemetry.evidence.Incomplete = true
			}
			sample := mediaadmission.ShadowSample{Domain: decision.Domain, Generation: decision.Generation, EventMonotonicNS: decision.TimeNS, ObservedMonotonicNS: uint64(monotonic.Nano()), ObservedAt: time.Now(), Reason: decision.Reason, Length: decision.Length, Fingerprint: decision.Fingerprint, Source: decision.Source, Destination: decision.Destination}
			telemetry.evidence.Received++
			if len(telemetry.samples) < s.Config.ShadowEvidenceCapacity {
				telemetry.samples = append(telemetry.samples, sample)
			} else {
				telemetry.samples[telemetry.next] = sample
				telemetry.next = (telemetry.next + 1) % len(telemetry.samples)
				telemetry.evidence.Overwritten++
				telemetry.evidence.Incomplete = true
			}
			telemetry.evidence.Retained = len(telemetry.samples)
			telemetry.mu.Unlock()
		}
	}()
	return nil
}
