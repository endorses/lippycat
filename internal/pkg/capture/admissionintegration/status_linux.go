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
)

func (s *Session) initTelemetry(ctx context.Context, backend *ebpfadmission.Backend) error {
	telemetry := &sessionTelemetry{counters: backend.Counters, diagnostics: mediaadmission.NewDiagnostics(s.Config.OwnerCapacity, s.Config.MissingMediaInterval), last: make(map[mediaadmission.DomainID]mediaadmission.State)}
	telemetry.evidence.Capacity = s.Config.ShadowEvidenceCapacity
	telemetry.clockErrorsBaseline = monotonicReadErrors()
	telemetry.evidence.SampleEvery = s.Config.ShadowSampleEvery
	s.telemetry = telemetry
	if s.Config.Mode != mediaadmission.ModeShadow {
		return nil
	}
	telemetry.correlator = mediaadmission.NewSampledShadowCorrelator(s.Config.ShadowEvidenceCapacity, s.Config.OwnerCapacity, uint64(s.Config.PendingTTL), s.Config.ShadowSampleEvery)
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
					telemetry.correlator.EvidenceLost(monotonicNow())
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
				telemetry.correlator.EvidenceLost(monotonicNow())
				telemetry.evidence.Malformed++
				telemetry.evidence.Incomplete = true
				telemetry.mu.Unlock()
				continue
			}
			monotonic := monotonicNow()
			if monotonic == 0 {
				telemetry.evidence.Incomplete = true
			}
			sample := mediaadmission.ShadowSample{Domain: decision.Domain, Generation: decision.Generation, EventMonotonicNS: decision.TimeNS, ObservedMonotonicNS: monotonic, ObservedAt: time.Now(), Reason: decision.Reason, Length: decision.Length, Fingerprint: decision.Fingerprint, Source: decision.Source, Destination: decision.Destination, IdentityLength: decision.IdentityLength, Identity: decision.Identity, SampleEvery: decision.SampleEvery}
			telemetry.correlator.Sample(sample, sample.ObservedMonotonicNS)
			// Retained diagnostic samples contain no frame bytes. The bounded
			// correlator exclusively owns full identity until its expiry.
			sample.IdentityLength = 0
			sample.Identity = [256]byte{}
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
