package admission

import (
	"encoding/binary"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

type sampledAttributionRecorder struct {
	*diagnosticRecorder
	correlator            *mediaadmission.ShadowCorrelator
	mediaLost, packetLost uint64
}

func (r *sampledAttributionRecorder) ShadowFrameEligible(domain mediaadmission.DomainID, frame []byte) bool {
	return r.correlator.FrameEligible(domain, frame)
}
func (r *sampledAttributionRecorder) RecordMediaAttributionUnavailable() { r.mediaLost++ }
func (r *sampledAttributionRecorder) RecordAttributionUnavailable() {
	r.packetLost++
	r.correlator.EvidenceLost(48)
}
func (r *sampledAttributionRecorder) RecordAttributedPacket(owner mediaadmission.OwnerID, domain mediaadmission.DomainID, frame []byte) {
	r.correlator.Attributed(owner, domain, frame, 47)
}

func TestBridgeSamplingGuardSeparatesMediaPressureFromEligiblePacketLoss(t *testing.T) {
	for _, eligiblePressure := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsampled", true: "eligible"}[eligiblePressure], func(t *testing.T) {
			bridge, registry, _ := fixture(t)
			message := offer("sampling-pressure")
			registry.Upsert(callregistry.Call{CallID: message.CallID})
			check(t, selectedReceiptFixture(bridge, message))
			call, exists := registry.Call(message.CallID)
			require.True(t, exists)
			owner := bridge.selected[message.CallID].owner
			c := mediaadmission.NewSampledShadowCorrelator(2, 1, 100, 7)
			c.Selection(owner, 0, 20)
			c.Expectation(owner, 0, true, true, 1, 30, 3)
			frame, background := make([]byte, 64), make([]byte, 64)
			found := false
			for i := uint32(0); i < 1000; i++ {
				binary.LittleEndian.PutUint32(frame[60:], i)
				if c.FrameEligible(0, frame) {
					found = true
					break
				}
			}
			require.True(t, found)
			found = false
			for i := uint32(0); i < 1000; i++ {
				binary.LittleEndian.PutUint32(background[60:], i)
				if !c.FrameEligible(0, background) {
					found = true
					break
				}
			}
			require.True(t, found)
			sample := mediaadmission.ShadowSample{Domain: 0, Generation: 3, EventMonotonicNS: 40, Length: 64, IdentityLength: 64, SampleEvery: 7, Reason: 1}
			copy(sample.Identity[:], frame)
			c.Sample(sample, 45)
			c.Observed(0, frame, 46)
			r := &sampledAttributionRecorder{diagnosticRecorder: &diagnosticRecorder{selections: make(map[mediaadmission.OwnerID]recordedSelection)}, correlator: c}
			bridge.cfg.Diagnostics = r
			bridge.RecordAttributedPacket(message.CallID, call.Lifetime, frame)
			// A bridge lock miss on unsampled aggregate media accounting and on
			// an unsampled frame cannot invalidate an otherwise unique tuple.
			bridge.mu.Lock()
			bridge.RecordAttributedMedia(message.CallID, call.Lifetime)
			bridge.RecordAttributedPacket(message.CallID, call.Lifetime, background)
			if eligiblePressure {
				bridge.RecordAttributedPacket(message.CallID, call.Lifetime, frame)
			}
			bridge.mu.Unlock()
			c.Advance(300)
			require.Equal(t, uint64(1), r.mediaLost)
			if eligiblePressure {
				require.Equal(t, uint64(1), r.packetLost)
				require.Equal(t, uint64(1), c.Snapshot().Incomplete)
				require.Zero(t, c.Snapshot().Admitted)
			} else {
				require.Zero(t, r.packetLost)
				require.Zero(t, c.Snapshot().Incomplete)
				require.Equal(t, uint64(1), c.Snapshot().Admitted)
			}
		})
	}
}
