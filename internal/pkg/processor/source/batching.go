package source

import (
	"bytes"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// appendEnvelopeDirect linearizes every local packet path with capture-policy grouping.
// Empty policy is a distinct ordinary group; it cannot inherit a neighboring
// learned packet's signed capture snapshot.
func (s *LocalSource) appendEnvelopeDirect(envelope *pipeline.PacketEnvelope, policy []byte, after func(), check func(*pipeline.PacketEnvelope) bool) {
	s.stats.AddForwarded(uint64(len(envelope.Data)))
	s.policyBatchMu.Lock()
	defer s.policyBatchMu.Unlock()
	s.batchMu.Lock()
	changed := len(s.currentBatch) > 0 && !bytes.Equal(s.currentBatchSignedCapturePolicy, policy)
	s.batchMu.Unlock()
	if changed {
		s.sendBatch()
	}
	s.batchMu.Lock()
	s.currentBatchSignedCapturePolicy = append([]byte(nil), policy...)
	s.currentBatch = append(s.currentBatch, envelope)
	if check != nil {
		if s.currentBatchPolicyChecks == nil {
			s.currentBatchPolicyChecks = make(map[*pipeline.PacketEnvelope]func(*pipeline.PacketEnvelope) bool)
		}
		s.currentBatchPolicyChecks[envelope] = check
	}
	if after != nil {
		s.currentBatchAfterProcess = append(s.currentBatchAfterProcess, after)
	}
	count := len(s.currentBatch)
	s.batchMu.Unlock()
	if count >= s.config.BatchSize {
		s.sendBatch()
	}
}
