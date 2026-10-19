//go:build processor || tap || all

package processor

import learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"

// A relay promises only the formats acknowledged by its complete active route.
// An unavailable or legacy upstream cannot silently receive typed evidence.
func (p *Processor) acceptLearnedEvidenceVersions(offered []uint32) []uint32 {
	accepted := learnedwire.AcceptEvidenceVersions(offered)
	if p.upstreamManager != nil && p.upstreamManager.Configured() && len(p.upstreamManager.LearnedEvidenceVersions()) == 0 {
		return nil
	}
	return accepted
}
