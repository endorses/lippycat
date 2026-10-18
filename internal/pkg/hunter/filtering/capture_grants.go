//go:build hunter || all

package filtering

import (
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capturegrant"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"google.golang.org/protobuf/proto"
)

// CaptureMediaRuleAllowed validates signed media authority separately from
// matching filters. Its capture time cannot renew the current live lease.
func (m *Manager) CaptureMediaRuleAllowed(rule *management.MediaRule, packet gopacket.Packet, domain uint32, capturedAt time.Time) bool {
	if m.sharedPolicy == nil || !m.CaptureAllowed(time.Now()) || m.sharedPolicy.state.Verifier().VerifyMediaRule(rule) != nil {
		return false
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	defer lease.mu.Unlock()

	now := time.Now()
	if lease.snapshot == nil || lease.fault {
		return false
	}
	wall := now.UnixNano()
	if wall < lease.lastWall {
		lease.fault = true
		return false
	}
	lease.lastWall = wall
	if now.UnixNano() < lease.snapshot.ValidFromNs || now.UnixNano() >= lease.snapshot.ValidUntilNs || !now.Before(lease.deadline) || (!lease.connected && !lease.snapshot.AllowOfflineCapture) {
		return false
	}
	return !lease.fault && capturegrant.ValidateRule(lease.snapshot, rule, m.hunterID, domain, packet, capturedAt) == nil
}

// CaptureSelectionProofAllowed validates immutable proof at the producer
// boundary against the installed revision and original packet capture time.
func (m *Manager) CaptureSelectionProofAllowed(envelope *pipeline.PacketEnvelope) bool {
	if envelope == nil || !envelope.Source.ObservationDomainKnown || len(envelope.CaptureSelectionProof) == 0 || len(envelope.CaptureSelectionProof) > filterpolicy.MaxMediaRuleBytes {
		return false
	}
	rule := &management.MediaRule{}
	if proto.Unmarshal(envelope.CaptureSelectionProof, rule) != nil || !m.CaptureMediaRuleAllowed(rule, envelope.Packet(), envelope.Source.ObservationDomain, envelope.CaptureTime) {
		return false
	}
	expected := make(map[string]bool)
	for _, ref := range rule.Call.SelectionGrants {
		expected[ref.Id] = true
	}
	for _, id := range rule.Call.FilterIds {
		expected[id] = true
	}
	if len(envelope.DirectMatchedFilterIDs) != 0 || len(envelope.InheritedMatchedFilterIDs) != len(expected) || len(envelope.MatchedFilterIDs) != len(expected) {
		return false
	}
	for _, ids := range [][]string{envelope.InheritedMatchedFilterIDs, envelope.MatchedFilterIDs} {
		seen := make(map[string]bool, len(ids))
		for _, id := range ids {
			if !expected[id] || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}

// sharedSelectionSnapshotRequired keeps grants on their signed producer boundary
// through all subsequent replacements, including grant-free legacy snapshots.
// Ordinary shared capture that has never installed grants keeps its existing
// unleased matcher startup and event-policy behavior.
func (m *Manager) sharedSelectionSnapshotRequired(snapshot *management.PolicySnapshot) bool {
	if len(snapshot.SelectionGrants) > 0 {
		return true
	}
	lease := &m.sharedPolicy.lease
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.snapshot != nil
}
