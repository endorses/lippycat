package capturepolicy

import (
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
	"testing"
)

type proofMatcherFixture struct{ current FilterSelectionProof }

func (proofMatcherFixture) MatchPacketWithSelectionProof(gopacket.Packet) (bool, []string, FilterSelectionProof) {
	return false, nil, nil
}
func (m proofMatcherFixture) CurrentSelection(proof FilterSelectionProof) (bool, []string) {
	var ids []string
	for id, fingerprint := range proof {
		if current, ok := m.current[id]; ok && current == fingerprint {
			ids = append(ids, id)
		}
	}
	return len(ids) > 0, ids
}
func TestMergeCurrentProofsRetiresRemovedDefinitions(t *testing.T) {
	matcher := proofMatcherFixture{current: FilterSelectionProof{"unchanged": {1}, "replaced": {2}}}
	prior := FilterSelectionProof{"unchanged": {1}, "replaced": {1}, "removed": {1}}
	merged := MergeCurrentProofs(matcher, prior, FilterSelectionProof{"replaced": {2}})
	require.Equal(t, FilterSelectionProof{"unchanged": {1}, "replaced": {2}}, merged)
	require.Len(t, prior, 3, "stored snapshots remain immutable")
}
