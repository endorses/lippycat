//go:build hunter || tap || all

package hunter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSelectionProofTracksSemanticDefinition(t *testing.T) {
	af, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	packet := mediaScopePacket(t, false, rtpPayloadContainingSIPIdentity())
	filters := []*management.Filter{{Id: "selected", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.10", Enabled: true, Revision: 1}, {Id: "other", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true}}
	af.UpdateFilters(filters)
	matched, ids, proof := af.MatchPacketWithSelectionProof(packet)
	require.True(t, matched)
	require.Contains(t, ids, "selected")
	filters[0].Revision = 2
	filters[0].Description = "renewed lease"
	filters[1].Pattern = "bob"
	af.UpdateFilters(filters)
	valid, currentIDs := af.CurrentSelection(proof)
	require.True(t, valid)
	require.Equal(t, []string{"selected"}, currentIDs)
	filters[0].Pattern = "203.0.113.99"
	af.UpdateFilters(filters)
	valid, _ = af.CurrentSelection(proof)
	require.False(t, valid, "same ID cannot retain prior pattern authority")
	af.UpdateFilters(nil)
	_, _, global := af.MatchPacketWithSelectionProof(packet)
	valid, _ = af.CurrentSelection(global)
	require.True(t, valid)
	af.UpdateFilters(filters)
	valid, _ = af.CurrentSelection(global)
	require.False(t, valid, "old unfiltered selection cannot survive enabling filters")
}
