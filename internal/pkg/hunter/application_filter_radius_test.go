//go:build hunter || tap || all

package hunter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestApplicationRADIUSMatchesAndRetainsOrdinaryEvidence(t *testing.T) {
	af, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	af.UpdateFilters([]*management.Filter{{Id: "user", Revision: 1, Enabled: true, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "Alice@Realm"}})
	raw := make([]byte, 20)
	raw[0] = 1
	raw = append(raw, 1, 13)
	raw = append(raw, []byte("Alice@Realm")...)
	raw[3] = byte(len(raw))
	message, err := radius.Decode(raw)
	require.NoError(t, err)
	epoch := [16]byte{1}
	o := &radius.Observation{Message: message, Scope: radius.CaptureScope{OriginNodeID: "hunter", SourceID: "eth0", Epoch: epoch, OperatorScope: "operator", ProfileRevision: "v1"}, Capture: radius.CaptureInfo{ID: radius.Identity{Epoch: epoch, Sequence: 1}}}
	matched, ids, refs := af.MatchRADIUSObservation(o)
	require.True(t, matched)
	require.Equal(t, []string{"user"}, ids)
	require.Len(t, refs, 1)
	require.Empty(t, refs[0].TaskID)
	o.Message.Raw[len(raw)-1] = 'm' - 1
	matched, _, _ = af.MatchRADIUSObservation(o)
	require.False(t, matched)
	// Missing or invalid RADIUS criteria never fall through the no-filter allow policy.
	af.UpdateFilters([]*management.Filter{{Id: "invalid", Enabled: true, Type: management.FilterType_FILTER_RADIUS_MAC, Pattern: "malformed"}})
	packet := gopacket.NewPacket([]byte{0}, layers.LayerTypeEthernet, gopacket.Default)
	require.False(t, af.MatchPacket(packet))
	require.Equal(t, []bool{false}, af.MatchBatch([]gopacket.Packet{packet}))
}

func TestRADIUSEvidenceCurrentRejectsRevisionAndRemoval(t *testing.T) {
	af, err := NewApplicationFilter(nil)
	require.NoError(t, err)
	defer af.Close()
	filter := &management.Filter{Id: "user", Revision: 1, Enabled: true, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice"}
	af.UpdateFilters([]*management.Filter{filter})
	raw := make([]byte, 20)
	raw[0] = 1
	raw = append(raw, 1, 7)
	raw = append(raw, []byte("alice")...)
	raw[3] = byte(len(raw))
	message, err := radius.Decode(raw)
	require.NoError(t, err)
	epoch := [16]byte{1}
	observation := &radius.Observation{Message: message, Scope: radius.CaptureScope{OriginNodeID: "hunter", SourceID: "eth0", Epoch: epoch, OperatorScope: "local", ProfileRevision: "unconfigured"}, Capture: radius.CaptureInfo{ID: radius.Identity{Epoch: epoch, Sequence: 1}}}
	_, _, refs := af.MatchRADIUSObservation(observation)
	require.Len(t, refs, 1)
	require.True(t, af.RADIUSEvidenceCurrent(refs[0]))
	forged := observation.Clone()
	forged.Direct = refs
	forged = forged.Clone()
	forged.Direct[0].Criteria[0].Value[0] = 'b'
	require.False(t, af.RADIUSEvidenceCurrent(forged.Direct[0]))
	filter.Revision = 2
	af.UpdateFilters([]*management.Filter{filter})
	require.False(t, af.RADIUSEvidenceCurrent(refs[0]))
	_, _, current := af.MatchRADIUSObservation(observation)
	require.True(t, af.RADIUSEvidenceCurrent(current[0]))
	af.UpdateFilters(nil)
	require.False(t, af.RADIUSEvidenceCurrent(current[0]))
}
