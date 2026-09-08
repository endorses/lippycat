package radius

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Exercise the independent committed wire fixtures through both Phase 2 components.
func TestPhase2AcceptanceFixtures(t *testing.T) {
	root := "../../../testdata/radius"
	manifest, err := os.ReadFile(filepath.Join(root, "expected.json"))
	require.NoError(t, err)
	var expected struct {
		Observations []struct {
			Name, Outcome, Association, Operator string
			CaptureScope                         string `json:"capture_scope"`
			AssociatedRequest                    string `json:"associated_request"`
			NASLine                              bool   `json:"matches_operator_a_nas_line"`
			CircuitLine                          bool   `json:"matches_operator_a_circuit_line"`
		}
	}
	require.NoError(t, json.Unmarshal(manifest, &expected))
	f, err := os.Open(filepath.Join(root, "acceptance.pcap"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	var now time.Time
	c, err := NewCorrelator(CorrelatorConfig{EvidenceCurrent: func(AttributionReference) bool { return true }, Now: func() time.Time { return now }})
	require.NoError(t, err)
	t.Cleanup(c.Close)
	groups := make([]*Group, 2)
	for i, target := range []string{"57086C696E652D61", "1A1100000DE9010B636972637569742D61"} {
		groups[i], err = CompileGroup(GroupSpec{ID: target, Scope: ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "v1"}, Criteria: []PredicateSpec{{Kind: PredicateAttribute, Value: target, FilterID: target, FilterRevision: 1}}})
		require.NoError(t, err)
	}
	ids := map[string]Identity{}
	refs := map[string][]AttributionReference{}
	for index, want := range expected.Observations {
		frame, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		// Existing peers can forward bytes without any RADIUS metadata or evidence,
		// including rejected fragments and malformed protocol payloads.
		packet := &data.CapturedPacket{Data: frame, TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(reader.LinkType())}
		wire, wireErr := proto.Marshal(packet)
		require.NoError(t, wireErr)
		var transported data.CapturedPacket
		require.NoError(t, proto.Unmarshal(wire, &transported))
		require.True(t, proto.Equal(packet, &transported))
		require.Empty(t, transported.MatchedFilterIds)
		now = ci.Timestamp
		epoch := [16]byte{1}
		if want.CaptureScope == "poi-b" {
			epoch[0] = 2
		}
		scope := CaptureScope{OriginNodeID: want.CaptureScope, SourceID: "fixture", Epoch: epoch, OperatorScope: want.Operator, ProfileRevision: "v1"}
		o, outcome, err := DecodePacket(frame, reader.LinkType(), ci, scope, Identity{Epoch: epoch, Sequence: uint64(index + 1)}, 19120)
		if outcome != OutcomeValid {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		t.Run(want.Name, func(t *testing.T) {
			for i, g := range groups {
				ref, match, err := g.Match(o)
				require.NoError(t, err)
				require.Equal(t, []bool{want.NASLine, want.CircuitLine}[i], match)
				if match {
					o.Direct = append(o.Direct, ref)
				}
			}
			result := c.Process(o)
			require.Equal(t, want.Association, string(result.Association.Status))
			if want.Association == "request" {
				ids[want.Name] = result.Association.RequestInstanceID
				refs[want.Name] = result.Direct
			}
			if want.AssociatedRequest != "" {
				require.Equal(t, ids[want.AssociatedRequest], result.Association.RequestInstanceID)
				require.Equal(t, refs[want.AssociatedRequest], result.Inherited)
			}
			require.Equal(t, o.Packet, result.Packet)
			require.Equal(t, o.Message.Raw, result.Message.Raw)
		})
	}
}
