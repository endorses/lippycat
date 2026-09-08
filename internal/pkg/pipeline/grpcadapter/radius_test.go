package grpcadapter

import (
	"io"
	"os"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func radiusFixture(t *testing.T) *radius.Observation {
	t.Helper()
	f, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	b, ci, err := r.ReadPacketData()
	require.NoError(t, err)
	scope := radius.CaptureScope{OriginNodeID: "hunter-a", SourceID: "eth0", Epoch: [16]byte{1}, OperatorScope: "operator-a", ProfileRevision: "v1"}
	o, _, err := radius.DecodePacket(b, r.LinkType(), ci, scope, radius.Identity{Epoch: scope.Epoch, Sequence: 1})
	require.NoError(t, err)
	return o
}
func radiusPacket(o *radius.Observation) *data.CapturedPacket {
	return &data.CapturedPacket{Data: append([]byte(nil), o.Packet...), TimestampNs: o.Capture.Timestamp.UnixNano(), CaptureLength: uint32(o.Capture.CapturedLength), OriginalLength: uint32(o.Capture.OriginalLength), LinkType: uint32(o.Capture.LinkType), InterfaceName: o.Scope.SourceID, Radius: RADIUSToProto(o)}
}

func TestRADIUSWireRoundTripAndRelayOwnership(t *testing.T) {
	o := radiusFixture(t)
	p := radiusPacket(o)
	wire, err := proto.Marshal(p)
	require.NoError(t, err)
	received := &data.CapturedPacket{}
	require.NoError(t, proto.Unmarshal(wire, received))
	e, err := FromCapturedPacket(received, pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: "relay-b"})
	require.NoError(t, err)
	require.NoError(t, e.RADIUSValidationError)
	require.Equal(t, o, e.RADIUS)
	// A relay's own transport identity must never rewrite the capture origin.
	out, err := ToCapturedPacket(e)
	require.NoError(t, err)
	require.True(t, proto.Equal(p, out))
	received.Data[0] ^= 255
	received.Radius.Message[0] ^= 255
	require.Equal(t, o.Packet, e.Data)
	require.Equal(t, o.Message.Raw, e.RADIUS.Message.Raw)
	out.Radius.Scope.Epoch[0] = 2
	require.Equal(t, byte(1), e.RADIUS.Scope.Epoch[0])
}
func TestRADIUSInvalidClaimsRetainRawPacket(t *testing.T) {
	original := radiusPacket(radiusFixture(t))
	tests := map[string]func(*data.CapturedPacket){
		"message":       func(p *data.CapturedPacket) { p.Radius.Message[1] ^= 1 },
		"epoch":         func(p *data.CapturedPacket) { p.Radius.Scope.Epoch = []byte{1} },
		"identity":      func(p *data.CapturedPacket) { p.Radius.ObservationId.Sequence = 0 },
		"truncation":    func(p *data.CapturedPacket) { p.OriginalLength++ },
		"link":          func(p *data.CapturedPacket) { p.LinkType = 65537 },
		"version":       func(p *data.CapturedPacket) { p.Radius.Version = 2 },
		"request claim": func(p *data.CapturedPacket) { p.Radius.AssociationStatus = "unique" },
		"direct forged": func(p *data.CapturedPacket) {
			p.Radius.Direct = []*data.RADIUSAttribution{{CriterionGroupId: "g", Scope: proto.Clone(p.Radius.Scope).(*data.RADIUSScope), Criteria: []*data.RADIUSCriterion{{FilterId: "f", FilterRevision: 1, AttributeType: 1, TargetKind: "account", Value: []byte("not-present")}}}}
		},
		"inherited orphan": func(p *data.CapturedPacket) { p.Radius.Inherited = []*data.RADIUSAttribution{{CriterionGroupId: "g"}} },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p := proto.Clone(original).(*data.CapturedPacket)
			change(p)
			p.MatchedFilterIds = []string{"li-task"}
			p.DirectMatchedFilterIds = []string{"li-task"}
			p.InheritedMatchedFilterIds = []string{"li-task"}
			e, err := FromCapturedPacket(p, pipeline.SourceProvenance{})
			require.NoError(t, err)
			require.Error(t, e.RADIUSValidationError)
			require.Nil(t, e.RADIUS)
			require.Equal(t, p.Data, e.Data)
			raw, err := ToCapturedPacket(e)
			require.NoError(t, err)
			require.Nil(t, raw.Radius)
			require.Empty(t, raw.MatchedFilterIds)
			require.Empty(t, raw.DirectMatchedFilterIds)
			require.Empty(t, raw.InheritedMatchedFilterIds)
			require.Equal(t, p.Data, raw.Data)
		})
	}
}
func TestRADIUSFixtureTransportAllValidMessages(t *testing.T) {
	f, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	count := 0
	for {
		b, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		scope := radius.CaptureScope{OriginNodeID: "hunter", SourceID: "eth0", Epoch: [16]byte{1}}
		o, _, err := radius.DecodePacket(b, r.LinkType(), ci, scope, radius.Identity{Epoch: scope.Epoch, Sequence: uint64(count + 1)}, 19120)
		if err != nil {
			continue
		}
		count++
		out, err := RADIUSFromProto(radiusPacket(o))
		require.NoError(t, err)
		require.Equal(t, o, out)
	}
	require.GreaterOrEqual(t, count, 18)
}

func TestRADIUSGroupedEvidenceRoundTrip(t *testing.T) {
	o := radiusFixture(t)
	for _, spec := range []radius.PredicateSpec{
		{Kind: radius.PredicateUserName, Value: "alice@example.test", FilterID: "account", FilterRevision: 3},
		{Kind: radius.PredicateMAC, Value: "02-00-00-00-00-01", MACProfile: radius.MACProfileUppercaseHyphen, FilterID: "mac", FilterRevision: 4},
	} {
		p, err := radius.CompilePredicate(spec)
		require.NoError(t, err)
		ref, matched, err := p.Reference(o)
		require.NoError(t, err)
		require.True(t, matched)
		o.Direct = append(o.Direct, ref)
	}
	o.Association = radius.Association{Status: radius.AssociationRequest, RequestInstanceID: o.Capture.ID, RequestObservationID: o.Capture.ID, RequestFirstSeen: o.Capture.Timestamp}
	received, err := RADIUSFromProto(radiusPacket(o))
	require.NoError(t, err)
	require.Equal(t, o, received)
	received.Direct[0].Criteria[0].Value[0] = 'z'
	require.Equal(t, byte('a'), o.Direct[0].Criteria[0].Value[0])
}

func TestRADIUSIdentityFreeResponseInheritanceTransport(t *testing.T) {
	request := radiusFixture(t)
	predicate, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateUserName, Value: "alice@example.test", FilterID: "user", FilterRevision: 9})
	require.NoError(t, err)
	ref, matched, err := predicate.Reference(request)
	require.NoError(t, err)
	require.True(t, matched)
	f, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	_, _, err = r.ReadPacketData()
	require.NoError(t, err)
	b, ci, err := r.ReadPacketData()
	require.NoError(t, err)
	response, _, err := radius.DecodePacket(b, r.LinkType(), ci, request.Scope, radius.Identity{Epoch: request.Scope.Epoch, Sequence: 2})
	require.NoError(t, err)
	require.Empty(t, response.Message.Attributes)
	response.Association = radius.Association{Status: radius.AssociationUnique, RequestInstanceID: request.Capture.ID, RequestObservationID: request.Capture.ID, RequestFirstSeen: request.Capture.Timestamp}
	response.Inherited = []radius.AttributionReference{ref}
	received, err := RADIUSFromProto(radiusPacket(response))
	require.NoError(t, err)
	require.Equal(t, response, received)
	// Flattened filter IDs cannot invent an observation or association on old peers.
	legacy := radiusPacket(response)
	legacy.Radius = nil
	legacy.MatchedFilterIds = []string{"user"}
	received, err = RADIUSFromProto(legacy)
	require.NoError(t, err)
	require.Nil(t, received)
}

func TestRADIUSEnvelopeCaptureMismatchRejected(t *testing.T) {
	p := radiusPacket(radiusFixture(t))
	e, err := FromCapturedPacket(p, pipeline.SourceProvenance{})
	require.NoError(t, err)
	e.CaptureTime = e.CaptureTime.Add(1)
	_, err = ToCapturedPacket(e)
	require.ErrorContains(t, err, "capture metadata differs")
}
