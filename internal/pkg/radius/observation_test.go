package radius

import (
	"math"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestIdentityConcurrentAndExhausted(t *testing.T) {
	var uninitialized IDGenerator
	missingID, missingErr := uninitialized.Next()
	require.ErrorIs(t, missingErr, ErrCaptureEpochMissing)
	require.Zero(t, missingID)
	g, err := NewIDGenerator()
	require.NoError(t, err)
	other, err := NewIDGenerator()
	require.NoError(t, err)
	require.NotEqual(t, g.Epoch(), other.Epoch())
	const count = 1000
	ids := make(chan Identity, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := g.Next()
			if err != nil {
				t.Errorf("allocate: %v", err)
				return
			}
			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	seen := make(map[Identity]bool)
	for id := range ids {
		require.Equal(t, g.Epoch(), id.Epoch)
		require.NotZero(t, id.Sequence)
		require.False(t, seen[id])
		seen[id] = true
	}
	require.Len(t, seen, count)
	g.sequence = math.MaxUint64 - 1
	id, err := g.Next()
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxUint64), id.Sequence)
	for range 2 {
		id, err = g.Next()
		require.ErrorIs(t, err, ErrIdentityExhausted)
		require.Zero(t, id)
	}
}

func TestObservationCloneOwnsEveryMutableField(t *testing.T) {
	refs := []AttributionReference{{CriterionGroupID: "and-group", TaskID: "task-a", TaskGeneration: 3,
		Criteria: []CriterionReference{{TargetKind: "line", FilterID: "f", FilterRevision: 2, Value: []byte("value")}}}}
	o := &Observation{
		Packet: []byte("packet"),
		Message: &Message{Raw: []byte("message"), Attributes: []Attribute{{Raw: []byte("avp"), Value: []byte("value"),
			VendorAttributes: []VendorAttribute{{Raw: []byte("subavp"), Value: []byte("subvalue")}}}}},
		NAS: NASIdentity{IPv4: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, IPv6: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			Identifiers: [][]byte{[]byte("nas")}, PortIDs: [][]byte{[]byte("line")}, AgentCircuitIDs: [][]byte{[]byte("circuit")}},
		Direct: refs, Inherited: cloneReferences(refs),
	}
	cloned := o.Clone()
	require.Equal(t, o, cloned)
	cloned.Packet[0] = '!'
	cloned.Message.Raw[0] = '!'
	cloned.Message.Attributes[0].Raw[0] = '!'
	cloned.Message.Attributes[0].Value[0] = '!'
	cloned.Message.Attributes[0].VendorAttributes[0].Raw[0] = '!'
	cloned.Message.Attributes[0].VendorAttributes[0].Value[0] = '!'
	cloned.NAS.IPv4[0] = netip.Addr{}
	cloned.NAS.IPv6[0] = netip.Addr{}
	cloned.NAS.Identifiers[0][0] = '!'
	cloned.NAS.PortIDs[0][0] = '!'
	cloned.NAS.AgentCircuitIDs[0][0] = '!'
	cloned.Direct[0].TaskGeneration = 99
	cloned.Direct[0].Criteria[0].Value[0] = '!'
	cloned.Inherited[0].Criteria[0].Value[0] = '!'
	require.Equal(t, "packet", string(o.Packet))
	require.Equal(t, "message", string(o.Message.Raw))
	require.Equal(t, "avp", string(o.Message.Attributes[0].Raw))
	require.Equal(t, "value", string(o.Message.Attributes[0].Value))
	require.Equal(t, "subavp", string(o.Message.Attributes[0].VendorAttributes[0].Raw))
	require.Equal(t, "subvalue", string(o.Message.Attributes[0].VendorAttributes[0].Value))
	require.True(t, o.NAS.IPv4[0].IsValid())
	require.True(t, o.NAS.IPv6[0].IsValid())
	require.Equal(t, "nas", string(o.NAS.Identifiers[0]))
	require.Equal(t, "line", string(o.NAS.PortIDs[0]))
	require.Equal(t, "circuit", string(o.NAS.AgentCircuitIDs[0]))
	require.Equal(t, uint64(3), o.Direct[0].TaskGeneration)
	require.Equal(t, "value", string(o.Direct[0].Criteria[0].Value))
	require.Equal(t, "value", string(o.Inherited[0].Criteria[0].Value))
	var absent *Observation
	require.Nil(t, absent.Clone())
}

func TestNASIdentityPreservesRepeatsAndSeparation(t *testing.T) {
	m := &Message{Attributes: []Attribute{
		{Type: 4, Value: []byte{192, 0, 2, 1}},
		{Type: 4, Value: []byte{192, 0, 2}},
		{Type: 95, Value: netip.MustParseAddr("2001:db8::1").AsSlice()},
		{Type: 95, Value: []byte{1}},
		{Type: 32, Value: []byte{0xff, 0x00}},
		{Type: 87, Value: []byte("line-a")},
		{Type: 87, Value: []byte("line-b")},
		{Type: 26, VendorID: 3561, VendorAttributes: []VendorAttribute{{Type: 1, Value: []byte("circuit")}, {Type: 2, Value: []byte("other")}}},
		{Type: 26, VendorID: 999, VendorAttributes: []VendorAttribute{{Type: 1, Value: []byte("wrong")}}},
	}}
	nas := nasIdentity(m)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nas.IPv4)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nas.IPv6)
	require.Equal(t, [][]byte{{0xff, 0x00}}, nas.Identifiers)
	require.Equal(t, [][]byte{[]byte("line-a"), []byte("line-b")}, nas.PortIDs)
	require.Equal(t, [][]byte{[]byte("circuit")}, nas.AgentCircuitIDs)
	m.Attributes[5].Value[0] = '!'
	require.Equal(t, "line-a", string(nas.PortIDs[0]))
}

func TestIngressCounterOwnershipAndEpoch(t *testing.T) {
	scope := CaptureScope{OriginNodeID: "origin", SourceID: "interface", OperatorScope: "operator", ProfileRevision: "v1"}
	ports := []uint16{1912}
	i, err := NewIngress(scope, ports...)
	require.NoError(t, err)
	ports[0] = 0
	require.Equal(t, uint16(1912), i.ports[0])
	require.NotZero(t, i.Scope().Epoch)
	scope.Epoch = i.Scope().Epoch
	require.Equal(t, scope, i.Scope())
	reopened, err := NewIngress(scope)
	require.NoError(t, err)
	require.NotEqual(t, i.Scope().Epoch, reopened.Scope().Epoch)
	_, err = NewIngress(scope, 0)
	require.Error(t, err)
	const attempts = 100
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, outcome, err := i.Observe([]byte{1}, layers.LinkTypeEthernet, gopacket.CaptureInfo{})
			if err == nil || outcome != OutcomeMalformed || o == nil {
				t.Errorf("unexpected validation: %v, %v", outcome, err)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, ValidationStats{Malformed: attempts}, i.Snapshot())
	_, _, _ = DecodePacket(nil, layers.LinkTypeEthernet, gopacket.CaptureInfo{}, i.Scope(), Identity{})
	require.Equal(t, ValidationStats{Malformed: attempts}, i.Snapshot())
	i.ids.sequence = math.MaxUint64
	o, outcome, err := i.Observe([]byte{1}, layers.LinkTypeEthernet, gopacket.CaptureInfo{})
	require.ErrorIs(t, err, ErrIdentityExhausted)
	require.Nil(t, o)
	require.Empty(t, outcome)
	require.Equal(t, ValidationStats{Malformed: attempts}, i.Snapshot())
}

func TestIngressMixedValidationOutcomes(t *testing.T) {
	i, err := NewIngress(CaptureScope{OriginNodeID: "origin", SourceID: "source"})
	require.NoError(t, err)
	fragment := testIPPacket(false, 1812)
	fragment[6] = 0x20
	malformed := testIPPacket(false, 1812)
	malformed[31] = 19 // RADIUS declared length below the fixed header length.
	tests := []struct {
		packet  []byte
		outcome Outcome
	}{
		{testIPPacket(false, 1812), OutcomeValid},
		{testIPPacket(true, 1813), OutcomeValid},
		{testIPPacket(false, 1234), OutcomeUnsupported},
		{fragment, OutcomeFragmented},
		{malformed, OutcomeMalformed},
	}
	for _, test := range tests {
		ci := gopacket.CaptureInfo{CaptureLength: len(test.packet), Length: len(test.packet)}
		o, outcome, err := i.Observe(test.packet, layers.LinkTypeRaw, ci)
		require.Equal(t, test.outcome, outcome)
		require.Equal(t, i.Scope(), o.Scope)
		require.Equal(t, o.Scope.Epoch, o.Capture.ID.Epoch)
		if outcome == OutcomeValid {
			require.NoError(t, err)
			require.NotNil(t, o.Message)
		} else {
			require.Error(t, err)
			require.Nil(t, o.Message)
			require.Zero(t, o.NAS)
			require.Empty(t, o.Direct)
			require.Empty(t, o.Inherited)
		}
		before := i.Snapshot()
		decoded, decodedOutcome, decodedErr := DecodePacket(o.Packet, layers.LinkTypeRaw, ci, o.Scope, o.Capture.ID)
		require.Equal(t, outcome, decodedOutcome)
		require.Equal(t, err != nil, decodedErr != nil)
		require.Equal(t, o, decoded)
		require.Equal(t, before, i.Snapshot())
	}
	require.Equal(t, ValidationStats{Valid: 2, Unsupported: 1, Fragmented: 1, Malformed: 1}, i.Snapshot())
}
