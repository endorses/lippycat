package radius

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func correlationObservation(t *testing.T, code, id, auth byte, sequence uint64) *Observation {
	t.Helper()
	raw := make([]byte, 20)
	raw[0] = code
	raw[1] = id
	binary.BigEndian.PutUint16(raw[2:4], 20)
	raw[4] = auth
	m, err := Decode(raw)
	require.NoError(t, err)
	scope := CaptureScope{OriginNodeID: "node", Epoch: [16]byte{1}, SourceID: "eth0", OperatorScope: "operator", ProfileRevision: "1"}
	return &Observation{Message: m, Scope: scope, Capture: CaptureInfo{ID: Identity{Epoch: scope.Epoch, Sequence: sequence}}, Endpoints: Endpoints{IPFamily: 4, Client: netip.MustParseAddrPort("192.0.2.1:2000"), Server: netip.MustParseAddrPort("192.0.2.2:1812")}, Direct: []AttributionReference{{CriterionGroupID: "group", Scope: scope, Criteria: []CriterionReference{{FilterID: "f", FilterRevision: 1, Value: []byte("alice")}}}}}
}
func testCorrelator(t *testing.T, config CorrelatorConfig) (*Correlator, *time.Time) {
	t.Helper()
	now := time.Unix(1000, 0)
	config.Now = func() time.Time { return now }
	if config.EvidenceCurrent == nil {
		config.EvidenceCurrent = func(r AttributionReference) bool { return r.TaskID == "" }
	}
	c, err := NewCorrelator(config)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c, &now
}
func TestCorrelatorUniqueRetransmissionAndSnapshot(t *testing.T) {
	c, now := testCorrelator(t, CorrelatorConfig{})
	req := correlationObservation(t, 1, 255, 1, 1)
	first := c.Process(req)
	*now = now.Add(time.Second)
	req.Capture.ID.Sequence = 2
	req.Direct[0].Criteria[0].Value[0] = 'b'
	again := c.Process(req)
	require.Equal(t, first.Association, again.Association)
	response := correlationObservation(t, 2, 255, 8, 3)
	for range 2 {
		out := c.Process(response)
		require.Equal(t, AssociationUnique, out.Association.Status)
		require.Equal(t, first.Association.RequestInstanceID, out.Association.RequestInstanceID)
		require.Equal(t, "alice", string(out.Inherited[0].Criteria[0].Value))
		out.Inherited[0].Criteria[0].Value[0] = 'z'
	}
	require.Equal(t, uint64(1), c.Stats().Retransmissions)
	require.Equal(t, uint64(2), c.Stats().Unique)
	*now = now.Add(29 * time.Second)
	require.Equal(t, AssociationExpired, c.Process(response).Association.Status)
}
func TestCorrelatorCompetingUnmatchedAndCodeFamilies(t *testing.T) {
	for _, code := range []byte{1, 4} {
		t.Run(string(rune('0'+code)), func(t *testing.T) {
			c, now := testCorrelator(t, CorrelatorConfig{})
			c.Process(correlationObservation(t, 1, 1, 1, 1))
			*now = now.Add(time.Second)
			competing := correlationObservation(t, code, 1, 2, 2)
			competing.Direct = nil
			c.Process(competing)
			response := correlationObservation(t, 2, 1, 3, 3)
			require.Equal(t, AssociationAmbiguous, c.Process(response).Association.Status)
			*now = now.Add(29 * time.Second)
			out := c.Process(response)
			require.Equal(t, AssociationAmbiguous, out.Association.Status)
			require.Empty(t, out.Inherited)
			require.NotEmpty(t, out.Direct)
			*now = now.Add(29 * time.Second)
			require.Equal(t, AssociationAmbiguous, c.Process(response).Association.Status)
			*now = now.Add(30 * time.Second)
			require.Equal(t, AssociationMissing, c.Process(response).Association.Status)
			require.Equal(t, uint64(1), c.Stats().Collisions)
		})
	}
	c, _ := testCorrelator(t, CorrelatorConfig{})
	c.Process(correlationObservation(t, 4, 1, 1, 1))
	require.Equal(t, AssociationIncompatible, c.Process(correlationObservation(t, 11, 1, 1, 2)).Association.Status)
	require.Equal(t, AssociationUnique, c.Process(correlationObservation(t, 5, 1, 1, 3)).Association.Status)
}
func TestCorrelatorScopeTupleAndMissingRequests(t *testing.T) {
	c, _ := testCorrelator(t, CorrelatorConfig{})
	response := correlationObservation(t, 3, 0, 1, 2)
	require.Equal(t, AssociationMissing, c.Process(response).Association.Status)
	c.Process(correlationObservation(t, 1, 0, 1, 1))
	for _, change := range []func(*Observation){func(o *Observation) { o.Scope.SourceID = "eth1" }, func(o *Observation) { o.Scope.Epoch[0] = 2; o.Capture.ID.Epoch = o.Scope.Epoch }, func(o *Observation) { o.Scope.OperatorScope = "other" }, func(o *Observation) { o.Endpoints.Client = netip.MustParseAddrPort("192.0.2.1:2001") }, func(o *Observation) { o.Endpoints.Server = netip.MustParseAddrPort("192.0.2.2:1813") }, func(o *Observation) { o.Scope.OriginNodeID = "" }} {
		other := response.Clone()
		change(other)
		require.Equal(t, AssociationMissing, c.Process(other).Association.Status)
	}
	require.Equal(t, AssociationUnique, c.Process(response).Association.Status)
}
func TestCorrelatorCapacityGuardsAndGlobalFallback(t *testing.T) {
	c, now := testCorrelator(t, CorrelatorConfig{MaxCandidates: 1, MaxSuppressionKeys: 1})
	c.Process(correlationObservation(t, 1, 1, 1, 1))
	require.Equal(t, AssociationCapacitySuppressed, c.Process(correlationObservation(t, 1, 2, 1, 2)).Association.Status)
	require.Equal(t, AssociationUnique, c.Process(correlationObservation(t, 2, 1, 1, 3)).Association.Status)
	c.Process(correlationObservation(t, 1, 3, 1, 4))
	require.True(t, c.Stats().GlobalSuppressed)
	require.Zero(t, c.Stats().Candidates)
	require.Equal(t, AssociationCapacitySuppressed, c.Process(correlationObservation(t, 2, 1, 1, 5)).Association.Status)
	*now = now.Add(29 * time.Second)
	c.Process(correlationObservation(t, 2, 4, 1, 6))
	*now = now.Add(29 * time.Second)
	require.Equal(t, AssociationCapacitySuppressed, c.Process(correlationObservation(t, 1, 1, 1, 7)).Association.Status)
	*now = now.Add(30 * time.Second)
	require.Equal(t, AssociationRequest, c.Process(correlationObservation(t, 1, 1, 1, 8)).Association.Status)
	require.Equal(t, uint64(2), c.Stats().CapacityLosses)
	c.Close()
	require.Zero(t, c.Stats().RetainedBytes)
	require.Equal(t, AssociationCapacitySuppressed, c.Process(correlationObservation(t, 2, 1, 1, 9)).Association.Status)
}
func TestCorrelatorMemoryAndPerKeyLimits(t *testing.T) {
	c, _ := testCorrelator(t, CorrelatorConfig{MaxPerKey: 1})
	c.Process(correlationObservation(t, 1, 1, 1, 1))
	c.Process(correlationObservation(t, 1, 1, 2, 2))
	require.Equal(t, AssociationCapacitySuppressed, c.Process(correlationObservation(t, 2, 1, 1, 3)).Association.Status)
	c, _ = testCorrelator(t, CorrelatorConfig{CandidateBytes: 1 << 20, TotalBytes: 2 << 20})
	req := correlationObservation(t, 1, 1, 1, 1)
	req.Direct[0].Criteria[0].Value = make([]byte, 1<<20)
	require.Equal(t, AssociationCapacitySuppressed, c.Process(req).Association.Status)
	require.Zero(t, c.Stats().Candidates)
	require.LessOrEqual(t, c.Stats().RetainedBytes, int64(2<<20))
	req = correlationObservation(t, 1, 2, 1, 2)
	req.Scope.SourceID = string(make([]byte, 2<<20))
	c.Process(req)
	require.True(t, c.Stats().GlobalSuppressed)
	require.Zero(t, c.Stats().RetainedBytes)
}
func TestCorrelatorCurrentGenerationsAndConcurrency(t *testing.T) {
	var generation atomic.Uint64
	generation.Store(1)
	c, err := NewCorrelator(CorrelatorConfig{EvidenceCurrent: func(r AttributionReference) bool { return r.TaskGeneration == generation.Load() }})
	require.NoError(t, err)
	defer c.Close()
	req := correlationObservation(t, 1, 1, 1, 1)
	req.Direct[0].TaskID = "task"
	req.Direct[0].TaskGeneration = 1
	second := req.Direct[0]
	second.TaskID = "other"
	req.Direct = append(req.Direct, second)
	c.Process(req)
	require.Len(t, c.Process(correlationObservation(t, 2, 1, 1, 2)).Inherited, 2)
	require.EqualValues(t, 1, c.Stats().MatchedRequests)
	generation.Store(2)
	require.Empty(t, c.Process(correlationObservation(t, 2, 1, 1, 3)).Inherited)
	require.EqualValues(t, 2, c.Stats().StaleReferences)
	req.Direct[0].TaskGeneration = 2
	c.Process(req) // Retransmission cannot refresh the snapshot.
	require.Empty(t, c.Process(correlationObservation(t, 2, 1, 1, 4)).Inherited)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 100 {
				generation.Store(uint64(1 + j%2))
				c.Process(req)
				c.Stats()
				c.Cleanup()
			}
		}(i)
	}
	wg.Wait()
	c2, _ := testCorrelator(t, CorrelatorConfig{})
	c2.Process(req)
	require.Empty(t, c2.Process(correlationObservation(t, 2, 1, 1, 5)).Inherited)
}
func TestCorrelatorConfigurationAndInvalidInput(t *testing.T) {
	for _, cfg := range []CorrelatorConfig{{Lifetime: time.Millisecond}, {Lifetime: 301 * time.Second}, {QuietGuard: time.Second}, {MaxCandidates: -1}, {MaxPerKey: 17}, {MaxSuppressionKeys: -1}, {CandidateBytes: 100}, {TotalBytes: 1 << 20}, {CleanupInterval: -1}} {
		_, err := NewCorrelator(cfg)
		require.Error(t, err)
	}
	c, now := testCorrelator(t, CorrelatorConfig{})
	require.Nil(t, c.Process(nil))
	invalid := correlationObservation(t, 1, 1, 1, 1)
	invalid.Message.Raw[2] = 255
	out := c.Process(invalid)
	require.Empty(t, out.Direct)
	require.Empty(t, out.Inherited)
	require.Equal(t, AssociationUnprocessed, out.Association.Status)
	require.Zero(t, c.Stats().Candidates)
	c.Process(correlationObservation(t, 1, 1, 1, 1))
	*now = now.Add(-time.Hour)
	require.Equal(t, AssociationUnique, c.Process(correlationObservation(t, 2, 1, 1, 2)).Association.Status)
}

func TestCorrelatorIPv6IdentifierWrapAndResponseFamilies(t *testing.T) {
	c, _ := testCorrelator(t, CorrelatorConfig{})
	for _, id := range []byte{255, 0} {
		req := correlationObservation(t, 1, id, id, uint64(id)+1)
		req.Endpoints.IPFamily = 6
		req.Endpoints.Client = netip.MustParseAddrPort("[2001:db8::1]:3000")
		req.Endpoints.Server = netip.MustParseAddrPort("[2001:db8::2]:1812")
		first := c.Process(req)
		for _, code := range []byte{2, 3, 11} {
			response := correlationObservation(t, code, id, 1, 300)
			response.Endpoints = req.Endpoints
			out := c.Process(response)
			require.Equal(t, AssociationUnique, out.Association.Status)
			require.Equal(t, first.Association.RequestInstanceID, out.Association.RequestInstanceID)
			other := response.Clone()
			other.Endpoints.Client = netip.MustParseAddrPort("[2001:db8::3]:3000")
			require.Equal(t, AssociationMissing, c.Process(other).Association.Status)
			other = response.Clone()
			other.Endpoints.Server = netip.MustParseAddrPort("[2001:db8::4]:1812")
			require.Equal(t, AssociationMissing, c.Process(other).Association.Status)
		}
	}
	require.Equal(t, 2, c.Stats().Candidates)
}

func TestCorrelatorEvidenceCheckerCannotMutateRetainedSnapshot(t *testing.T) {
	c, _ := testCorrelator(t, CorrelatorConfig{EvidenceCurrent: func(r AttributionReference) bool { r.Criteria[0].Value[0] = 'z'; return true }})
	c.Process(correlationObservation(t, 1, 1, 1, 1))
	for range 2 {
		require.Equal(t, "alice", string(c.Process(correlationObservation(t, 2, 1, 1, 2)).Inherited[0].Criteria[0].Value))
	}
	unchecked, err := NewCorrelator(CorrelatorConfig{})
	require.NoError(t, err)
	defer unchecked.Close()
	unchecked.Process(correlationObservation(t, 1, 1, 1, 1))
	require.Empty(t, unchecked.Process(correlationObservation(t, 2, 1, 1, 2)).Inherited)
}

func TestCorrelatorCleanupShrinksMapAndExpiryPressureCountsLoss(t *testing.T) {
	c, now := testCorrelator(t, CorrelatorConfig{MaxSuppressionKeys: 1})
	c.Process(correlationObservation(t, 1, 1, 1, 1))
	c.Process(correlationObservation(t, 1, 2, 1, 2))
	*now = now.Add(30 * time.Second)
	c.Cleanup()
	require.True(t, c.Stats().GlobalSuppressed)
	require.Equal(t, uint64(1), c.Stats().CapacityLosses)
	require.Zero(t, c.mapPeak)
	require.Zero(t, c.Stats().RetainedBytes)
	*now = now.Add(30 * time.Second)
	c.Cleanup()
	require.False(t, c.Stats().GlobalSuppressed)
	c.Process(correlationObservation(t, 1, 1, 1, 3))
	*now = now.Add(30 * time.Second)
	c.Cleanup()
	*now = now.Add(30 * time.Second)
	c.Cleanup()
	require.Zero(t, c.mapPeak)
	require.Zero(t, c.Stats().RetainedBytes)
}
