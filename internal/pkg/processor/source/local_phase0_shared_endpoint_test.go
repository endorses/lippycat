package source

import (
	"hash/fnv"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const (
	phase0LegacyCallA       = "synthetic-leg-a@example.invalid"
	phase0LegacyCallB       = "synthetic-leg-b@example.invalid"
	phase0LegacyFilterA     = "synthetic-identity-filter-a"
	phase0LegacyFilterB     = "synthetic-identity-filter-b"
	phase0LegacySharedMedia = "192.0.2.44:20000"
)

var (
	phase0LegacyXIDA = uuid.MustParse("10000000-0000-4000-8000-00000000000a")
	phase0LegacyXIDB = uuid.MustParse("10000000-0000-4000-8000-00000000000b")
)

type phase0SharedEndpointFixture struct {
	mediaOwner string
	endpoint   string
	callXIDs   map[string]uuid.UUID
	callFilter map[string]string
}

func newPhase0SharedEndpointFixture() phase0SharedEndpointFixture {
	return phase0SharedEndpointFixture{
		mediaOwner: phase0LegacyCallB,
		endpoint:   phase0LegacySharedMedia,
		callXIDs: map[string]uuid.UUID{
			phase0LegacyCallA: phase0LegacyXIDA,
			phase0LegacyCallB: phase0LegacyXIDB,
		},
		callFilter: map[string]string{
			phase0LegacyCallA: phase0LegacyFilterA,
			phase0LegacyCallB: phase0LegacyFilterB,
		},
	}
}

// phase0LegacyAttribution models only the two v0.11.4 behaviors frozen by
// Phase 0: insertion-first endpoint attribution and unioning the identity
// filters of every call associated with the endpoint. It is deliberately
// test-only and must not be used as an ownership implementation.
type phase0LegacyAttribution struct {
	endpointCalls map[string][]string
	callEndpoints map[string][]string
	callFilters   map[string][]string
}

func newPhase0LegacyAttribution() *phase0LegacyAttribution {
	return &phase0LegacyAttribution{
		endpointCalls: make(map[string][]string),
		callEndpoints: make(map[string][]string),
		callFilters:   make(map[string][]string),
	}
}

func (a *phase0LegacyAttribution) associate(callID, endpoint string, filterIDs ...string) {
	a.endpointCalls[endpoint] = append(a.endpointCalls[endpoint], callID)
	a.callEndpoints[callID] = append(a.callEndpoints[callID], endpoint)
	a.callFilters[callID] = append([]string(nil), filterIDs...)
}

func (a *phase0LegacyAttribution) attribute(endpoint string) (string, []string) {
	callIDs := a.endpointCalls[endpoint]
	if len(callIDs) == 0 {
		return "", nil
	}
	var filters []string
	for _, callID := range callIDs {
		filters = append(filters, a.callFilters[callID]...)
	}
	return callIDs[0], filters
}

// evict mirrors callregistry.Core.removeLocked at 92ed306a for the state used
// by RTP attribution: only the removed call leaves each endpoint owner slice.
func (a *phase0LegacyAttribution) evict(callID string) {
	for _, endpoint := range a.callEndpoints[callID] {
		owners := a.endpointCalls[endpoint]
		remaining := owners[:0]
		for _, owner := range owners {
			if owner != callID {
				remaining = append(remaining, owner)
			}
		}
		if len(remaining) == 0 {
			delete(a.endpointCalls, endpoint)
		} else {
			a.endpointCalls[endpoint] = remaining
		}
	}
	delete(a.callEndpoints, callID)
	delete(a.callFilters, callID)
}

func phase0LegacyRTPDisplay(callID string) *types.PacketDisplay {
	return &types.PacketDisplay{
		Timestamp: time.Unix(1_700_000_000, 0),
		SrcIP:     "192.0.2.44",
		DstIP:     "198.51.100.44",
		SrcPort:   "20000",
		DstPort:   "30000",
		Protocol:  "UDP",
		RawData:   phase0RTPPayload(),
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			CallID:      callID,
			SSRC:        0x11223344,
			SequenceNum: 42,
		},
	}
}

func phase0CallIDCorrelation(callID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(callID))
	return h.Sum64()
}

func TestPhase0LegacyCharacterization_SharedEndpointMisattributesIdentityTasks(t *testing.T) {
	fixture := newPhase0SharedEndpointFixture()
	legacy := newPhase0LegacyAttribution()
	legacy.associate(phase0LegacyCallA, fixture.endpoint, fixture.callFilter[phase0LegacyCallA])
	legacy.associate(phase0LegacyCallB, fixture.endpoint, fixture.callFilter[phase0LegacyCallB])

	stampedCallID, inheritedFilters := legacy.attribute(fixture.endpoint)
	require.Equal(t, phase0LegacyCallA, stampedCallID,
		"v0.11.4 stamped the insertion-first call on media attributable to leg B")
	require.NotEqual(t, fixture.mediaOwner, stampedCallID)
	require.Equal(t, []string{phase0LegacyFilterA, phase0LegacyFilterB}, inheritedFilters,
		"v0.11.4 unioned identity filters belonging to distinct calls")

	filterXIDs := map[string]uuid.UUID{
		fixture.callFilter[phase0LegacyCallA]: fixture.callXIDs[phase0LegacyCallA],
		fixture.callFilter[phase0LegacyCallB]: fixture.callXIDs[phase0LegacyCallB],
	}
	encoder := x2x3.NewX3Encoder()
	wantCorrelation := phase0CallIDCorrelation(phase0LegacyCallA)
	for _, filterID := range inheritedFilters {
		pdu, err := encoder.EncodeCC(phase0LegacyRTPDisplay(stampedCallID), filterXIDs[filterID])
		require.NoError(t, err)
		require.Equal(t, filterXIDs[filterID], pdu.Header.XID)
		require.Equal(t, wantCorrelation, pdu.Header.CorrelationID,
			"both identity tasks received content correlated as insertion-first call A")
	}
}

func TestPhase0LegacyCharacterization_EvictionRemovesTaskABeforeLIWhileBsurvives(t *testing.T) {
	fixture := newPhase0SharedEndpointFixture()
	legacy := newPhase0LegacyAttribution()
	legacy.associate(phase0LegacyCallA, fixture.endpoint, fixture.callFilter[phase0LegacyCallA])
	legacy.associate(phase0LegacyCallB, fixture.endpoint, fixture.callFilter[phase0LegacyCallB])

	legacy.evict(phase0LegacyCallA)
	stampedCallID, inheritedFilters := legacy.attribute(fixture.endpoint)
	require.Equal(t, phase0LegacyCallB, stampedCallID,
		"92ed306a winner recomputation retained the packet through call B")
	require.Equal(t, []string{phase0LegacyFilterB}, inheritedFilters,
		"call B retained its identity-selection cache after call A was evicted")

	observedByXID := map[uuid.UUID]int{
		fixture.callXIDs[phase0LegacyCallA]: 0,
		fixture.callXIDs[phase0LegacyCallB]: 0,
	}
	filterXIDs := map[string]uuid.UUID{
		fixture.callFilter[phase0LegacyCallA]: fixture.callXIDs[phase0LegacyCallA],
		fixture.callFilter[phase0LegacyCallB]: fixture.callXIDs[phase0LegacyCallB],
	}
	for _, filterID := range inheritedFilters {
		observedByXID[filterXIDs[filterID]]++
	}
	require.Zero(t, observedByXID[fixture.callXIDs[phase0LegacyCallA]],
		"task A disappeared during source selection, before LI could account for it")
	require.Equal(t, 1, observedByXID[fixture.callXIDs[phase0LegacyCallB]],
		"winner recomputation and call B's cache keep task B observable")
}
