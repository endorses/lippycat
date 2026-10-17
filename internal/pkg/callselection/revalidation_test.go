package callselection

import (
	"errors"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func TestFilterRevalidationKeepsUnrelatedCallsAndRetiresRevokedSelection(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	process(t, tracker, clock, "hunter-a", invite("alice-tag"))
	other, source := udpEnvelope(t, clock, "hunter-b", 2, invite("other-tag"), false)
	_, err := tracker.Process(other, source)
	require.NoError(t, err)
	before := tracker.Snapshot()
	require.Len(t, before, 2)
	seen := 0
	err = tracker.Reevaluate(func(call Call, proof sip.Event, source Source) (Selection, error) {
		seen++
		require.Equal(t, "INVITE", proof.Method)
		require.Equal(t, "alice", proof.FromUser)
		require.Empty(t, proof.Body)
		require.Empty(t, proof.SDP)
		require.Equal(t, source.Domain, call.Domain)
		if call.Domain == 1 {
			return Selection{}, nil
		}
		return Selection{Selected: true, FilterIDs: []string{"still-current"}, Revision: 5}, nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, seen)
	after := tracker.Snapshot()
	require.Len(t, after, 1)
	require.Equal(t, before[1].Info.Lifetime, after[0].Info.Lifetime)
	require.Equal(t, before[1].Endpoints, after[0].Endpoints)
	require.Equal(t, uint64(5), after[0].SelectionRevision)
	require.Equal(t, []string{"still-current"}, after[0].FilterIDs)
	media, source := udpEnvelope(t, clock, "hunter-b", 1, rtp(), true)
	result, err := tracker.Process(media, source)
	require.NoError(t, err)
	require.Nil(t, result.Call)
}

func TestRevalidationFailureRetiresOnlyAffectedCall(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	process(t, tracker, clock, "hunter-a", invite("alice-tag"))
	err := tracker.Reevaluate(func(Call, sip.Event, Source) (Selection, error) {
		return Selection{}, errors.New("current filter state unavailable")
	})
	require.ErrorContains(t, err, "current filter state unavailable")
	require.Empty(t, tracker.Snapshot())
}
