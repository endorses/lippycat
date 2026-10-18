//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestOrdinaryLocalSelectionDoesNotAcquireTaskGrantRequirements(t *testing.T) {
	p := mediaControlFixture(t)
	_, err := p.deleteManagedFilter("local-alice")
	require.NoError(t, err)
	_, err = p.updateManagedFilter(&management.Filter{Id: "li-ordinary-label", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	invite := centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-ordinary", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	centralObserve(p, centralEnvelope(t, "hunter-a", invite, false), true)
	rules := p.mediaControl.store.Snapshot().Rules
	require.NotEmpty(t, rules, "ordinary names are not authority ownership")
	for _, rule := range rules {
		require.Equal(t, []string{"li-ordinary-label"}, rule.Call.FilterIDs)
		require.Empty(t, rule.Call.SelectionGrants)
		require.Empty(t, rule.CaptureSignature)
	}
}
