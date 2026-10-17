package callselection

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestTrackedCallBudgetSharedAcrossDomainsWithoutEndpoints(t *testing.T) {
	tracker, clock := trackerFixture(t, func(c *Config) { c.Processor.MaxCalls = 1 })
	payload := message("INVITE sip:bob@example.invalid SIP/2.0", "alice-tag", "", "z9hG4bK-invite", 1, "INVITE", "")
	first, source := udpEnvelope(t, clock, "hunter-a", 1, payload, false)
	result, err := tracker.Process(first, source)
	require.Error(t, err, "delayed offer remains unknown to media admission")
	require.NotNil(t, result.Call)
	require.Empty(t, result.Call.Endpoints)
	second, source := udpEnvelope(t, clock, "hunter-b", 2, payload, false)
	_, err = tracker.Process(second, source)
	require.ErrorIs(t, err, ErrCapacity)
	require.Len(t, tracker.Snapshot(), 1)

	// An existing delayed-offer lifetime remains tracked at full capacity.
	first, source = udpEnvelope(t, clock, "hunter-b", 1, payload, false)
	continued, err := tracker.Process(first, source)
	require.Error(t, err, "unknown media remains fail closed")
	require.NotNil(t, continued.Call)
	require.Equal(t, result.Call.Info.Lifetime, continued.Call.Info.Lifetime)
	clock.Advance(tracker.config.Processor.CallTimeout + time.Second)
	tracker.Sweep()
	second, source = udpEnvelope(t, clock, "hunter-b", 2, payload, false)
	admitted, err := tracker.Process(second, source)
	require.Error(t, err, "new delayed offer remains fail closed")
	require.NotNil(t, admitted.Call)
	require.Equal(t, mediaadmission.DomainID(2), admitted.Call.Domain)
	// Unknown media is intentionally not repaired by inventing endpoint proof.
	// Close reports that diagnostic once; the fixture's repeated close is safe.
	require.Error(t, tracker.Close())
}

func TestEndpointAssociationBudgetPartitionedAcrossDomains(t *testing.T) {
	tracker, _ := trackerFixture(t, func(c *Config) { c.Domains = []mediaadmission.DomainID{2, 1}; c.Processor.MaxEndpointAssociations = 5 })
	for _, domain := range []mediaadmission.DomainID{1, 2} {
		registry := tracker.domains[domain].processor.CallRegistry()
		require.True(t, registry.Upsert(callregistry.Call{CallID: "budget-call"}))
		expected := 2
		if domain == 1 {
			expected = 3
		}
		for endpoint := 0; endpoint < expected; endpoint++ {
			require.True(t, registry.TryAssociateEndpoint("budget-call", fmt.Sprintf("192.0.2.1:%d", 4000+endpoint)))
		}
		require.False(t, registry.TryAssociateEndpoint("budget-call", "192.0.2.1:4999"))
	}
}
